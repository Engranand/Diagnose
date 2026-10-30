"""Tests for asynchronous Worker execution, idempotency, retries, and dead-letter handling."""

from __future__ import annotations

import asyncio
import uuid
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.jobs import JobStatus
from diagnose.models.audit_log import AuditLog
from diagnose.models.job import Job
from diagnose.models.job_effect import JobEffect
from diagnose.repositories.job import JobRepository
from diagnose.repositories.job_effect import JobEffectRepository
from diagnose.workers.handlers import WorkerCrashSimulation, register_handler
from diagnose.workers.queue import RedisQueue
from diagnose.workers.worker import Worker
from tests.factories import create_test_job, create_test_organization
from tests.fake_redis import FakeAsyncRedis


@pytest.mark.asyncio
async def test_worker_executes_valid_job_successfully(
    app, db_session: AsyncSession
) -> None:
    """Requirement 9, 10: Worker loads durable Job, transitions to RUNNING then SUCCEEDED with completed_at."""
    session_factory = app.state.db_session_factory
    org = await create_test_organization(db_session)
    job = await create_test_job(
        db_session,
        org.id,
        job_type="TEST_JOB",
        payload={"message": "hello"},
    )

    worker = Worker()
    processed_job = await worker.process_job(
        session_factory=session_factory,
        job_data={"job_id": str(job.id), "organization_id": str(org.id)},
    )

    assert processed_job is not None
    assert processed_job.status == JobStatus.SUCCEEDED.value
    assert processed_job.started_at is not None
    assert processed_job.completed_at is not None
    assert processed_job.last_error is None

    # Check audit log records
    async with session_factory() as session:
        q_audit = select(AuditLog.action).where(
            AuditLog.organization_id == org.id,
            AuditLog.entity_id == job.id,
        ).order_by(AuditLog.created_at.asc())
        actions = (await session.execute(q_audit)).scalars().all()
        assert "JOB_STARTED" in actions
        assert "JOB_SUCCEEDED" in actions


@pytest.mark.asyncio
async def test_retryable_failure_increments_attempts_and_schedules_backoff(
    app, db_session: AsyncSession
) -> None:
    """Requirement 11, 12: Retryable failure increments attempt_count and sets RETRYING status with exponential backoff."""
    session_factory = app.state.db_session_factory
    org = await create_test_organization(db_session)
    job = await create_test_job(
        db_session,
        org.id,
        job_type="TEST_JOB",
        payload={"force_retryable_error": True, "error_message": "Transient DB timeout"},
        max_attempts=3,
    )
    initial_available_at = job.available_at

    worker = Worker()
    processed_job = await worker.process_job(
        session_factory=session_factory,
        job_data={"job_id": str(job.id), "organization_id": str(org.id)},
    )

    assert processed_job is not None
    assert processed_job.status == JobStatus.RETRYING.value
    assert processed_job.attempt_count == 1
    assert "Transient DB timeout" in processed_job.last_error
    assert processed_job.available_at > initial_available_at

    # Audit log
    async with session_factory() as session:
        q_audit = select(AuditLog.action).where(
            AuditLog.organization_id == org.id,
            AuditLog.entity_id == job.id,
        )
        actions = (await session.execute(q_audit)).scalars().all()
        assert "JOB_RETRYING" in actions


@pytest.mark.asyncio
async def test_max_attempts_moves_job_to_dead_letter(
    app, db_session: AsyncSession
) -> None:
    """Requirement 13: When attempt_count reaches max_attempts, job transitions to DEAD (not deleted)."""
    session_factory = app.state.db_session_factory
    org = await create_test_organization(db_session)
    # Start at attempt_count = 2 with max_attempts = 3
    job = await create_test_job(
        db_session,
        org.id,
        job_type="TEST_JOB",
        payload={"force_retryable_error": True, "error_message": "Network flap"},
        attempt_count=2,
        max_attempts=3,
    )

    worker = Worker()
    processed_job = await worker.process_job(
        session_factory=session_factory,
        job_data={"job_id": str(job.id), "organization_id": str(org.id)},
    )

    assert processed_job is not None
    assert processed_job.status == JobStatus.DEAD.value
    assert processed_job.attempt_count == 3
    assert processed_job.completed_at is not None
    assert "Network flap" in processed_job.last_error

    # Ensure record is durable and NOT deleted
    async with session_factory() as session:
        db_job = await JobRepository().get_by_id(session, org.id, job.id)
        assert db_job is not None
        assert db_job.status == JobStatus.DEAD.value


@pytest.mark.asyncio
async def test_permanent_failure_moves_immediately_to_dead_letter(
    app, db_session: AsyncSession
) -> None:
    """Requirement 14: Permanent failure transitions job to DEAD on first attempt without burning through retries."""
    session_factory = app.state.db_session_factory
    org = await create_test_organization(db_session)
    job = await create_test_job(
        db_session,
        org.id,
        job_type="TEST_JOB",
        payload={"force_permanent_error": True, "error_message": "Invalid JSON Schema in payload"},
        attempt_count=0,
        max_attempts=5,
    )

    worker = Worker()
    processed_job = await worker.process_job(
        session_factory=session_factory,
        job_data={"job_id": str(job.id), "organization_id": str(org.id)},
    )

    assert processed_job is not None
    assert processed_job.status == JobStatus.DEAD.value
    assert processed_job.attempt_count == 1  # Did NOT loop to 5
    assert "Invalid JSON Schema" in processed_job.last_error


@pytest.mark.asyncio
async def test_duplicate_job_delivery_is_idempotent(
    app, db_session: AsyncSession
) -> None:
    """Requirement 15: Re-delivering a SUCCEEDED job skips execution without duplicating side effects."""
    session_factory = app.state.db_session_factory
    org = await create_test_organization(db_session)

    execution_counter = 0

    # Register custom handler that counts invocations
    @register_handler("IDEMPOTENT_TEST_JOB")
    async def handle_idempotent(session, j):
        nonlocal execution_counter
        execution_counter += 1

    job = await create_test_job(
        db_session,
        org.id,
        job_type="IDEMPOTENT_TEST_JOB",
    )

    worker = Worker()
    job_ref = {"job_id": str(job.id), "organization_id": str(org.id)}

    # 1. First execution
    res1 = await worker.process_job(session_factory, job_ref)
    assert res1.status_code if hasattr(res1, "status_code") else res1.status == JobStatus.SUCCEEDED.value
    assert execution_counter == 1

    # 2. Second execution (duplicate delivery)
    res2 = await worker.process_job(session_factory, job_ref)
    assert res2.status == JobStatus.SUCCEEDED.value
    # Invariant: Side effect was NOT executed a second time!
    assert execution_counter == 1


@pytest.mark.asyncio
async def test_concurrent_worker_execution_row_locking(
    app, db_session: AsyncSession
) -> None:
    """Requirement 16: Two concurrent workers processing the same job payload do not duplicate side effects."""
    session_factory = app.state.db_session_factory
    org = await create_test_organization(db_session)

    execution_count = 0

    @register_handler("CONCURRENT_LOCK_JOB")
    async def handle_concurrent(session, j):
        nonlocal execution_count
        execution_count += 1
        await asyncio.sleep(0.05)  # Simulate non-instant workload

    job = await create_test_job(
        db_session,
        org.id,
        job_type="CONCURRENT_LOCK_JOB",
    )

    worker1 = Worker()
    worker2 = Worker()
    job_ref = {"job_id": str(job.id), "organization_id": str(org.id)}

    # Dispatch concurrently
    r1, r2 = await asyncio.gather(
        worker1.process_job(session_factory, job_ref),
        worker2.process_job(session_factory, job_ref),
    )

    # Handler executed exactly ONCE
    assert execution_count == 1
    statuses = {r1.status, r2.status}
    assert JobStatus.SUCCEEDED.value in statuses

    # In database, final status is SUCCEEDED
    async with session_factory() as session:
        db_job = await JobRepository().get_by_id(session, org.id, job.id)
        assert db_job.status == JobStatus.SUCCEEDED.value


@pytest.mark.asyncio
async def test_crash_recovery_preserves_idempotent_side_effect(
    app, db_session: AsyncSession
) -> None:
    """M6 Correction: Worker crash after committing durable side-effect does not duplicate effect on retry."""
    session_factory = app.state.db_session_factory
    org = await create_test_organization(db_session)
    effect_key = f"durable-effect-{uuid.uuid4().hex[:8]}"

    job = await create_test_job(
        db_session,
        org.id,
        job_type="TEST_JOB",
        payload={
            "effect_key": effect_key,
            "crash_after_effect": True,
        },
    )

    worker = Worker()
    job_ref = {"job_id": str(job.id), "organization_id": str(org.id)}

    # 1. Attempt 1: Worker executes handler, handler commits JobEffect, then worker crashes abruptly
    with pytest.raises(WorkerCrashSimulation):
        await worker.process_job(session_factory, job_ref)

    # In DB: Job is still RUNNING because the worker crashed before marking SUCCEEDED
    async with session_factory() as session:
        db_job = await JobRepository().get_by_id(session, org.id, job.id)
        assert db_job.status == JobStatus.RUNNING.value

        # The side-effect WAS durably committed to PostgreSQL
        effect_repo = JobEffectRepository()
        effect = await effect_repo.get_by_effect_key(session, org.id, effect_key)
        assert effect is not None
        assert effect.status == "COMMITTED"

    # 2. Crash recovery: Supervisor recovers stuck RUNNING job back to RETRYING
    recovered_job = await worker.recover_stuck_job(session_factory, org.id, job.id)
    assert recovered_job is not None
    assert recovered_job.status == JobStatus.RETRYING.value

    # 3. Attempt 2: Worker retries the job
    # The handler checks JobEffect, sees COMMITTED, skips side-effect, and does NOT crash
    retry_result = await worker.process_job(session_factory, job_ref)
    assert retry_result is not None
    assert retry_result.status == JobStatus.SUCCEEDED.value

    # 4. Final verification: exactly ONE durable effect exists in PostgreSQL
    async with session_factory() as session:
        q_effects = select(JobEffect).where(
            JobEffect.organization_id == org.id,
            JobEffect.effect_key == effect_key,
        )
        effects = (await session.execute(q_effects)).scalars().all()
        assert len(effects) == 1
        assert effects[0].status == "COMMITTED"
        assert effects[0].job_id == job.id

        # Verify audit logs record recovery and success
        q_audit = select(AuditLog.action).where(
            AuditLog.organization_id == org.id,
            AuditLog.entity_id == job.id,
        )
        actions = (await session.execute(q_audit)).scalars().all()
        assert "JOB_STARTED" in actions
        assert "JOB_RECOVERED_AFTER_CRASH" in actions
        assert "JOB_SUCCEEDED" in actions


@pytest.mark.asyncio
async def test_stuck_jobs_batch_sweep_recovery(
    app, db_session: AsyncSession
) -> None:
    """Worker.recover_stuck_jobs sweeps timed-out RUNNING jobs."""
    from datetime import datetime, timedelta, timezone

    session_factory = app.state.db_session_factory
    org = await create_test_organization(db_session)

    job = await create_test_job(
        db_session,
        org.id,
        job_type="TEST_JOB",
    )
    job.status = JobStatus.RUNNING.value
    job.started_at = datetime.now(timezone.utc) - timedelta(seconds=400)
    await db_session.commit()

    worker = Worker()
    recovered = await worker.recover_stuck_jobs(session_factory, timeout_seconds=300)
    recovered_ids = [j.id for j in recovered]
    assert job.id in recovered_ids

    async with session_factory() as session:
        refreshed = await JobRepository().get_by_id(session, org.id, job.id)
        assert refreshed.status == JobStatus.RETRYING.value
