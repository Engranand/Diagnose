"""Live verification script: Crash-Safe Worker Idempotency with durable JobEffect."""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

# Ensure src in sys.path
sys.path.insert(0, os.path.abspath("src"))

from diagnose.domain.jobs import JobStatus
from diagnose.models.audit_log import AuditLog
from diagnose.models.job import Job
from diagnose.models.job_effect import JobEffect
from diagnose.models.organization import Organization
from diagnose.repositories.job import JobRepository
from diagnose.repositories.job_effect import JobEffectRepository
from diagnose.workers.handlers import WorkerCrashSimulation
from diagnose.workers.worker import Worker


async def main() -> None:
    db_url = os.environ.get(
        "DIAGNOSE_DATABASE_URL",
        "postgresql+asyncpg://diagnose:diagnose_dev@localhost:5432/diagnose",
    )
    print(f"[*] Connecting to database: {db_url}")
    engine = create_async_engine(db_url, echo=False)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with session_factory() as session:
        # 1. Setup Organization
        org = Organization(
            id=uuid.uuid4(),
            name=f"Idempotency Test Org {uuid.uuid4().hex[:6]}",
            slug=f"idemp-org-{uuid.uuid4().hex[:6]}",
            is_active=True,
        )
        session.add(org)
        await session.commit()
        print(f"[+] Created organization: {org.id} ({org.name})")

        effect_key = f"payment-refund:{uuid.uuid4().hex[:8]}"
        job = Job(
            id=uuid.uuid4(),
            organization_id=org.id,
            job_type="TEST_JOB",
            status=JobStatus.PENDING.value,
            payload={
                "effect_key": effect_key,
                "crash_after_effect": True,
            },
            max_attempts=3,
            available_at=datetime.now(timezone.utc),
        )
        session.add(job)
        await session.commit()
        print(f"[+] Enqueued job: {job.id} with effect_key='{effect_key}' and crash_after_effect=True")

    worker = Worker()
    job_ref = {"job_id": str(job.id), "organization_id": str(org.id)}

    # 2. Simulate Worker Attempt 1: Handler commits JobEffect, then worker crashes abruptly
    print("\n--- ATTEMPT 1: Worker processes job and crashes after committing durable effect ---")
    crashed = False
    try:
        await worker.process_job(session_factory, job_ref)
    except WorkerCrashSimulation as exc:
        crashed = True
        print(f"[!] Intercepted expected crash: {exc}")

    assert crashed, "Expected worker to simulate abrupt crash!"

    # 3. Verify state after crash
    async with session_factory() as session:
        j = await JobRepository().get_by_id(session, org.id, job.id)
        assert j.status == JobStatus.RUNNING.value, f"Expected RUNNING, got {j.status}"
        print(f"[OK] Verified: Job {job.id} remains in RUNNING state (worker crashed before SUCCEEDED)")

        effect = await JobEffectRepository().get_by_effect_key(session, org.id, effect_key)
        assert effect is not None, "JobEffect should have been durably committed before crash!"
        assert effect.status == "COMMITTED"
        print(f"[OK] Verified: JobEffect was durably committed to PostgreSQL: status={effect.status}")

    # 4. Supervisor recovers stuck job
    print("\n--- SUPERVISOR: Recovering stuck RUNNING job ---")
    recovered = await worker.recover_stuck_job(session_factory, org.id, job.id)
    assert recovered.status == JobStatus.RETRYING.value
    print(f"[OK] Verified: Stuck job recovered back to {recovered.status}")

    # 5. Worker Attempt 2 (Retry)
    print("\n--- ATTEMPT 2: Worker retries the recovered job ---")
    retried_job = await worker.process_job(session_factory, job_ref)
    assert retried_job is not None
    assert retried_job.status == JobStatus.SUCCEEDED.value, f"Expected SUCCEEDED, got {retried_job.status}"
    print(f"[OK] Verified: Job completed successfully: status={retried_job.status}")

    # 6. Database Verification: At-most-once durable effect guarantee
    print("\n--- DATABASE VERIFICATION: At-most-once durable effect check ---")
    async with session_factory() as session:
        q_effects = select(JobEffect).where(
            JobEffect.organization_id == org.id,
            JobEffect.effect_key == effect_key,
        )
        effects = (await session.execute(q_effects)).scalars().all()
        assert len(effects) == 1, f"Expected exactly 1 effect, found {len(effects)}"
        print(f"[OK] Verified: Exactly ONE JobEffect exists in DB for key '{effect_key}'")

        # 7. Duplicate delivery test (At-most-once delivery guarantee)
        print("\n--- REDELIVERY: Testing duplicate delivery on already-succeeded job ---")
        redelivery_result = await worker.process_job(session_factory, job_ref)
        assert redelivery_result.status == JobStatus.SUCCEEDED.value
        effects_after = (await session.execute(q_effects)).scalars().all()
        assert len(effects_after) == 1
        print(f"[OK] Verified: Redelivery on SUCCEEDED job was a clean no-op, effect count remains 1")

        # Audit logs check
        q_audit = select(AuditLog.action).where(
            AuditLog.organization_id == org.id,
            AuditLog.entity_id == job.id,
        ).order_by(AuditLog.created_at.asc())
        actions = (await session.execute(q_audit)).scalars().all()
        print(f"[OK] Audit log trail: {' -> '.join(actions)}")
        assert "JOB_STARTED" in actions
        assert "JOB_RECOVERED_AFTER_CRASH" in actions
        assert "JOB_SUCCEEDED" in actions

    await engine.dispose()
    print("\n=======================================================")
    print("ALL CRASH-SAFE WORKER IDEMPOTENCY CHECKS PASSED!")
    print("=======================================================")


if __name__ == "__main__":
    asyncio.run(main())
