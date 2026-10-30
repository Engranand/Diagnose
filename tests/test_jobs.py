"""Tests for Job entity, transactional outbox creation, atomicity, and tenant scoping."""

from __future__ import annotations

import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.jobs import JobStatus
from diagnose.domain.outbox import OutboxStatus
from diagnose.domain.roles import Role
from diagnose.models.audit_log import AuditLog
from diagnose.models.job import Job
from diagnose.models.outbox import OutboxEvent
from diagnose.schemas.job import JobCreate
from diagnose.services.job import JobService
from tests.factories import (
    auth_headers_for,
    create_test_job,
    create_test_organization,
    create_test_user,
)


@pytest.mark.asyncio
async def test_job_and_outbox_creation_atomic(
    db_session: AsyncSession,
) -> None:
    """Requirement 1, 2, 3: Business job creation and outbox event are committed in the SAME transaction."""
    org = await create_test_organization(db_session)
    service = JobService()

    job_data = JobCreate(
        job_type="TEST_JOB",
        payload={"param": "value123"},
        idempotency_key=f"idemp-{uuid.uuid4().hex[:6]}",
        max_attempts=3,
    )
    correlation_id = f"corr-{uuid.uuid4().hex[:6]}"

    job, is_created = await service.create_job(
        session=db_session,
        organization_id=org.id,
        data=job_data,
        correlation_id=correlation_id,
    )

    assert is_created is True
    assert job.id is not None
    assert job.status == JobStatus.PENDING.value
    assert job.attempt_count == 0
    assert job.max_attempts == 3
    assert job.correlation_id == correlation_id

    # Verify matching outbox event was created in the SAME transaction
    q_outbox = select(OutboxEvent).where(
        OutboxEvent.organization_id == org.id,
        OutboxEvent.aggregate_id == str(job.id),
    )
    outbox_event = (await db_session.execute(q_outbox)).scalar_one_or_none()
    assert outbox_event is not None
    assert outbox_event.status == OutboxStatus.PENDING.value
    assert outbox_event.event_type == "job.created"
    assert outbox_event.payload["job_id"] == str(job.id)
    assert outbox_event.payload["job_type"] == "TEST_JOB"
    assert outbox_event.payload["correlation_id"] == correlation_id


@pytest.mark.asyncio
async def test_transaction_rollback_leaves_no_orphan_outbox(
    db_session: AsyncSession,
) -> None:
    """Requirement 4: When a transaction rolls back, neither the Job nor an orphan OutboxEvent persists."""
    org = await create_test_organization(db_session)
    service = JobService()

    fake_idempotency = f"rollback-{uuid.uuid4().hex[:6]}"
    job_data = JobCreate(
        job_type="TEST_JOB",
        payload={"param": "never_committed"},
        idempotency_key=fake_idempotency,
    )

    # Begin transaction, stage job and outbox, then explicitly rollback
    try:
        async with db_session.begin_nested():
            job = Job(
                organization_id=org.id,
                job_type=job_data.job_type,
                status=JobStatus.PENDING.value,
                idempotency_key=fake_idempotency,
            )
            db_session.add(job)
            await db_session.flush()

            outbox = OutboxEvent(
                organization_id=org.id,
                event_type="job.created",
                aggregate_type="job",
                aggregate_id=str(job.id),
                payload={"job_id": str(job.id)},
                status=OutboxStatus.PENDING.value,
            )
            db_session.add(outbox)
            await db_session.flush()
            # Force failure
            raise RuntimeError("Intentional failure triggering rollback")
    except RuntimeError:
        pass

    # Verify neither Job nor OutboxEvent exists in the database
    q_job = select(Job).where(Job.organization_id == org.id, Job.idempotency_key == fake_idempotency)
    assert (await db_session.execute(q_job)).scalar_one_or_none() is None

    q_out = select(OutboxEvent).where(OutboxEvent.organization_id == org.id)
    assert (await db_session.execute(q_out)).scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_job_idempotency_key_deduplication(
    db_session: AsyncSession,
) -> None:
    """Submitting the same idempotency key within a tenant returns existing job without duplicate work."""
    org = await create_test_organization(db_session)
    service = JobService()

    idemp_key = f"idemp-shared-{uuid.uuid4().hex[:6]}"
    job_data = JobCreate(
        job_type="TEST_JOB",
        payload={"run": 1},
        idempotency_key=idemp_key,
    )

    job1, created1 = await service.create_job(db_session, org.id, job_data)
    assert created1 is True

    # Re-submit with same idempotency key
    job2, created2 = await service.create_job(db_session, org.id, job_data)
    assert created2 is False
    assert job1.id == job2.id

    # Verify only 1 Job row and 1 OutboxEvent row exists
    q_jobs = select(Job).where(Job.organization_id == org.id, Job.idempotency_key == idemp_key)
    jobs = (await db_session.execute(q_jobs)).scalars().all()
    assert len(jobs) == 1

    q_outbox = select(OutboxEvent).where(OutboxEvent.organization_id == org.id)
    events = (await db_session.execute(q_outbox)).scalars().all()
    assert len(events) == 1


@pytest.mark.asyncio
async def test_api_job_lifecycle_and_rbac(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requirement 18: Admin can trigger job, viewer can view, and correlation ID propagates."""
    org = await create_test_organization(db_session)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)
    viewer = await create_test_user(db_session, org.id, role=Role.VIEWER)

    # 1. Admin triggers job via API
    corr_id = f"test-corr-{uuid.uuid4().hex[:6]}"
    res_create = await client.post(
        "/api/v1/jobs",
        json={"job_type": "TEST_JOB", "payload": {"foo": "bar"}, "max_attempts": 3},
        headers={**auth_headers_for(admin), "X-Request-ID": corr_id},
    )
    assert res_create.status_code == 201
    job_data = res_create.json()
    job_id = job_data["id"]
    assert job_data["correlation_id"] == corr_id
    assert job_data["status"] == "PENDING"
    assert job_data["job_type"] == "TEST_JOB"

    # 2. Viewer can view job
    res_get = await client.get(
        f"/api/v1/jobs/{job_id}",
        headers=auth_headers_for(viewer),
    )
    assert res_get.status_code == 200
    assert res_get.json()["id"] == job_id

    # 3. Viewer cannot trigger job (403 Forbidden)
    res_viewer_post = await client.post(
        "/api/v1/jobs",
        json={"job_type": "TEST_JOB"},
        headers=auth_headers_for(viewer),
    )
    assert res_viewer_post.status_code == 403


@pytest.mark.asyncio
async def test_cross_tenant_job_isolation_404(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requirement 17: Tenant A cannot access Tenant B's jobs."""
    org_a = await create_test_organization(db_session, name="Org A")
    org_b = await create_test_organization(db_session, name="Org B")

    admin_a = await create_test_user(db_session, org_a.id, role=Role.ADMIN)
    admin_b = await create_test_user(db_session, org_b.id, role=Role.ADMIN)

    job_b = await create_test_job(db_session, org_b.id)

    # Tenant A attempts to read Tenant B's job
    res = await client.get(f"/api/v1/jobs/{job_b.id}", headers=auth_headers_for(admin_a))
    assert res.status_code == 404

    # Tenant A lists jobs -> Tenant B's job is not present
    res_list = await client.get("/api/v1/jobs", headers=auth_headers_for(admin_a))
    assert res_list.status_code == 200
    ids = [j["id"] for j in res_list.json()["items"]]
    assert str(job_b.id) not in ids
