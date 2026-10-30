"""Job Service — atomic creation with transactional outbox, querying, and audit logging."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.exceptions import EntityNotFound
from diagnose.domain.jobs import JobStatus, JobType
from diagnose.domain.outbox import OutboxEventType
from diagnose.models.job import Job
from diagnose.repositories.job import JobRepository
from diagnose.schemas.job import JobCreate
from diagnose.services.audit import AuditService
from diagnose.services.outbox import OutboxService


class JobService:
    """Operations for durable background job lifecycle."""

    def __init__(
        self,
        job_repository: JobRepository | None = None,
        outbox_service: OutboxService | None = None,
        audit_service: AuditService | None = None,
    ) -> None:
        self.job_repo = job_repository or JobRepository()
        self.outbox_service = outbox_service or OutboxService()
        self.audit_service = audit_service or AuditService()

    async def create_job(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        data: JobCreate,
        actor_user_id: uuid.UUID | None = None,
        correlation_id: str | None = None,
        ip_address: str | None = None,
    ) -> tuple[Job, bool]:
        """Atomically create a Job and its corresponding OutboxEvent in a single transaction.

        If idempotency_key is provided and an existing job is found for this tenant,
        returns the existing job without creating duplicate work.
        """
        # Idempotency check
        if data.idempotency_key:
            existing = await self.job_repo.get_by_idempotency_key(
                session,
                organization_id=organization_id,
                idempotency_key=data.idempotency_key,
            )
            if existing is not None:
                return existing, False

        now = datetime.now(timezone.utc)
        job = Job(
            organization_id=organization_id,
            job_type=data.job_type,
            status=JobStatus.PENDING.value,
            payload=data.payload,
            correlation_id=correlation_id,
            idempotency_key=data.idempotency_key,
            attempt_count=0,
            max_attempts=data.max_attempts,
            available_at=now,
            created_at=now,
        )
        await self.job_repo.create_job(session, job)

        # Invariant: Job and OutboxEvent are staged in the same transaction
        outbox_payload = {
            "job_id": str(job.id),
            "organization_id": str(organization_id),
            "job_type": job.job_type,
            "correlation_id": correlation_id,
        }
        await self.outbox_service.record_event(
            session=session,
            organization_id=organization_id,
            event_type=OutboxEventType.JOB_CREATED,
            aggregate_type="job",
            aggregate_id=str(job.id),
            payload=outbox_payload,
        )

        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="JOB_CREATED",
            entity_type="job",
            entity_id=job.id,
            old_values=None,
            new_values={
                "job_type": job.job_type,
                "status": job.status,
                "max_attempts": job.max_attempts,
                "idempotency_key": job.idempotency_key,
            },
            correlation_id=correlation_id,
            ip_address=ip_address,
        )

        # Single atomic commit for business entity + outbox event + audit log
        await session.commit()
        await session.refresh(job)
        return job, True

    async def get_job(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        job_id: uuid.UUID,
    ) -> Job:
        """Fetch job scoped strictly to organization."""
        job = await self.job_repo.get_by_id(
            session,
            organization_id=organization_id,
            job_id=job_id,
        )
        if job is None:
            raise EntityNotFound("Job", str(job_id))
        return job

    async def list_jobs(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        status: JobStatus | None = None,
        job_type: str | None = None,
        created_from: datetime | None = None,
        created_to: datetime | None = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[Job], int]:
        """List jobs with tenant scoping, filtering, sorting, and pagination."""
        return await self.job_repo.list_jobs(
            session=session,
            organization_id=organization_id,
            status=status.value if status else None,
            job_type=job_type,
            created_from=created_from,
            created_to=created_to,
            sort_by=sort_by,
            sort_order=sort_order,
            offset=offset,
            limit=limit,
        )
