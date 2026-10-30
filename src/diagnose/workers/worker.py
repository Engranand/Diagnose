"""Worker process — loads durable Job state from PostgreSQL, verifies idempotency, executes handler, and manages retries."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from diagnose.domain.jobs import (
    JobStatus,
    PermanentJobError,
    RetryableJobError,
    calculate_backoff_delay,
)
from diagnose.domain.outbox import OutboxEventType
from diagnose.models.job import Job
from diagnose.repositories.job import JobRepository
from diagnose.services.audit import AuditService
from diagnose.services.outbox import OutboxService
from diagnose.workers.handlers import get_handler
from diagnose.workers.queue import RedisQueue, RedisUnavailableError

log = structlog.get_logger()

DEFAULT_QUEUE_NAME = "diagnose:jobs:queue"


class Worker:
    """Worker executor that processes jobs durably backed by PostgreSQL."""

    def __init__(
        self,
        redis_queue: RedisQueue | None = None,
        job_repository: JobRepository | None = None,
        outbox_service: OutboxService | None = None,
        audit_service: AuditService | None = None,
        default_queue_name: str = DEFAULT_QUEUE_NAME,
    ) -> None:
        self.redis_queue = redis_queue
        self.job_repo = job_repository or JobRepository()
        self.outbox_service = outbox_service or OutboxService()
        self.audit_service = audit_service or AuditService()
        self.default_queue_name = default_queue_name

    async def process_job(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        job_data: dict[str, Any],
    ) -> Job | None:
        """Process a single job reference by loading its durable state from PostgreSQL.

        Enforces:
        - FOR UPDATE row locking against race conditions.
        - Idempotency checks (SUCCEEDED or terminal jobs are not re-executed).
        - State transition recording with audit logs.
        - Handler execution with isolated rollback on handler failure.
        - Retry scheduling with exponential backoff and DEAD letter transition on exhaustion.
        """
        raw_job_id = job_data.get("job_id")
        raw_org_id = job_data.get("organization_id")
        if not raw_job_id or not raw_org_id:
            log.error("malformed_job_payload_missing_identifiers", payload=job_data)
            return None

        job_id = uuid.UUID(str(raw_job_id))
        org_id = uuid.UUID(str(raw_org_id))

        # 1. Acquire durable lock on the Job record
        async with session_factory() as session:
            job = await self.job_repo.get_by_id(
                session=session,
                organization_id=org_id,
                job_id=job_id,
                for_update=True,
            )
            if job is None:
                log.warning("job_not_found_in_database", job_id=str(job_id), organization_id=str(org_id))
                return None

            # 2. Idempotency Check: if already terminal or completed, skip execution
            if job.status == JobStatus.SUCCEEDED.value:
                log.info(
                    "job_already_succeeded_skipping_duplicate_delivery",
                    job_id=str(job.id),
                    organization_id=str(job.organization_id),
                )
                return job

            if job.status == JobStatus.DEAD.value:
                log.info(
                    "job_already_dead_skipping_delivery",
                    job_id=str(job.id),
                    organization_id=str(job.organization_id),
                )
                return job

            if job.status == JobStatus.RUNNING.value:
                log.info(
                    "job_already_running_skipping_concurrent_delivery",
                    job_id=str(job.id),
                    organization_id=str(job.organization_id),
                )
                return job

            # Mark RUNNING
            now = datetime.now(timezone.utc)
            job.status = JobStatus.RUNNING.value
            job.started_at = now
            await self.audit_service.record(
                session=session,
                organization_id=org_id,
                actor_user_id=None,
                action="JOB_STARTED",
                entity_type="job",
                entity_id=job.id,
                correlation_id=job.correlation_id,
            )
            await session.commit()

        # 3. Locate registered handler
        handler = get_handler(job.job_type)
        if handler is None:
            err_msg = f"No registered handler found for job_type '{job.job_type}'"
            log.error("unregistered_job_type", job_type=job.job_type, job_id=str(job.id))
            return await self._handle_failure(
                session_factory=session_factory,
                org_id=org_id,
                job_id=job_id,
                exc=PermanentJobError(err_msg),
            )

        # 4. Execute handler in isolated transaction
        try:
            async with session_factory() as exec_session:
                exec_job = await self.job_repo.get_by_id(
                    session=exec_session,
                    organization_id=org_id,
                    job_id=job_id,
                )
                if exec_job is None:
                    return None
                await handler(exec_session, exec_job)
                await exec_session.commit()

            # Mark SUCCEEDED on successful completion
            async with session_factory() as success_session:
                succ_job = await self.job_repo.get_by_id(
                    session=success_session,
                    organization_id=org_id,
                    job_id=job_id,
                    for_update=True,
                )
                if succ_job is None:
                    return None
                now = datetime.now(timezone.utc)
                succ_job.status = JobStatus.SUCCEEDED.value
                succ_job.completed_at = now
                succ_job.last_error = None
                await self.audit_service.record(
                    session=success_session,
                    organization_id=org_id,
                    actor_user_id=None,
                    action="JOB_SUCCEEDED",
                    entity_type="job",
                    entity_id=succ_job.id,
                    correlation_id=succ_job.correlation_id,
                )
                await success_session.commit()
                log.info(
                    "job_succeeded",
                    job_id=str(succ_job.id),
                    organization_id=str(succ_job.organization_id),
                    duration_seconds=(now - succ_job.started_at).total_seconds() if succ_job.started_at else None,
                )
                return succ_job

        except Exception as exc:
            log.warning(
                "job_handler_execution_failed",
                job_id=str(job_id),
                organization_id=str(org_id),
                error=str(exc),
                exc_info=True,
            )
            return await self._handle_failure(
                session_factory=session_factory,
                org_id=org_id,
                job_id=job_id,
                exc=exc,
            )

    async def _handle_failure(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        org_id: uuid.UUID,
        job_id: uuid.UUID,
        exc: Exception,
    ) -> Job | None:
        """Handle execution failure, update attempt count, compute backoff, and transition to RETRYING or DEAD."""
        now = datetime.now(timezone.utc)
        is_permanent = isinstance(exc, PermanentJobError)

        async with session_factory() as session:
            job = await self.job_repo.get_by_id(
                session=session,
                organization_id=org_id,
                job_id=job_id,
                for_update=True,
            )
            if job is None:
                return None

            job.attempt_count += 1
            job.last_error = str(exc)

            is_exhausted = job.attempt_count >= job.max_attempts

            if is_permanent or is_exhausted:
                # Terminal failure -> DEAD
                job.status = JobStatus.DEAD.value
                job.completed_at = now
                await self.audit_service.record(
                    session=session,
                    organization_id=org_id,
                    actor_user_id=None,
                    action="JOB_DEAD",
                    entity_type="job",
                    entity_id=job.id,
                    new_values={
                        "attempt_count": job.attempt_count,
                        "max_attempts": job.max_attempts,
                        "last_error": job.last_error,
                        "is_permanent": is_permanent,
                    },
                    correlation_id=job.correlation_id,
                )
                log.error(
                    "job_moved_to_dead_letter",
                    job_id=str(job.id),
                    attempts=job.attempt_count,
                    max_attempts=job.max_attempts,
                    permanent=is_permanent,
                    error=job.last_error,
                )
            else:
                # Retryable failure -> RETRYING with exponential backoff
                delay = calculate_backoff_delay(job.attempt_count)
                job.status = JobStatus.RETRYING.value
                job.available_at = now + timedelta(seconds=delay)

                # Record outbox event for re-dispatch when available_at arrives
                await self.outbox_service.record_event(
                    session=session,
                    organization_id=org_id,
                    event_type=OutboxEventType.JOB_CREATED,
                    aggregate_type="job",
                    aggregate_id=str(job.id),
                    payload={
                        "job_id": str(job.id),
                        "organization_id": str(org_id),
                        "job_type": job.job_type,
                        "correlation_id": job.correlation_id,
                    },
                    available_at=job.available_at,
                )

                await self.audit_service.record(
                    session=session,
                    organization_id=org_id,
                    actor_user_id=None,
                    action="JOB_RETRYING",
                    entity_type="job",
                    entity_id=job.id,
                    new_values={
                        "attempt_count": job.attempt_count,
                        "retry_delay_seconds": delay,
                        "available_at": job.available_at.isoformat(),
                        "last_error": job.last_error,
                    },
                    correlation_id=job.correlation_id,
                )
                log.info(
                    "job_retry_scheduled",
                    job_id=str(job.id),
                    attempts=job.attempt_count,
                    retry_delay_seconds=delay,
                    available_at=job.available_at.isoformat(),
                )

            await session.commit()
            return job

    async def run_once(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        queue_name: str | None = None,
        timeout: float = 1.0,
    ) -> Job | None:
        """Pop a single job from the Redis queue and process it."""
        if self.redis_queue is None:
            raise RuntimeError("Cannot call run_once() without a configured RedisQueue instance.")

        target_queue = queue_name or self.default_queue_name
        try:
            job_data = await self.redis_queue.dequeue(target_queue, timeout=timeout)
        except RedisUnavailableError as exc:
            log.warning("redis_unavailable_during_worker_dequeue", error=str(exc))
            return None

        if job_data is None:
            return None

        return await self.process_job(session_factory, job_data)

    async def recover_stuck_job(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        organization_id: uuid.UUID,
        job_id: uuid.UUID,
    ) -> Job | None:
        """Recover a job left in RUNNING status after a worker crash or unexpected death.

        Transitions the job back to RETRYING so that it can be safely re-dispatched and executed.
        """
        async with session_factory() as session:
            job = await self.job_repo.get_by_id(
                session=session,
                organization_id=organization_id,
                job_id=job_id,
                for_update=True,
            )
            if job is None:
                return None
            if job.status != JobStatus.RUNNING.value:
                log.info("job_not_in_running_state_skipping_recovery", job_id=str(job_id), status=job.status)
                return job

            now = datetime.now(timezone.utc)
            job.status = JobStatus.RETRYING.value
            job.available_at = now
            await self.audit_service.record(
                session=session,
                organization_id=organization_id,
                actor_user_id=None,
                action="JOB_RECOVERED_AFTER_CRASH",
                entity_type="job",
                entity_id=job.id,
                new_values={"previous_status": "RUNNING", "new_status": "RETRYING"},
                correlation_id=job.correlation_id,
            )
            await session.commit()
            log.info("stuck_job_recovered", job_id=str(job.id), organization_id=str(organization_id))
            return job

    async def recover_stuck_jobs(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        timeout_seconds: int = 300,
    ) -> list[Job]:
        """Find and recover all jobs stuck in RUNNING status older than timeout_seconds."""
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=timeout_seconds)
        recovered: list[Job] = []
        async with session_factory() as session:
            stmt = (
                select(Job)
                .where(
                    Job.status == JobStatus.RUNNING.value,
                    Job.started_at <= cutoff,
                )
                .with_for_update(skip_locked=True)
            )
            result = await session.execute(stmt)
            stuck_jobs = list(result.scalars().all())
            now = datetime.now(timezone.utc)
            for job in stuck_jobs:
                job.status = JobStatus.RETRYING.value
                job.available_at = now
                await self.audit_service.record(
                    session=session,
                    organization_id=job.organization_id,
                    actor_user_id=None,
                    action="JOB_RECOVERED_AFTER_CRASH",
                    entity_type="job",
                    entity_id=job.id,
                    new_values={"previous_status": "RUNNING", "new_status": "RETRYING"},
                    correlation_id=job.correlation_id,
                )
                recovered.append(job)
            await session.commit()
        return recovered
