"""Job handlers registry and default deterministic implementations."""

from __future__ import annotations

import uuid
from typing import Any, Awaitable, Callable

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.jobs import PermanentJobError, RetryableJobError
from diagnose.models.job import Job
from diagnose.models.job_effect import JobEffect
from diagnose.repositories.job_effect import JobEffectRepository

log = structlog.get_logger()


class WorkerCrashSimulation(BaseException):
    """Simulates an abrupt process crash/failure after committing a durable side-effect."""


async def record_job_effect(
    session: AsyncSession,
    job: Job,
    effect_key: str,
    payload: dict[str, Any] | None = None,
    status: str = "COMMITTED",
) -> tuple[JobEffect, bool]:
    """Atomically record or check a durable side-effect for a job handler.

    Guarantees at-most-once durable effect execution:
    - If the effect key has already been committed for this tenant, returns (effect, False).
    - If not yet recorded, inserts a JobEffect with status and flushes, returning (effect, True).
    """
    repo = JobEffectRepository()
    return await repo.record_effect(
        session=session,
        organization_id=job.organization_id,
        job_id=job.id,
        effect_key=effect_key,
        payload=payload,
        status=status,
    )


JobHandler = Callable[[AsyncSession, Job], Awaitable[None]]

_HANDLER_REGISTRY: dict[str, JobHandler] = {}


def register_handler(job_type: str) -> Callable[[JobHandler], JobHandler]:
    """Decorator to register an async function as the handler for a job_type."""

    def decorator(fn: JobHandler) -> JobHandler:
        _HANDLER_REGISTRY[job_type] = fn
        return fn

    return decorator


def get_handler(job_type: str) -> JobHandler | None:
    """Retrieve the registered handler for a job_type."""
    return _HANDLER_REGISTRY.get(job_type)


@register_handler("TEST_JOB")
async def handle_test_job(session: AsyncSession, job: Job) -> None:
    """Deterministic test job handler for testing, verification, and benchmark execution.

    Supports test instructions in payload:
    - force_retryable_error: raises RetryableJobError
    - force_permanent_error: raises PermanentJobError
    """
    payload = job.payload or {}
    correlation_id = job.correlation_id

    log.info(
        "executing_test_job",
        job_id=str(job.id),
        organization_id=str(job.organization_id),
        correlation_id=correlation_id,
        attempt=job.attempt_count + 1,
    )

    if payload.get("force_permanent_error"):
        raise PermanentJobError(payload.get("error_message", "Deterministic permanent failure triggered."))

    if payload.get("force_retryable_error"):
        # If payload specifies succeed_on_attempt and we reached it, succeed instead!
        succeed_on_attempt = payload.get("succeed_on_attempt")
        current_attempt = job.attempt_count + 1
        if succeed_on_attempt is not None and current_attempt >= succeed_on_attempt:
            log.info("test_job_succeeding_after_retries", job_id=str(job.id), attempt=current_attempt)
            return

        raise RetryableJobError(payload.get("error_message", "Deterministic retryable failure triggered."))

    # Durable side-effect handling with crash idempotency support
    effect_key = payload.get("effect_key")
    if effect_key:
        effect, was_applied = await record_job_effect(
            session=session,
            job=job,
            effect_key=effect_key,
            payload={"action": "test_side_effect", "attempt": job.attempt_count + 1},
        )
        if not was_applied:
            log.info(
                "test_job_effect_already_applied_skipping",
                job_id=str(job.id),
                organization_id=str(job.organization_id),
                effect_key=effect_key,
            )
            return

        # If test requests a simulated crash after committing the durable side-effect:
        if payload.get("crash_after_effect"):
            # Commit the session so the effect is durably written to PostgreSQL
            await session.commit()
            log.warning(
                "simulating_worker_crash_after_side_effect_commit",
                job_id=str(job.id),
                effect_key=effect_key,
            )
            raise WorkerCrashSimulation("Simulated abrupt worker crash after committing durable side-effect.")
