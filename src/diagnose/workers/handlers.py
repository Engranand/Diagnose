"""Job handlers registry and default deterministic implementations."""

from __future__ import annotations

import uuid
from typing import Awaitable, Callable

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.jobs import PermanentJobError, RetryableJobError
from diagnose.models.job import Job

log = structlog.get_logger()

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
