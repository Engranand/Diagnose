"""Job domain models, enums, exceptions, and backoff policy."""

from __future__ import annotations

from enum import StrEnum


class JobStatus(StrEnum):
    """Operational lifecycle status of an asynchronous job."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    RETRYING = "RETRYING"
    FAILED = "FAILED"
    DEAD = "DEAD"


class JobType(StrEnum):
    """Registered job types recognized by worker executors."""

    TEST_JOB = "TEST_JOB"


class JobExecutionError(Exception):
    """Base error for job execution failures."""


class RetryableJobError(JobExecutionError):
    """Transient failure that should be retried with backoff."""


class PermanentJobError(JobExecutionError):
    """Non-retryable failure that immediately transitions job to DEAD."""


def calculate_backoff_delay(
    attempt: int,
    base_seconds: float = 1.0,
    max_seconds: float = 300.0,
) -> float:
    """Calculate deterministic exponential backoff delay for retrying failed jobs.

    Formula: min(base_seconds * (2 ** (attempt - 1)), max_seconds)
    - Attempt 1: 1s
    - Attempt 2: 2s
    - Attempt 3: 4s
    - Attempt 4: 8s
    """
    if attempt <= 0:
        return 0.0
    delay = base_seconds * (2 ** (attempt - 1))
    return min(delay, max_seconds)
