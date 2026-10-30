"""Pydantic schemas for Job entity and operational inspection."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from diagnose.domain.jobs import JobStatus


class JobCreate(BaseModel):
    """Payload to trigger an asynchronous background job."""

    job_type: str = Field(..., min_length=1, max_length=100)
    payload: dict[str, Any] | None = None
    idempotency_key: str | None = Field(default=None, max_length=255)
    max_attempts: int = Field(default=3, ge=1, le=10)

    model_config = ConfigDict(extra="ignore")


class JobRead(BaseModel):
    """Serialized Job representation."""

    id: uuid.UUID
    organization_id: uuid.UUID
    job_type: str
    status: JobStatus
    payload: dict[str, Any] | None = None
    correlation_id: str | None = None
    idempotency_key: str | None = None
    attempt_count: int
    max_attempts: int
    available_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    last_error: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class JobListResponse(BaseModel):
    """Paginated list of Jobs."""

    items: list[JobRead]
    total: int
    page: int
    page_size: int
