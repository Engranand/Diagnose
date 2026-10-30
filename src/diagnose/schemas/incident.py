"""Pydantic schemas for Incident entity, lifecycle transitions, and events."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from diagnose.domain.incidents import IncidentSeverity, IncidentStatus


class IncidentCreate(BaseModel):
    """Request payload to create a new Incident."""

    title: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=5000)
    service_id: uuid.UUID
    severity: IncidentSeverity = Field(default=IncidentSeverity.MEDIUM)
    assigned_user_id: uuid.UUID | None = None

    model_config = ConfigDict(extra="ignore")

    @field_validator("title")
    @classmethod
    def validate_title(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Incident title cannot be empty or whitespace.")
        return trimmed


class IncidentUpdate(BaseModel):
    """Request payload to update incident metadata (status cannot be updated here)."""

    title: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=5000)
    severity: IncidentSeverity | None = None
    service_id: uuid.UUID | None = None

    model_config = ConfigDict(extra="ignore")

    @field_validator("title")
    @classmethod
    def validate_title(cls, v: str | None) -> str | None:
        if v is None:
            return None
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Incident title cannot be empty or whitespace.")
        return trimmed


class IncidentTransition(BaseModel):
    """Request payload for an explicit lifecycle state transition."""

    target_status: IncidentStatus
    message: str | None = Field(default=None, max_length=1000)

    model_config = ConfigDict(extra="ignore")


class IncidentAssign(BaseModel):
    """Request payload to assign or unassign an incident."""

    assigned_user_id: uuid.UUID | None = None

    model_config = ConfigDict(extra="ignore")


class IncidentRead(BaseModel):
    """Response payload representing an Incident."""

    id: uuid.UUID
    organization_id: uuid.UUID
    service_id: uuid.UUID
    incident_number: int
    title: str
    description: str | None
    severity: IncidentSeverity
    status: IncidentStatus
    assigned_user_id: uuid.UUID | None
    detected_at: datetime
    acknowledged_at: datetime | None
    resolved_at: datetime | None
    closed_at: datetime | None
    version: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IncidentEventRead(BaseModel):
    """Response payload for an IncidentEvent in the timeline."""

    id: uuid.UUID
    organization_id: uuid.UUID
    incident_id: uuid.UUID
    event_type: str
    actor_user_id: uuid.UUID | None
    from_status: str | None
    to_status: str | None
    message: str | None
    event_metadata: dict[str, Any] | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IncidentListResponse(BaseModel):
    """Paginated list of incidents."""

    items: list[IncidentRead]
    total: int
    page: int
    page_size: int
    pages: int
