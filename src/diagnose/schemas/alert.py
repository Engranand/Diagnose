"""Pydantic schemas for Alert entity and associations."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from diagnose.domain.alerts import AlertSeverity, AlertStatus


class AlertCreate(BaseModel):
    """Request payload to ingest an alert signal."""

    service_id: uuid.UUID
    incident_id: uuid.UUID | None = None
    fingerprint: str = Field(..., min_length=1, max_length=255)
    source: str = Field(..., min_length=1, max_length=100)
    alert_type: str = Field(..., min_length=1, max_length=100)
    title: str = Field(..., min_length=1, max_length=255)
    message: str | None = None
    severity: AlertSeverity = Field(default=AlertSeverity.MEDIUM)
    status: AlertStatus = Field(default=AlertStatus.FIRING)
    payload: dict[str, Any] | None = None

    model_config = ConfigDict(extra="ignore")

    @field_validator("fingerprint", "source", "alert_type", "title")
    @classmethod
    def validate_non_empty(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Field cannot be empty or whitespace.")
        return trimmed


class AlertUpdate(BaseModel):
    """Request payload to update operational alert metadata."""

    status: AlertStatus | None = None
    severity: AlertSeverity | None = None
    title: str | None = Field(default=None, min_length=1, max_length=255)
    message: str | None = None
    payload: dict[str, Any] | None = None

    model_config = ConfigDict(extra="ignore")

    @field_validator("title")
    @classmethod
    def validate_title(cls, v: str | None) -> str | None:
        if v is None:
            return None
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Title cannot be empty or whitespace.")
        return trimmed


class AlertIncidentAssociation(BaseModel):
    """Request payload to associate an alert with an incident."""

    incident_id: uuid.UUID

    model_config = ConfigDict(extra="ignore")


class AlertRead(BaseModel):
    """Response payload for an Alert."""

    id: uuid.UUID
    organization_id: uuid.UUID
    service_id: uuid.UUID
    incident_id: uuid.UUID | None
    fingerprint: str
    source: str
    alert_type: str
    title: str
    message: str | None
    severity: AlertSeverity
    status: AlertStatus
    payload: dict[str, Any] | None
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertListResponse(BaseModel):
    """Paginated list of alerts."""

    items: list[AlertRead]
    total: int
    page: int
    page_size: int
    pages: int
