"""Pydantic schemas for Evidence entity."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from diagnose.domain.evidence import EvidenceReliability, EvidenceType


class EvidenceCreate(BaseModel):
    """Request payload to ingest an immutable evidence artifact."""

    evidence_type: EvidenceType
    source: str = Field(..., min_length=1, max_length=100)
    title: str = Field(..., min_length=1, max_length=255)
    content: str | None = None
    structured_data: dict[str, Any] | None = None
    observed_at: datetime | None = None
    reliability: EvidenceReliability = Field(default=EvidenceReliability.HIGH)
    metadata: dict[str, Any] | None = None

    model_config = ConfigDict(extra="ignore")

    @field_validator("source", "title")
    @classmethod
    def validate_non_empty(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Field cannot be empty or whitespace.")
        return trimmed


class EvidenceRead(BaseModel):
    """Response payload representing an Evidence artifact."""

    id: uuid.UUID
    organization_id: uuid.UUID
    incident_id: uuid.UUID
    evidence_type: EvidenceType
    source: str
    title: str
    content: str | None
    structured_data: dict[str, Any] | None
    observed_at: datetime | None
    collected_at: datetime
    collected_by_user_id: uuid.UUID | None
    reliability: EvidenceReliability
    evidence_metadata: dict[str, Any] | None = None
    evidence_hash: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class EvidenceListResponse(BaseModel):
    """Paginated list of evidence artifacts."""

    items: list[EvidenceRead]
    total: int
    page: int
    page_size: int
    pages: int
