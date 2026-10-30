"""Pydantic schemas for Service entity."""

from __future__ import annotations

import re
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from diagnose.domain.services import ServiceTier

SLUG_REGEX = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class ServiceCreate(BaseModel):
    """Request payload to create a new Service in the organization catalog."""

    name: str = Field(..., min_length=1, max_length=255)
    slug: str = Field(..., min_length=2, max_length=100)
    description: str | None = Field(default=None, max_length=1000)
    tier: ServiceTier = Field(default=ServiceTier.MEDIUM)

    model_config = ConfigDict(extra="ignore")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Service name cannot be empty")
        return trimmed

    @field_validator("slug")
    @classmethod
    def validate_slug(cls, v: str) -> str:
        trimmed = v.strip().lower()
        if not SLUG_REGEX.match(trimmed):
            raise ValueError(
                "Service slug must contain only lowercase alphanumeric characters and hyphens, "
                "and cannot start or end with a hyphen"
            )
        return trimmed


class ServiceUpdate(BaseModel):
    """Request payload to update an existing Service or deactivate it."""

    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1000)
    tier: ServiceTier | None = None
    is_active: bool | None = None

    model_config = ConfigDict(extra="ignore")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str | None) -> str | None:
        if v is None:
            return None
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Service name cannot be empty")
        return trimmed


class ServiceRead(BaseModel):
    """Response payload for a Service."""

    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    slug: str
    description: str | None
    tier: ServiceTier
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
