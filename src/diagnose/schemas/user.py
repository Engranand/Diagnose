"""User request and response schemas."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from diagnose.domain.roles import Role


class UserResponse(BaseModel):
    """Public representation of a user."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    email: str
    full_name: str | None
    role: Role
    is_active: bool
    created_at: datetime
    updated_at: datetime


class UserCreateRequest(BaseModel):
    """Payload to create a new user within the caller's organization."""

    model_config = ConfigDict(extra="ignore")

    email: str = Field(..., min_length=3, max_length=255, description="Unique user email within organization")
    password: str = Field(..., min_length=8, description="User password (min 8 chars)")
    full_name: str | None = Field(None, max_length=255)
    role: Role = Field(default=Role.VIEWER, description="Initial role")


class UserUpdateRequest(BaseModel):
    """Payload to update a user (ADMIN only)."""

    model_config = ConfigDict(extra="ignore")

    full_name: str | None = Field(None, max_length=255)
    role: Role | None = None
    is_active: bool | None = None


class UserMeUpdateRequest(BaseModel):
    """Payload for self-update (no role or org modification allowed)."""

    model_config = ConfigDict(extra="ignore")

    full_name: str | None = Field(None, max_length=255)
