"""AuditLog response schema."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class AuditLogResponse(BaseModel):
    """Public representation of an immutable audit record."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    actor_user_id: UUID | None
    action: str
    entity_type: str
    entity_id: UUID
    old_values: dict[str, Any] | None
    new_values: dict[str, Any] | None
    correlation_id: str | None
    ip_address: str | None = None
    created_at: datetime


class AuditLogListResponse(BaseModel):
    """Paginated response envelope for audit logs."""

    items: list[AuditLogResponse]
    total: int
    page: int
    page_size: int
    pages: int
