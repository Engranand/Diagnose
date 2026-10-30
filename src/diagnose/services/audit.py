"""Audit service — records immutable audit log entries within existing transactions."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.models.audit_log import AuditLog
from diagnose.repositories.audit_log import AuditLogRepository

# Blacklist of fields that must NEVER appear in audit logs
FORBIDDEN_FIELDS = {
    "password",
    "password_hash",
    "hashed_password",
    "token",
    "access_token",
    "refresh_token",
    "secret",
    "jwt",
}


def sanitize_audit_payload(
    payload: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Filter out any sensitive keys from audit log payloads."""
    if payload is None:
        return None
    return {
        k: v
        for k, v in payload.items()
        if k.lower() not in FORBIDDEN_FIELDS
    }


class AuditService:
    """Service to create audit log records within active session transactions."""

    def __init__(
        self, repository: AuditLogRepository | None = None
    ) -> None:
        self.repository = repository or AuditLogRepository()

    async def record(
        self,
        session: AsyncSession,
        organization_id: UUID,
        actor_user_id: UUID | None,
        action: str,
        entity_type: str,
        entity_id: UUID,
        old_values: dict[str, Any] | None = None,
        new_values: dict[str, Any] | None = None,
        correlation_id: str | None = None,
        ip_address: str | None = None,
    ) -> AuditLog:
        """Create and flush an audit log entry in the current session.

        This ensures the audit record is committed or rolled back atomically
        with the business mutation.
        """
        entry = AuditLog(
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            old_values=sanitize_audit_payload(old_values),
            new_values=sanitize_audit_payload(new_values),
            correlation_id=correlation_id,
            ip_address=ip_address,
        )
        return await self.repository.create(session, entry)
