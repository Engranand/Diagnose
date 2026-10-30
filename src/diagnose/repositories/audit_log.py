"""AuditLog repository."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.models.audit_log import AuditLog


class AuditLogRepository:
    """Data-access methods for AuditLog entities."""

    async def create(
        self, session: AsyncSession, audit_log: AuditLog
    ) -> AuditLog:
        """Add and flush a new audit log record."""
        session.add(audit_log)
        await session.flush()
        return audit_log

    async def list_by_organization(
        self,
        session: AsyncSession,
        organization_id: UUID,
        limit: int = 100,
    ) -> list[AuditLog]:
        """List audit records for the specified organization."""
        stmt = (
            select(AuditLog)
            .where(AuditLog.organization_id == organization_id)
            .order_by(AuditLog.created_at.desc())
            .limit(limit)
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())
