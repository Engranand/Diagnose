"""AuditLog repository."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.sorting import validate_date_range, validate_sort_field
from diagnose.models.audit_log import AuditLog

AUDIT_LOG_SORT_FIELDS = {
    "created_at": AuditLog.created_at,
    "action": AuditLog.action,
}


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
        action: str | None = None,
        entity_type: str | None = None,
        actor_user_id: UUID | None = None,
        created_from: datetime | None = None,
        created_to: datetime | None = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[AuditLog], int]:
        """List and count audit records for the specified organization with filtering, sorting, and pagination."""
        tz_from, tz_to = validate_date_range(created_from, created_to)

        base_query = select(AuditLog).where(AuditLog.organization_id == organization_id)

        if action is not None:
            base_query = base_query.where(AuditLog.action == action)
        if entity_type is not None:
            base_query = base_query.where(AuditLog.entity_type == entity_type)
        if actor_user_id is not None:
            base_query = base_query.where(AuditLog.actor_user_id == actor_user_id)
        if tz_from is not None:
            base_query = base_query.where(AuditLog.created_at >= tz_from)
        if tz_to is not None:
            base_query = base_query.where(AuditLog.created_at <= tz_to)

        count_query = select(func.count()).select_from(base_query.subquery())
        total = (await session.execute(count_query)).scalar_one()

        order_clauses = validate_sort_field(
            sort_by=sort_by,
            allowed_columns=AUDIT_LOG_SORT_FIELDS,
            default_field="created_at",
            sort_order=sort_order,
            tie_breaker_column=AuditLog.id,
        )

        stmt = base_query.order_by(*order_clauses).offset(offset).limit(limit)
        result = await session.execute(stmt)
        return list(result.scalars().all()), total
