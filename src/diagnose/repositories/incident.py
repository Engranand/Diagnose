"""Repository for Incident and IncidentEvent data access."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Sequence

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.sorting import validate_date_range, validate_sort_field
from diagnose.models.incident import Incident
from diagnose.models.incident_event import IncidentEvent
from diagnose.models.organization import Organization

INCIDENT_SORT_FIELDS = {
    "created_at": Incident.created_at,
    "updated_at": Incident.updated_at,
    "severity": Incident.severity,
    "status": Incident.status,
}


class IncidentRepository:
    """Tenant-scoped repository for incidents and immutable incident events."""

    async def get_next_incident_number(
        self, session: AsyncSession, organization_id: uuid.UUID
    ) -> int:
        """Atomically calculate the next incident number for the tenant.

        Locks the organization row for update to serialize concurrent creations
        within the tenant and guarantee gap-free, non-colliding incident numbers.
        """
        # Lock organization row to serialize numbering
        org_lock_stmt = (
            select(Organization.id)
            .where(Organization.id == organization_id)
            .with_for_update()
        )
        await session.execute(org_lock_stmt)

        stmt = select(
            func.coalesce(func.max(Incident.incident_number), 0) + 1
        ).where(Incident.organization_id == organization_id)
        result = await session.execute(stmt)
        return int(result.scalar_one())

    async def create_incident(
        self, session: AsyncSession, incident: Incident
    ) -> Incident:
        """Add a new incident to the active session."""
        session.add(incident)
        await session.flush()
        return incident

    async def get_by_id(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        incident_id: uuid.UUID,
        for_update: bool = False,
    ) -> Incident | None:
        """Retrieve an incident strictly scoped to an organization."""
        query = select(Incident).where(
            Incident.organization_id == organization_id,
            Incident.id == incident_id,
        )
        if for_update:
            query = query.with_for_update()
        result = await session.execute(query)
        return result.scalar_one_or_none()

    async def list_incidents(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        status: str | None = None,
        severity: str | None = None,
        service_id: uuid.UUID | None = None,
        assigned_user_id: uuid.UUID | None = None,
        created_from: datetime | None = None,
        created_to: datetime | None = None,
        search: str | None = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[Incident], int]:
        """List and count incidents for a tenant with optional filtering, search, sorting, and pagination."""
        tz_from, tz_to = validate_date_range(created_from, created_to)

        base_query = select(Incident).where(Incident.organization_id == organization_id)

        if status is not None:
            base_query = base_query.where(Incident.status == status)
        if severity is not None:
            base_query = base_query.where(Incident.severity == severity)
        if service_id is not None:
            base_query = base_query.where(Incident.service_id == service_id)
        if assigned_user_id is not None:
            base_query = base_query.where(Incident.assigned_user_id == assigned_user_id)
        if tz_from is not None:
            base_query = base_query.where(Incident.created_at >= tz_from)
        if tz_to is not None:
            base_query = base_query.where(Incident.created_at <= tz_to)

        if search:
            escaped = search.strip().replace("%", "\\%").replace("_", "\\_")
            base_query = base_query.where(
                or_(
                    Incident.title.ilike(f"%{escaped}%"),
                    Incident.description.ilike(f"%{escaped}%"),
                )
            )

        count_query = select(func.count()).select_from(base_query.subquery())
        total = (await session.execute(count_query)).scalar_one()

        order_clauses = validate_sort_field(
            sort_by=sort_by,
            allowed_columns=INCIDENT_SORT_FIELDS,
            default_field="created_at",
            sort_order=sort_order,
            tie_breaker_column=Incident.id,
        )

        items_query = (
            base_query.order_by(*order_clauses)
            .offset(offset)
            .limit(limit)
        )
        items = (await session.execute(items_query)).scalars().all()

        return items, total

    async def create_event(
        self, session: AsyncSession, event: IncidentEvent
    ) -> IncidentEvent:
        """Add an immutable timeline event to the active session."""
        session.add(event)
        await session.flush()
        return event

    async def list_events(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        incident_id: uuid.UUID,
    ) -> Sequence[IncidentEvent]:
        """List chronological timeline events for an incident."""
        query = (
            select(IncidentEvent)
            .where(
                IncidentEvent.organization_id == organization_id,
                IncidentEvent.incident_id == incident_id,
            )
            .order_by(IncidentEvent.created_at.asc())
        )
        result = await session.execute(query)
        return result.scalars().all()
