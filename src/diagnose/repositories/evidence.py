"""Repository for Evidence data access."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.sorting import validate_date_range, validate_sort_field
from diagnose.models.evidence import Evidence

EVIDENCE_SORT_FIELDS = {
    "observed_at": Evidence.observed_at,
    "created_at": Evidence.created_at,
}


class EvidenceRepository:
    """Tenant-scoped repository for immutable evidence artifacts."""

    async def create_evidence(
        self, session: AsyncSession, evidence: Evidence
    ) -> Evidence:
        """Add an immutable evidence artifact to the session."""
        session.add(evidence)
        await session.flush()
        return evidence

    async def get_by_id(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        evidence_id: uuid.UUID,
    ) -> Evidence | None:
        """Retrieve an evidence artifact strictly scoped to an organization."""
        query = select(Evidence).where(
            Evidence.organization_id == organization_id,
            Evidence.id == evidence_id,
        )
        result = await session.execute(query)
        return result.scalar_one_or_none()

    async def get_by_hash(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        evidence_hash: str,
    ) -> Evidence | None:
        """Find existing evidence by hash strictly within the tenant."""
        query = select(Evidence).where(
            Evidence.organization_id == organization_id,
            Evidence.evidence_hash == evidence_hash,
        )
        result = await session.execute(query)
        return result.scalar_one_or_none()

    async def list_by_incident(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        incident_id: uuid.UUID,
        evidence_type: str | None = None,
        reliability: str | None = None,
        observed_from: datetime | None = None,
        observed_to: datetime | None = None,
        sort_by: str = "observed_at",
        sort_order: str = "asc",
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[Evidence], int]:
        """List and count evidence items for an incident within the tenant with filtering, sorting, and pagination."""
        tz_from, tz_to = validate_date_range(
            observed_from, observed_to, from_name="observed_from", to_name="observed_to"
        )

        base_query = select(Evidence).where(
            Evidence.organization_id == organization_id,
            Evidence.incident_id == incident_id,
        )
        if evidence_type is not None:
            base_query = base_query.where(Evidence.evidence_type == evidence_type)
        if reliability is not None:
            base_query = base_query.where(Evidence.reliability == reliability)
        if tz_from is not None:
            base_query = base_query.where(Evidence.observed_at >= tz_from)
        if tz_to is not None:
            base_query = base_query.where(Evidence.observed_at <= tz_to)

        count_query = select(func.count()).select_from(base_query.subquery())
        total = (await session.execute(count_query)).scalar_one()

        order_clauses = validate_sort_field(
            sort_by=sort_by,
            allowed_columns=EVIDENCE_SORT_FIELDS,
            default_field="observed_at",
            sort_order=sort_order,
            tie_breaker_column=Evidence.id,
        )

        items_query = (
            base_query.order_by(*order_clauses)
            .offset(offset)
            .limit(limit)
        )
        items = (await session.execute(items_query)).scalars().all()

        return items, total
