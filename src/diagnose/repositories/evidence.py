"""Repository for Evidence data access."""

from __future__ import annotations

import uuid
from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.models.evidence import Evidence


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
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[Evidence], int]:
        """List and count evidence items for an incident within the tenant."""
        base_query = select(Evidence).where(
            Evidence.organization_id == organization_id,
            Evidence.incident_id == incident_id,
        )
        if evidence_type is not None:
            base_query = base_query.where(Evidence.evidence_type == evidence_type)

        count_query = select(func.count()).select_from(base_query.subquery())
        total = (await session.execute(count_query)).scalar_one()

        items_query = (
            base_query.order_by(Evidence.created_at.asc())
            .offset(offset)
            .limit(limit)
        )
        items = (await session.execute(items_query)).scalars().all()

        return items, total
