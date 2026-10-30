"""Repository for persisting and querying LLM investigation analyses (Milestone 9)."""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.llm import AnalysisStatus
from diagnose.models.investigation_analysis import InvestigationAnalysis


class InvestigationAnalysisRepository:
    """Tenant-scoped repository for investigation analyses."""

    async def create_analysis(
        self, session: AsyncSession, analysis: InvestigationAnalysis
    ) -> InvestigationAnalysis:
        """Persist a new investigation analysis record."""
        session.add(analysis)
        await session.flush()
        return analysis

    async def get_analysis_by_id(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        analysis_id: uuid.UUID,
    ) -> InvestigationAnalysis | None:
        """Retrieve an analysis record strictly scoped to the tenant."""
        stmt = select(InvestigationAnalysis).where(
            InvestigationAnalysis.organization_id == organization_id,
            InvestigationAnalysis.id == analysis_id,
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_latest_completed(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        investigation_id: uuid.UUID,
    ) -> InvestigationAnalysis | None:
        """Retrieve the latest COMPLETED analysis for an investigation in this tenant."""
        stmt = (
            select(InvestigationAnalysis)
            .where(
                InvestigationAnalysis.organization_id == organization_id,
                InvestigationAnalysis.investigation_id == investigation_id,
                InvestigationAnalysis.status == AnalysisStatus.COMPLETED.value,
            )
            .order_by(InvestigationAnalysis.created_at.desc())
            .limit(1)
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_input_hash(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        investigation_id: uuid.UUID,
        input_hash: str,
    ) -> InvestigationAnalysis | None:
        """Find an existing COMPLETED analysis matching the exact input hash for idempotency."""
        stmt = (
            select(InvestigationAnalysis)
            .where(
                InvestigationAnalysis.organization_id == organization_id,
                InvestigationAnalysis.investigation_id == investigation_id,
                InvestigationAnalysis.input_hash == input_hash,
                InvestigationAnalysis.status == AnalysisStatus.COMPLETED.value,
            )
            .order_by(InvestigationAnalysis.created_at.desc())
            .limit(1)
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_analyses(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        investigation_id: uuid.UUID,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[InvestigationAnalysis], int]:
        """List all analyses for an investigation with total count."""
        base_where = (
            InvestigationAnalysis.organization_id == organization_id,
            InvestigationAnalysis.investigation_id == investigation_id,
        )

        count_stmt = select(func.count(InvestigationAnalysis.id)).where(*base_where)
        total = (await session.execute(count_stmt)).scalar() or 0

        stmt = (
            select(InvestigationAnalysis)
            .where(*base_where)
            .order_by(InvestigationAnalysis.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        result = await session.execute(stmt)
        return result.scalars().all(), total
