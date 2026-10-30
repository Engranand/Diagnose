"""Tenant-scoped database repository for Root-Cause Analysis (Milestone 8)."""

from __future__ import annotations

import uuid
from typing import Sequence

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from diagnose.domain.investigation import InvestigationStatus
from diagnose.models.investigation import (
    CandidateCause,
    EvidenceCorrelation,
    HypothesisEvidence,
    InvestigationHypothesis,
    InvestigationRun,
    InvestigationStep,
    InvestigationTimelineEvent,
)


class InvestigationRepository:
    """Repository managing persistence of investigation runs and artifacts."""

    async def create_run(
        self, session: AsyncSession, run: InvestigationRun
    ) -> InvestigationRun:
        """Persist a new investigation run."""
        session.add(run)
        await session.flush()
        return run

    async def get_run_by_id(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        run_id: uuid.UUID,
        for_update: bool = False,
    ) -> InvestigationRun | None:
        """Retrieve an investigation run scoped strictly to an organization."""
        query = (
            select(InvestigationRun)
            .where(
                InvestigationRun.organization_id == organization_id,
                InvestigationRun.id == run_id,
            )
            .options(
                selectinload(InvestigationRun.steps),
                selectinload(InvestigationRun.hypotheses).selectinload(
                    InvestigationHypothesis.evidence_links
                ),
            )
            .execution_options(populate_existing=True)
        )
        if for_update:
            query = query.with_for_update()
        result = await session.execute(query)
        return result.scalar_one_or_none()

    async def get_active_run_for_incident(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        incident_id: uuid.UUID,
        for_update: bool = False,
    ) -> InvestigationRun | None:
        """Find any currently active (PENDING or RUNNING) run for an incident."""
        query = select(InvestigationRun).where(
            InvestigationRun.organization_id == organization_id,
            InvestigationRun.incident_id == incident_id,
            InvestigationRun.status.in_(
                [InvestigationStatus.PENDING.value, InvestigationStatus.RUNNING.value]
            ),
        )
        if for_update:
            query = query.with_for_update()
        result = await session.execute(query)
        return result.scalar_one_or_none()

    async def get_next_run_number(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        incident_id: uuid.UUID,
    ) -> int:
        """Compute the next sequential run number for an incident."""
        query = select(
            func.coalesce(func.max(InvestigationRun.run_number), 0) + 1
        ).where(
            InvestigationRun.organization_id == organization_id,
            InvestigationRun.incident_id == incident_id,
        )
        result = await session.execute(query)
        return result.scalar_one()

    async def list_runs_for_incident(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        incident_id: uuid.UUID,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[InvestigationRun], int]:
        """List investigation runs for an incident sorted by run_number DESC."""
        count_q = (
            select(func.count(InvestigationRun.id))
            .where(
                InvestigationRun.organization_id == organization_id,
                InvestigationRun.incident_id == incident_id,
            )
        )
        total = (await session.execute(count_q)).scalar_one()

        items_q = (
            select(InvestigationRun)
            .where(
                InvestigationRun.organization_id == organization_id,
                InvestigationRun.incident_id == incident_id,
            )
            .order_by(InvestigationRun.run_number.desc())
            .offset(offset)
            .limit(limit)
        )
        items = (await session.execute(items_q)).scalars().all()
        return items, total

    async def create_step(
        self, session: AsyncSession, step: InvestigationStep
    ) -> InvestigationStep:
        """Record an investigation step execution."""
        session.add(step)
        await session.flush()
        return step

    async def create_timeline_events(
        self, session: AsyncSession, events: list[InvestigationTimelineEvent]
    ) -> None:
        """Batch insert timeline events."""
        session.add_all(events)
        await session.flush()

    async def list_timeline_events(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        investigation_run_id: uuid.UUID,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[InvestigationTimelineEvent], int]:
        """List normalized timeline events sorted deterministically: timestamp ASC, source_id ASC."""
        base_filter = [
            InvestigationTimelineEvent.organization_id == organization_id,
            InvestigationTimelineEvent.investigation_run_id == investigation_run_id,
        ]
        count_q = select(func.count(InvestigationTimelineEvent.id)).where(*base_filter)
        total = (await session.execute(count_q)).scalar_one()

        items_q = (
            select(InvestigationTimelineEvent)
            .where(*base_filter)
            .order_by(
                InvestigationTimelineEvent.timestamp.asc(),
                InvestigationTimelineEvent.source_id.asc(),
            )
            .offset(offset)
            .limit(limit)
        )
        items = (await session.execute(items_q)).scalars().all()
        return items, total

    async def create_correlations(
        self, session: AsyncSession, correlations: list[EvidenceCorrelation]
    ) -> None:
        """Batch insert evidence correlation records."""
        session.add_all(correlations)
        await session.flush()

    async def list_correlations(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        investigation_run_id: uuid.UUID,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[EvidenceCorrelation], int]:
        """List correlations for a run ordered by score DESC."""
        base_filter = [
            EvidenceCorrelation.organization_id == organization_id,
            EvidenceCorrelation.investigation_run_id == investigation_run_id,
        ]
        count_q = select(func.count(EvidenceCorrelation.id)).where(*base_filter)
        total = (await session.execute(count_q)).scalar_one()

        items_q = (
            select(EvidenceCorrelation)
            .where(*base_filter)
            .order_by(
                EvidenceCorrelation.score.desc(),
                EvidenceCorrelation.id.asc(),
            )
            .offset(offset)
            .limit(limit)
        )
        items = (await session.execute(items_q)).scalars().all()
        return items, total

    async def create_candidate_causes(
        self, session: AsyncSession, causes: list[CandidateCause]
    ) -> None:
        """Batch insert candidate causes."""
        session.add_all(causes)
        await session.flush()

    async def create_hypotheses(
        self, session: AsyncSession, hypotheses: list[InvestigationHypothesis]
    ) -> None:
        """Batch insert hypotheses."""
        session.add_all(hypotheses)
        await session.flush()

    async def create_hypothesis_evidence(
        self, session: AsyncSession, evidence_links: list[HypothesisEvidence]
    ) -> None:
        """Batch insert hypothesis evidence links."""
        session.add_all(evidence_links)
        await session.flush()

    async def list_hypotheses(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        investigation_run_id: uuid.UUID,
    ) -> Sequence[InvestigationHypothesis]:
        """List evaluated hypotheses for a run ordered by rank ASC."""
        query = (
            select(InvestigationHypothesis)
            .where(
                InvestigationHypothesis.organization_id == organization_id,
                InvestigationHypothesis.investigation_run_id == investigation_run_id,
            )
            .options(selectinload(InvestigationHypothesis.evidence_links))
            .order_by(
                InvestigationHypothesis.rank.asc(),
                InvestigationHypothesis.id.asc(),
            )
        )
        result = await session.execute(query)
        return result.scalars().all()

    async def clear_run_artifacts(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        investigation_run_id: uuid.UUID,
    ) -> None:
        """Clear previously generated artifacts for an investigation run before re-execution."""
        await session.execute(
            delete(HypothesisEvidence).where(
                HypothesisEvidence.organization_id == organization_id,
                HypothesisEvidence.investigation_run_id == investigation_run_id,
            )
        )
        await session.execute(
            delete(InvestigationHypothesis).where(
                InvestigationHypothesis.organization_id == organization_id,
                InvestigationHypothesis.investigation_run_id == investigation_run_id,
            )
        )
        await session.execute(
            delete(CandidateCause).where(
                CandidateCause.organization_id == organization_id,
                CandidateCause.investigation_run_id == investigation_run_id,
            )
        )
        await session.execute(
            delete(EvidenceCorrelation).where(
                EvidenceCorrelation.organization_id == organization_id,
                EvidenceCorrelation.investigation_run_id == investigation_run_id,
            )
        )
        await session.execute(
            delete(InvestigationTimelineEvent).where(
                InvestigationTimelineEvent.organization_id == organization_id,
                InvestigationTimelineEvent.investigation_run_id == investigation_run_id,
            )
        )
        await session.execute(
            delete(InvestigationStep).where(
                InvestigationStep.organization_id == organization_id,
                InvestigationStep.investigation_run_id == investigation_run_id,
            )
        )
        await session.flush()
