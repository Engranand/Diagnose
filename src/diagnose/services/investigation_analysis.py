"""Orchestration service for LLM-powered incident investigation analysis (Milestone 9)."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Sequence
from datetime import datetime, timezone

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.exceptions import ConflictError, EntityNotFound
from diagnose.domain.investigation import InvestigationStatus
from diagnose.domain.llm import (
    AnalysisStatus,
    LLMError,
    LLMProviderUnavailableError,
    LLMTimeoutError,
    LLMValidationError,
    PROMPT_VERSION,
)
from diagnose.llm.base import LLMProvider
from diagnose.llm.context import (
    InvestigationContext,
    SanitizedCandidateCause,
    SanitizedCorrelation,
    SanitizedHypothesis,
    SanitizedHypothesisEvidence,
    SanitizedIncident,
    SanitizedService,
    SanitizedTimelineEvent,
)
from diagnose.llm.prompts import SYSTEM_PROMPT, build_user_prompt
from diagnose.llm.provider import get_llm_provider
from diagnose.llm.validator import validate_analysis
from diagnose.models.investigation_analysis import InvestigationAnalysis
from diagnose.repositories.evidence import EvidenceRepository
from diagnose.repositories.incident import IncidentRepository
from diagnose.repositories.investigation import InvestigationRepository
from diagnose.repositories.investigation_analysis import InvestigationAnalysisRepository
from diagnose.repositories.service import ServiceRepository
from diagnose.schemas.llm import InvestigationAnalysisOutput
from diagnose.services.audit import AuditService
from diagnose.settings import Settings, get_settings

log = structlog.get_logger()


class InvestigationAnalysisService:
    """Orchestrates deterministic context compilation, LLM analysis, grounding validation, and persistence."""

    def __init__(
        self,
        analysis_repo: InvestigationAnalysisRepository | None = None,
        investigation_repo: InvestigationRepository | None = None,
        incident_repo: IncidentRepository | None = None,
        service_repo: ServiceRepository | None = None,
        evidence_repo: EvidenceRepository | None = None,
        audit_service: AuditService | None = None,
        llm_provider: LLMProvider | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.analysis_repo = analysis_repo or InvestigationAnalysisRepository()
        self.investigation_repo = investigation_repo or InvestigationRepository()
        self.incident_repo = incident_repo or IncidentRepository()
        self.service_repo = service_repo or ServiceRepository()
        self.evidence_repo = evidence_repo or EvidenceRepository()
        self.audit_service = audit_service or AuditService()
        self.settings = settings or get_settings()
        self.provider = llm_provider

    def _get_provider(self) -> LLMProvider:
        """Resolve configured LLM provider instance."""
        if self.provider is not None:
            return self.provider
        return get_llm_provider(self.settings)

    async def build_context(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        investigation_id: uuid.UUID,
    ) -> InvestigationContext:
        """Deterministically compile bounded M8 investigation context for the LLM."""
        run = await self.investigation_repo.get_run_by_id(
            session, organization_id, investigation_id
        )
        if run is None:
            raise EntityNotFound("InvestigationRun", str(investigation_id))

        incident = await self.incident_repo.get_by_id(session, organization_id, run.incident_id)
        if incident is None:
            raise EntityNotFound("Incident", str(run.incident_id))

        service = (
            await self.service_repo.get_by_id(session, organization_id, incident.service_id)
            if incident.service_id
            else None
        )

        timeline_events, _ = await self.investigation_repo.list_timeline_events(
            session, organization_id, run.id, offset=0, limit=200
        )
        correlations, _ = await self.investigation_repo.list_correlations(
            session, organization_id, run.id, offset=0, limit=200
        )
        causes = await self.investigation_repo.list_candidate_causes(
            session, organization_id, run.id
        )
        hypotheses = await self.investigation_repo.list_hypotheses(
            session, organization_id, run.id
        )
        evidence_records, _ = await self.evidence_repo.list_by_incident(
            session, organization_id, incident.id, limit=200
        )

        # Collect complete set of valid evidence identifiers
        valid_evidence_set: set[str] = set()
        for te in timeline_events:
            valid_evidence_set.add(str(te.source_id))
        for c in correlations:
            valid_evidence_set.add(str(c.source_evidence_id))
            valid_evidence_set.add(str(c.target_evidence_id))
        for h in hypotheses:
            for el in h.evidence_links:
                valid_evidence_set.add(str(el.evidence_id))
        for ev in evidence_records:
            valid_evidence_set.add(str(ev.id))

        valid_evidence_list = sorted(valid_evidence_set)
        valid_hypothesis_list = [str(h.id) for h in hypotheses]

        sanitized_incident = SanitizedIncident(
            id=str(incident.id),
            incident_number=incident.incident_number,
            title=incident.title,
            description=incident.description,
            severity=incident.severity,
            status=incident.status,
            detected_at=incident.detected_at.isoformat(),
            acknowledged_at=incident.acknowledged_at.isoformat() if incident.acknowledged_at else None,
            resolved_at=incident.resolved_at.isoformat() if incident.resolved_at else None,
        )

        sanitized_service = (
            SanitizedService(
                id=str(service.id),
                name=service.name,
                slug=service.slug,
                tier=service.tier,
                description=service.description,
            )
            if service
            else None
        )

        sanitized_timeline = [
            SanitizedTimelineEvent(
                timestamp=te.timestamp.isoformat(),
                source_id=te.source_id,
                source_type=te.source_type,
                event_type=te.event_type,
                summary=te.summary,
                reliability=te.reliability,
                metadata=te.event_metadata or {},
            )
            for te in timeline_events
        ]

        sanitized_correlations = [
            SanitizedCorrelation(
                source_evidence_id=c.source_evidence_id,
                target_evidence_id=c.target_evidence_id,
                correlation_type=c.correlation_type,
                strength=c.strength,
                score=c.score,
                explanation=c.explanation,
            )
            for c in correlations
        ]

        sanitized_causes = [
            SanitizedCandidateCause(
                id=str(cc.id),
                cause_type=cc.cause_type,
                title=cc.title,
                description=cc.description,
                service_id=str(cc.service_id) if cc.service_id else None,
            )
            for cc in causes
        ]

        sanitized_hypotheses = [
            SanitizedHypothesis(
                id=str(h.id),
                title=h.title,
                explanation=h.explanation,
                confidence=h.confidence,
                score=h.score,
                rank=h.rank,
                status=h.status,
                evidence_links=[
                    SanitizedHypothesisEvidence(
                        evidence_id=el.evidence_id,
                        evidence_type=el.evidence_type,
                        relationship=el.relationship,
                        contribution=el.contribution,
                        explanation=el.explanation,
                    )
                    for el in h.evidence_links
                ],
            )
            for h in hypotheses
        ]

        return InvestigationContext(
            investigation_id=str(run.id),
            run_number=run.run_number,
            completed_at=run.completed_at.isoformat() if run.completed_at else None,
            incident=sanitized_incident,
            service=sanitized_service,
            timeline=sanitized_timeline,
            correlations=sanitized_correlations,
            candidate_causes=sanitized_causes,
            hypotheses=sanitized_hypotheses,
            valid_evidence_ids=valid_evidence_list,
            valid_hypothesis_ids=valid_hypothesis_list,
        )

    async def execute_analysis(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        investigation_id: uuid.UUID,
        force_refresh: bool = False,
        actor_user_id: uuid.UUID | None = None,
        correlation_id: str | None = None,
    ) -> InvestigationAnalysis:
        """Execute evidence-grounded LLM analysis for an investigation run."""
        run = await self.investigation_repo.get_run_by_id(
            session, organization_id, investigation_id
        )
        if run is None:
            raise EntityNotFound("InvestigationRun", str(investigation_id))

        if run.status != InvestigationStatus.COMPLETED.value:
            raise ConflictError(
                f"Deterministic investigation ({investigation_id}) must be COMPLETED before running LLM analysis (current: {run.status})."
            )

        context = await self.build_context(session, organization_id, investigation_id)
        provider = self._get_provider()
        provider_name = provider.provider_name
        model_name = provider.model_name
        prompt_version = PROMPT_VERSION

        input_hash = context.compute_input_hash(
            model_provider=provider_name,
            model_name=model_name,
            prompt_version=prompt_version,
        )

        # Idempotency check: if identical completed analysis exists and not forced, return it
        if not force_refresh:
            existing = await self.analysis_repo.get_by_input_hash(
                session=session,
                organization_id=organization_id,
                investigation_id=investigation_id,
                input_hash=input_hash,
            )
            if existing is not None:
                log.info(
                    "llm_analysis_idempotent_hit",
                    investigation_id=str(investigation_id),
                    analysis_id=str(existing.id),
                    input_hash=input_hash,
                )
                return existing

        # Create record in PENDING status
        analysis_id = uuid.uuid4()
        analysis = InvestigationAnalysis(
            id=analysis_id,
            organization_id=organization_id,
            investigation_id=investigation_id,
            model_provider=provider_name,
            model_name=model_name,
            prompt_version=prompt_version,
            status=AnalysisStatus.PENDING.value,
            input_hash=input_hash,
        )
        await self.analysis_repo.create_analysis(session, analysis)
        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="LLM_ANALYSIS_CREATED",
            entity_type="investigation_analysis",
            entity_id=analysis_id,
            new_values={
                "investigation_id": str(investigation_id),
                "provider": provider_name,
                "model": model_name,
                "prompt_version": prompt_version,
                "input_hash": input_hash,
                "status": analysis.status,
            },
            correlation_id=correlation_id,
        )
        await session.commit()

        # Transition to RUNNING
        analysis = await self.analysis_repo.get_analysis_by_id(session, organization_id, analysis_id)
        if analysis is None:
            raise EntityNotFound("InvestigationAnalysis", str(analysis_id))

        analysis.status = AnalysisStatus.RUNNING.value
        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="LLM_ANALYSIS_STARTED",
            entity_type="investigation_analysis",
            entity_id=analysis_id,
            new_values={"status": analysis.status},
            correlation_id=correlation_id,
        )
        await session.commit()

        user_prompt = build_user_prompt(context)

        try:
            raw_output, metadata = await provider.generate_analysis(
                context=context,
                system_prompt=SYSTEM_PROMPT,
                user_prompt=user_prompt,
            )

            # Post-generation grounding validation
            validate_analysis(raw_output, context)

            # Compute output hash
            structured_dict = raw_output.model_dump(mode="json")
            canonical_output = json.dumps(structured_dict, sort_keys=True, separators=(",", ":"))
            output_hash = hashlib.sha256(canonical_output.encode("utf-8")).hexdigest()

            analysis = await self.analysis_repo.get_analysis_by_id(session, organization_id, analysis_id)
            if analysis is not None:
                analysis.status = AnalysisStatus.COMPLETED.value
                analysis.summary = raw_output.summary
                analysis.structured_output = structured_dict
                analysis.output_hash = output_hash
                analysis.error = None
                analysis.updated_at = datetime.now(timezone.utc)

            await self.audit_service.record(
                session=session,
                organization_id=organization_id,
                actor_user_id=actor_user_id,
                action="LLM_ANALYSIS_COMPLETED",
                entity_type="investigation_analysis",
                entity_id=analysis_id,
                new_values={
                    "status": AnalysisStatus.COMPLETED.value,
                    "output_hash": output_hash,
                    "primary_hypothesis_id": str(raw_output.primary_hypothesis_id) if raw_output.primary_hypothesis_id else None,
                    "key_findings_count": len(raw_output.key_findings),
                },
                correlation_id=correlation_id,
            )
            await session.commit()
            return analysis

        except Exception as exc:
            log.error(
                "llm_analysis_execution_failed",
                investigation_id=str(investigation_id),
                analysis_id=str(analysis_id),
                error=str(exc),
            )
            try:
                await session.rollback()
                failed_analysis = await self.analysis_repo.get_analysis_by_id(
                    session, organization_id, analysis_id
                )
                if failed_analysis is not None:
                    failed_analysis.status = AnalysisStatus.FAILED.value
                    failed_analysis.error = str(exc)
                    failed_analysis.updated_at = datetime.now(timezone.utc)
                    await self.audit_service.record(
                        session=session,
                        organization_id=organization_id,
                        actor_user_id=actor_user_id,
                        action="LLM_ANALYSIS_FAILED",
                        entity_type="investigation_analysis",
                        entity_id=analysis_id,
                        new_values={"status": AnalysisStatus.FAILED.value, "error": str(exc)},
                        correlation_id=correlation_id,
                    )
                    await session.commit()
            except Exception:
                pass
            raise

    async def get_analysis(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        analysis_id: uuid.UUID,
    ) -> InvestigationAnalysis:
        """Retrieve a specific analysis record strictly within tenant boundary."""
        analysis = await self.analysis_repo.get_analysis_by_id(
            session, organization_id, analysis_id
        )
        if analysis is None:
            raise EntityNotFound("InvestigationAnalysis", str(analysis_id))
        return analysis

    async def get_latest_analysis(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        investigation_id: uuid.UUID,
    ) -> InvestigationAnalysis:
        """Retrieve the latest completed analysis for an investigation."""
        # Ensure investigation exists and belongs to tenant
        run = await self.investigation_repo.get_run_by_id(
            session, organization_id, investigation_id
        )
        if run is None:
            raise EntityNotFound("InvestigationRun", str(investigation_id))

        analysis = await self.analysis_repo.get_latest_completed(
            session, organization_id, investigation_id
        )
        if analysis is None:
            raise EntityNotFound(
                "InvestigationAnalysis",
                f"No completed LLM analysis found for investigation '{investigation_id}'",
            )
        return analysis
