"""Deterministic Root-Cause Analysis (RCA) service and execution engine (Milestone 8)."""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from typing import Sequence
import uuid

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.exceptions import ConflictError, EntityNotFound
from diagnose.domain.investigation import (
    CauseType,
    ConfidenceBand,
    CorrelationStrength,
    CorrelationType,
    EvidenceRelationship,
    HypothesisStatus,
    InvestigationStatus,
    InvestigationStepType,
    PENALTY_CONTRADICTING,
    WEIGHT_INCIDENT_ATTACHMENT,
    WEIGHT_RELIABILITY,
    WEIGHT_SERVICE_MATCH,
    WEIGHT_SUPPORTING_EVIDENCE,
    WEIGHT_TEMPORAL,
    calculate_confidence_band,
)
from diagnose.models.alert import Alert
from diagnose.models.evidence import Evidence
from diagnose.models.incident import Incident
from diagnose.models.incident_event import IncidentEvent
from diagnose.models.investigation import (
    CandidateCause,
    EvidenceCorrelation,
    HypothesisEvidence,
    InvestigationHypothesis,
    InvestigationRun,
    InvestigationStep,
    InvestigationTimelineEvent,
)
from diagnose.models.service import Service
from diagnose.repositories.alert import AlertRepository
from diagnose.repositories.evidence import EvidenceRepository
from diagnose.repositories.incident import IncidentRepository
from diagnose.repositories.investigation import InvestigationRepository
from diagnose.repositories.service import ServiceRepository
from diagnose.services.audit import AuditService

log = structlog.get_logger()


@dataclasses.dataclass(frozen=True)
class NormalizedEvidenceItem:
    """Canonical in-memory representation of an evidence item collected across Diagnos."""

    source_type: str
    source_id: str
    timestamp: datetime
    service_id: uuid.UUID | None
    summary: str
    reliability: str
    evidence_type: str
    content_text: str
    metadata: dict


class InvestigationService:
    """Service orchestrating deterministic, reproducible root-cause analysis runs."""

    def __init__(
        self,
        investigation_repo: InvestigationRepository | None = None,
        incident_repo: IncidentRepository | None = None,
        service_repo: ServiceRepository | None = None,
        alert_repo: AlertRepository | None = None,
        evidence_repo: EvidenceRepository | None = None,
        audit_service: AuditService | None = None,
    ) -> None:
        self.investigation_repo = investigation_repo or InvestigationRepository()
        self.incident_repo = incident_repo or IncidentRepository()
        self.service_repo = service_repo or ServiceRepository()
        self.alert_repo = alert_repo or AlertRepository()
        self.evidence_repo = evidence_repo or EvidenceRepository()
        self.audit_service = audit_service or AuditService()

    async def create_investigation(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        incident_id: uuid.UUID,
        actor_user_id: uuid.UUID | None = None,
        correlation_id: str | None = None,
    ) -> InvestigationRun:
        """Create a new investigation run in PENDING status with concurrency guard."""
        # Validate incident belongs strictly to caller's tenant
        incident = await self.incident_repo.get_by_id(session, organization_id, incident_id)
        if incident is None:
            raise EntityNotFound("Incident", str(incident_id))

        # Concurrency protection: prevent concurrent active investigations for the same incident
        active_run = await self.investigation_repo.get_active_run_for_incident(
            session, organization_id, incident_id, for_update=True
        )
        if active_run is not None:
            raise ConflictError(
                f"An active investigation run ({active_run.id}) is already in progress for this incident."
            )

        run_number = await self.investigation_repo.get_next_run_number(
            session, organization_id, incident_id
        )

        run = InvestigationRun(
            organization_id=organization_id,
            incident_id=incident_id,
            status=InvestigationStatus.PENDING.value,
            run_number=run_number,
        )
        created_run = await self.investigation_repo.create_run(session, run)

        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="INVESTIGATION_CREATED",
            entity_type="investigation_run",
            entity_id=created_run.id,
            new_values={
                "incident_id": str(incident_id),
                "run_number": run_number,
                "status": created_run.status,
            },
            correlation_id=correlation_id,
        )
        await session.commit()
        await session.refresh(created_run)
        return created_run

    async def get_investigation(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        investigation_id: uuid.UUID,
    ) -> InvestigationRun:
        """Retrieve investigation run details scoped to caller's tenant."""
        run = await self.investigation_repo.get_run_by_id(
            session, organization_id, investigation_id
        )
        if run is None:
            raise EntityNotFound("InvestigationRun", str(investigation_id))
        return run

    async def list_investigations_for_incident(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        incident_id: uuid.UUID,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[InvestigationRun], int]:
        """List all investigation runs for an incident."""
        incident = await self.incident_repo.get_by_id(session, organization_id, incident_id)
        if incident is None:
            raise EntityNotFound("Incident", str(incident_id))

        return await self.investigation_repo.list_runs_for_incident(
            session, organization_id, incident_id, offset=offset, limit=limit
        )

    async def list_timeline(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        investigation_id: uuid.UUID,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[InvestigationTimelineEvent], int]:
        """Fetch chronologically sorted timeline events for an investigation."""
        await self.get_investigation(session, organization_id, investigation_id)
        return await self.investigation_repo.list_timeline_events(
            session, organization_id, investigation_id, offset=offset, limit=limit
        )

    async def list_correlations(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        investigation_id: uuid.UUID,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[EvidenceCorrelation], int]:
        """Fetch correlations for an investigation."""
        await self.get_investigation(session, organization_id, investigation_id)
        return await self.investigation_repo.list_correlations(
            session, organization_id, investigation_id, offset=offset, limit=limit
        )

    async def list_hypotheses(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        investigation_id: uuid.UUID,
    ) -> Sequence[InvestigationHypothesis]:
        """Fetch evaluated hypotheses for an investigation."""
        await self.get_investigation(session, organization_id, investigation_id)
        return await self.investigation_repo.list_hypotheses(
            session, organization_id, investigation_id
        )

    async def execute_investigation(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        investigation_id: uuid.UUID,
        actor_user_id: uuid.UUID | None = None,
        correlation_id: str | None = None,
    ) -> InvestigationRun:
        """Deterministically execute all steps of an investigation run."""
        run = await self.investigation_repo.get_run_by_id(
            session, organization_id, investigation_id, for_update=True
        )
        if run is None:
            raise EntityNotFound("InvestigationRun", str(investigation_id))

        # Idempotency check: if run is already COMPLETED, return it without duplicate side effects
        if run.status == InvestigationStatus.COMPLETED.value:
            log.info("investigation_already_completed", run_id=str(investigation_id))
            return run

        if run.status == InvestigationStatus.RUNNING.value:
            raise ConflictError(
                f"Investigation run ({investigation_id}) is currently executing."
            )

        # Transition PENDING -> RUNNING
        now = datetime.now(timezone.utc)
        run.status = InvestigationStatus.RUNNING.value
        run.started_at = now
        run.error = None

        # Clean any partial artifacts from prior failed execution
        await self.investigation_repo.clear_run_artifacts(session, organization_id, investigation_id)

        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="INVESTIGATION_STARTED",
            entity_type="investigation_run",
            entity_id=investigation_id,
            new_values={"status": run.status, "started_at": now.isoformat()},
            correlation_id=correlation_id,
        )
        await session.commit()

        try:
            # ── STEP 1: EVIDENCE_COLLECTION ──────────────────────────────────
            step_collection = await self._start_step(
                session, organization_id, investigation_id, InvestigationStepType.EVIDENCE_COLLECTION
            )
            collected_evidence, incident, service = await self._collect_evidence(
                session, organization_id, run.incident_id
            )
            await self._complete_step(
                session, step_collection, metadata={"collected_count": len(collected_evidence)}
            )

            # ── STEP 2: TIMELINE_BUILD ───────────────────────────────────────
            step_timeline = await self._start_step(
                session, organization_id, investigation_id, InvestigationStepType.TIMELINE_BUILD
            )
            timeline_events = self._build_normalized_timeline(investigation_id, organization_id, collected_evidence)
            await self.investigation_repo.create_timeline_events(session, timeline_events)
            await self._complete_step(
                session, step_timeline, metadata={"timeline_events_count": len(timeline_events)}
            )

            # ── STEP 3: CORRELATION ──────────────────────────────────────────
            step_correlation = await self._start_step(
                session, organization_id, investigation_id, InvestigationStepType.CORRELATION
            )
            correlations = self._correlate_evidence(
                investigation_id, organization_id, incident, service, collected_evidence
            )
            await self.investigation_repo.create_correlations(session, correlations)
            await self._complete_step(
                session, step_correlation, metadata={"correlations_count": len(correlations)}
            )

            # ── STEP 4: HYPOTHESIS_GENERATION ────────────────────────────────
            step_gen = await self._start_step(
                session, organization_id, investigation_id, InvestigationStepType.HYPOTHESIS_GENERATION
            )
            candidate_causes = self._generate_candidate_causes(
                investigation_id, organization_id, incident, service, collected_evidence
            )
            await self.investigation_repo.create_candidate_causes(session, candidate_causes)
            await self._complete_step(
                session, step_gen, metadata={"causes_count": len(candidate_causes)}
            )

            # ── STEP 5: HYPOTHESIS_SCORING ───────────────────────────────────
            step_scoring = await self._start_step(
                session, organization_id, investigation_id, InvestigationStepType.HYPOTHESIS_SCORING
            )
            hypotheses, evidence_links = self._score_and_rank_hypotheses(
                investigation_id, organization_id, incident, service, candidate_causes, collected_evidence, correlations
            )
            await self.investigation_repo.create_hypotheses(session, hypotheses)
            await self.investigation_repo.create_hypothesis_evidence(session, evidence_links)
            await self._complete_step(
                session, step_scoring, metadata={"hypotheses_count": len(hypotheses)}
            )

            # ── STEP 6: FINALIZATION ─────────────────────────────────────────
            step_final = await self._start_step(
                session, organization_id, investigation_id, InvestigationStepType.FINALIZATION
            )
            run = await self.investigation_repo.get_run_by_id(session, organization_id, investigation_id)
            if run is not None:
                run.status = InvestigationStatus.COMPLETED.value
                run.completed_at = datetime.now(timezone.utc)
            await self._complete_step(session, step_final, metadata={"final_status": InvestigationStatus.COMPLETED.value})

            # Audit completion
            top_hypo = hypotheses[0] if hypotheses else None
            await self.audit_service.record(
                session=session,
                organization_id=organization_id,
                actor_user_id=actor_user_id,
                action="INVESTIGATION_COMPLETED",
                entity_type="investigation_run",
                entity_id=investigation_id,
                new_values={
                    "status": InvestigationStatus.COMPLETED.value,
                    "top_hypothesis": top_hypo.title if top_hypo else None,
                    "top_confidence": top_hypo.confidence if top_hypo else None,
                    "hypotheses_count": len(hypotheses),
                },
                correlation_id=correlation_id,
            )
            await session.commit()
            return await self.get_investigation(session, organization_id, investigation_id)

        except Exception as exc:
            log.error("investigation_run_failed", run_id=str(investigation_id), error=str(exc))
            try:
                await session.rollback()
                failed_run = await self.investigation_repo.get_run_by_id(session, organization_id, investigation_id)
                if failed_run is not None:
                    failed_run.status = InvestigationStatus.FAILED.value
                    failed_run.completed_at = datetime.now(timezone.utc)
                    failed_run.error = str(exc)
                    await session.commit()
            except Exception:
                pass
            raise

    # ── PRIVATE STEP LIFECYCLE ───────────────────────────────────────────────

    async def _start_step(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        run_id: uuid.UUID,
        step_type: InvestigationStepType,
    ) -> InvestigationStep:
        step = InvestigationStep(
            organization_id=organization_id,
            investigation_run_id=run_id,
            step_type=step_type.value,
            status=InvestigationStatus.RUNNING.value,
            started_at=datetime.now(timezone.utc),
        )
        return await self.investigation_repo.create_step(session, step)

    async def _complete_step(
        self,
        session: AsyncSession,
        step: InvestigationStep,
        metadata: dict | None = None,
    ) -> None:
        step.status = InvestigationStatus.COMPLETED.value
        step.completed_at = datetime.now(timezone.utc)
        step.step_metadata = metadata
        await session.commit()

    # ── STEP 1: EVIDENCE COLLECTION ──────────────────────────────────────────

    async def _collect_evidence(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        incident_id: uuid.UUID,
    ) -> tuple[list[NormalizedEvidenceItem], Incident, Service | None]:
        incident = await self.incident_repo.get_by_id(session, organization_id, incident_id)
        if incident is None:
            raise EntityNotFound("Incident", str(incident_id))

        service = (
            await self.service_repo.get_by_id(session, organization_id, incident.service_id)
            if incident.service_id
            else None
        )

        items: list[NormalizedEvidenceItem] = []

        # 1. Incident Onset & Events
        items.append(
            NormalizedEvidenceItem(
                source_type="incident",
                source_id=str(incident.id),
                timestamp=incident.detected_at,
                service_id=incident.service_id,
                summary=f"Incident #{incident.incident_number} detected: {incident.title}",
                reliability="HIGH",
                evidence_type="EVENT",
                content_text=f"{incident.title}\n{incident.description or ''}",
                metadata={"severity": incident.severity, "status": incident.status},
            )
        )

        incident_events = await self.incident_repo.list_events(session, organization_id, incident.id)
        for ie in incident_events:
            items.append(
                NormalizedEvidenceItem(
                    source_type="incident_event",
                    source_id=str(ie.id),
                    timestamp=ie.created_at,
                    service_id=incident.service_id,
                    summary=f"Incident Event: {ie.event_type} - {ie.message or ''}",
                    reliability="HIGH",
                    evidence_type="EVENT",
                    content_text=ie.message or "",
                    metadata={"event_type": ie.event_type},
                )
            )

        # 2. Alerts attached to incident or service
        alerts, _ = await self.alert_repo.list_alerts(
            session=session,
            organization_id=organization_id,
            service_id=incident.service_id,
            limit=100,
        )
        for a in alerts:
            # Include if attached or occurs near incident window (within 2 hours)
            is_attached = a.incident_id == incident.id
            diff = abs((a.first_seen_at - incident.detected_at).total_seconds())
            if is_attached or diff <= 7200:
                items.append(
                    NormalizedEvidenceItem(
                        source_type="alert",
                        source_id=str(a.id),
                        timestamp=a.first_seen_at,
                        service_id=a.service_id,
                        summary=f"Alert [{a.severity}]: {a.title} ({a.source})",
                        reliability="HIGH" if a.severity in ("CRITICAL", "HIGH") else "MEDIUM",
                        evidence_type="ALERT",
                        content_text=f"{a.title}\n{a.message or ''}",
                        metadata={
                            "fingerprint": a.fingerprint,
                            "alert_type": a.alert_type,
                            "severity": a.severity,
                            "status": a.status,
                        },
                    )
                )

        # 3. Evidence Artifacts
        evidence_records, _ = await self.evidence_repo.list_by_incident(
            session=session,
            organization_id=organization_id,
            incident_id=incident.id,
            limit=100,
        )
        for ev in evidence_records:
            items.append(
                NormalizedEvidenceItem(
                    source_type="evidence",
                    source_id=str(ev.id),
                    timestamp=ev.observed_at or ev.collected_at,
                    service_id=incident.service_id,
                    summary=f"Evidence [{ev.evidence_type}]: {ev.title}",
                    reliability=ev.reliability,
                    evidence_type=ev.evidence_type,
                    content_text=f"{ev.title}\n{ev.content or ''}",
                    metadata={"source": ev.source, "reliability": ev.reliability},
                )
            )

        return items, incident, service

    # ── STEP 2: TIMELINE BUILD ───────────────────────────────────────────────

    def _build_normalized_timeline(
        self,
        run_id: uuid.UUID,
        organization_id: uuid.UUID,
        items: list[NormalizedEvidenceItem],
    ) -> list[InvestigationTimelineEvent]:
        # Deterministic sort: timestamp ASC, source_id ASC tie-breaker
        sorted_items = sorted(items, key=lambda x: (x.timestamp, x.source_id))

        timeline_events: list[InvestigationTimelineEvent] = []
        for item in sorted_items:
            timeline_events.append(
                InvestigationTimelineEvent(
                    id=uuid.uuid4(),
                    organization_id=organization_id,
                    investigation_run_id=run_id,
                    timestamp=item.timestamp,
                    event_type=item.evidence_type,
                    source_type=item.source_type,
                    source_id=item.source_id,
                    service_id=item.service_id,
                    summary=item.summary,
                    reliability=item.reliability,
                    event_metadata=item.metadata,
                )
            )
        return timeline_events

    # ── STEP 3: CORRELATION ENGINE ───────────────────────────────────────────

    def _correlate_evidence(
        self,
        run_id: uuid.UUID,
        organization_id: uuid.UUID,
        incident: Incident,
        service: Service | None,
        items: list[NormalizedEvidenceItem],
    ) -> list[EvidenceCorrelation]:
        correlations: list[EvidenceCorrelation] = []

        # 1. Correlate items with incident onset
        for item in items:
            if item.source_type == "incident":
                continue

            delta_sec = (item.timestamp - incident.detected_at).total_seconds()
            abs_delta = abs(delta_sec)

            # A. Temporal Correlation
            if abs_delta <= 60:
                score = 0.90
                strength = CorrelationStrength.STRONG.value
                expl = f"Evidence occurred within {int(abs_delta)}s of incident detection."
            elif abs_delta <= 300:
                score = 0.70
                strength = CorrelationStrength.MODERATE.value
                expl = f"Evidence occurred within {int(abs_delta)}s of incident detection."
            elif abs_delta <= 1800:
                score = 0.40
                strength = CorrelationStrength.WEAK.value
                expl = f"Evidence occurred {int(abs_delta // 60)} minutes near incident detection."
            else:
                score = 0.15
                strength = CorrelationStrength.WEAK.value
                expl = f"Evidence occurred {int(abs_delta // 60)} minutes away from incident onset."

            correlations.append(
                EvidenceCorrelation(
                    organization_id=organization_id,
                    investigation_run_id=run_id,
                    source_evidence_id=item.source_id,
                    target_evidence_id=str(incident.id),
                    correlation_type=CorrelationType.TEMPORAL.value,
                    strength=strength,
                    score=score,
                    explanation=expl,
                )
            )

            # B. Service Correlation
            if item.service_id is not None and item.service_id == incident.service_id:
                correlations.append(
                    EvidenceCorrelation(
                        organization_id=organization_id,
                        investigation_run_id=run_id,
                        source_evidence_id=item.source_id,
                        target_evidence_id=str(incident.service_id),
                        correlation_type=CorrelationType.SERVICE.value,
                        strength=CorrelationStrength.STRONG.value,
                        score=0.85,
                        explanation=f"Evidence directly matches affected service '{service.name if service else ''}'.",
                    )
                )

            # C. Alert Correlation
            if item.source_type == "alert":
                correlations.append(
                    EvidenceCorrelation(
                        organization_id=organization_id,
                        investigation_run_id=run_id,
                        source_evidence_id=item.source_id,
                        target_evidence_id=str(incident.id),
                        correlation_type=CorrelationType.ALERT.value,
                        strength=CorrelationStrength.STRONG.value,
                        score=0.80,
                        explanation=f"Alert occurred on affected service {service.name if service else ''}.",
                    )
                )

        # 2. Pairwise Cross-correlation: Deployment preceding subsequent telemetry
        deployments = [x for x in items if x.evidence_type == "DEPLOYMENT" or "deploy" in x.summary.lower()]
        other_events = [x for x in items if x not in deployments and x.source_type != "incident"]

        for dep in deployments:
            for ev in other_events:
                diff_sec = (ev.timestamp - dep.timestamp).total_seconds()
                if 0 <= diff_sec <= 300:
                    correlations.append(
                        EvidenceCorrelation(
                            organization_id=organization_id,
                            investigation_run_id=run_id,
                            source_evidence_id=dep.source_id,
                            target_evidence_id=ev.source_id,
                            correlation_type=CorrelationType.TEMPORAL.value,
                            strength=CorrelationStrength.STRONG.value,
                            score=0.88,
                            explanation=f"Evidence occurred {int(diff_sec)} seconds after the suspected deployment.",
                        )
                    )

        return correlations

    # ── STEP 4: HYPOTHESIS GENERATION ────────────────────────────────────────

    def _generate_candidate_causes(
        self,
        run_id: uuid.UUID,
        organization_id: uuid.UUID,
        incident: Incident,
        service: Service | None,
        items: list[NormalizedEvidenceItem],
    ) -> list[CandidateCause]:
        causes: list[CandidateCause] = []
        svc_name = service.name if service else "System"

        # Check for DEPLOYMENT
        deployments = [
            x for x in items if x.evidence_type == "DEPLOYMENT" or "deploy" in x.content_text.lower()
        ]
        if deployments:
            causes.append(
                CandidateCause(
                    id=uuid.uuid4(),
                    organization_id=organization_id,
                    investigation_run_id=run_id,
                    cause_type=CauseType.DEPLOYMENT.value,
                    title=f"Recent Deployment Regression on {svc_name}",
                    description=f"Deployment event '{deployments[0].summary}' completed shortly before incident onset.",
                    service_id=incident.service_id,
                    score=0.0,
                    status=HypothesisStatus.CANDIDATE.value,
                )
            )

        # Check for CONFIGURATION
        configs = [
            x for x in items if x.evidence_type == "CONFIG" or "config" in x.content_text.lower()
        ]
        if configs:
            causes.append(
                CandidateCause(
                    id=uuid.uuid4(),
                    organization_id=organization_id,
                    investigation_run_id=run_id,
                    cause_type=CauseType.CONFIGURATION.value,
                    title=f"Configuration Drift or Invalid Flag on {svc_name}",
                    description=f"Configuration change '{configs[0].summary}' detected in proximity to incident.",
                    service_id=incident.service_id,
                    score=0.0,
                    status=HypothesisStatus.CANDIDATE.value,
                )
            )

        # Check for DEPENDENCY_FAILURE
        dep_keywords = ["timeout", "deadline", "database", "db", "redis", "postgres", "gateway", "upstream", "connection pool"]
        dep_matches = [
            x for x in items if any(k in x.content_text.lower() for k in dep_keywords)
        ]
        if dep_matches:
            causes.append(
                CandidateCause(
                    id=uuid.uuid4(),
                    organization_id=organization_id,
                    investigation_run_id=run_id,
                    cause_type=CauseType.DEPENDENCY_FAILURE.value,
                    title=f"Upstream / Downstream Dependency Failure Affecting {svc_name}",
                    description=f"Observed timeout, connection refusal, or database latency in telemetry.",
                    service_id=incident.service_id,
                    score=0.0,
                    status=HypothesisStatus.CANDIDATE.value,
                )
            )

        # Check for SERVICE_FAILURE
        svc_keywords = ["crash", "oom", "memory", "cpu", "panic", "exception", "null pointer", "restart"]
        svc_matches = [
            x for x in items if any(k in x.content_text.lower() for k in svc_keywords)
        ]
        if svc_matches:
            causes.append(
                CandidateCause(
                    id=uuid.uuid4(),
                    organization_id=organization_id,
                    investigation_run_id=run_id,
                    cause_type=CauseType.SERVICE_FAILURE.value,
                    title=f"Internal Service Crash or Resource Exhaustion on {svc_name}",
                    description="Telemetry reports unhandled runtime exceptions or resource exhaustion.",
                    service_id=incident.service_id,
                    score=0.0,
                    status=HypothesisStatus.CANDIDATE.value,
                )
            )

        # Check for ALERT_PATTERN
        alerts = [x for x in items if x.source_type == "alert"]
        if len(alerts) >= 2:
            causes.append(
                CandidateCause(
                    id=uuid.uuid4(),
                    organization_id=organization_id,
                    investigation_run_id=run_id,
                    cause_type=CauseType.ALERT_PATTERN.value,
                    title=f"Cascading Alert Storm on {svc_name}",
                    description=f"Cluster of {len(alerts)} concurrent firing alerts observed.",
                    service_id=incident.service_id,
                    score=0.0,
                    status=HypothesisStatus.CANDIDATE.value,
                )
            )

        # Fallback / Default UNKNOWN if no specific causes found
        if not causes:
            causes.append(
                CandidateCause(
                    id=uuid.uuid4(),
                    organization_id=organization_id,
                    investigation_run_id=run_id,
                    cause_type=CauseType.UNKNOWN.value,
                    title="Undetermined Root Cause",
                    description="Available incident telemetry does not support a specific root-cause hypothesis.",
                    service_id=incident.service_id,
                    score=0.10,
                    status=HypothesisStatus.WEAKENED.value,
                )
            )

        return causes

    # ── STEP 5: HYPOTHESIS SCORING & RANKING ──────────────────────────────────

    def _score_and_rank_hypotheses(
        self,
        run_id: uuid.UUID,
        organization_id: uuid.UUID,
        incident: Incident,
        service: Service | None,
        candidate_causes: list[CandidateCause],
        items: list[NormalizedEvidenceItem],
        correlations: list[EvidenceCorrelation],
    ) -> tuple[list[InvestigationHypothesis], list[HypothesisEvidence]]:
        hypotheses: list[InvestigationHypothesis] = []
        evidence_links: list[HypothesisEvidence] = []

        for cause in candidate_causes:
            hypo_id = uuid.uuid4()

            # Determine supporting / contradicting evidence for this cause
            supporting_items: list[tuple[NormalizedEvidenceItem, float, str]] = []
            contradicting_items: list[tuple[NormalizedEvidenceItem, float, str]] = []

            for item in items:
                if cause.cause_type == CauseType.DEPLOYMENT.value:
                    if item.evidence_type == "DEPLOYMENT" or "deploy" in item.content_text.lower():
                        dt = abs((item.timestamp - incident.detected_at).total_seconds())
                        contrib = max(0.2, 1.0 - (dt / 3600.0))
                        supporting_items.append((
                            item,
                            contrib,
                            f"Deployment occurred {int(dt)}s before incident detection with high temporal proximity.",
                        ))
                    elif "healthy" in item.content_text.lower() and (item.timestamp - incident.detected_at).total_seconds() > 0:
                        contradicting_items.append((
                            item,
                            0.5,
                            "Service reported healthy status immediately after deployment.",
                        ))

                elif cause.cause_type == CauseType.CONFIGURATION.value:
                    if item.evidence_type == "CONFIG" or "config" in item.content_text.lower():
                        dt = abs((item.timestamp - incident.detected_at).total_seconds())
                        contrib = max(0.2, 1.0 - (dt / 3600.0))
                        supporting_items.append((
                            item,
                            contrib,
                            f"Configuration change observed {int(dt)}s from incident onset.",
                        ))

                elif cause.cause_type == CauseType.DEPENDENCY_FAILURE.value:
                    if any(k in item.content_text.lower() for k in ["timeout", "database", "db", "redis", "gateway", "upstream"]):
                        supporting_items.append((
                            item,
                            0.85,
                            f"Evidence records direct database or upstream dependency timeout.",
                        ))

                elif cause.cause_type == CauseType.SERVICE_FAILURE.value:
                    if any(k in item.content_text.lower() for k in ["crash", "oom", "memory", "cpu", "panic", "exception"]):
                        supporting_items.append((
                            item,
                            0.80,
                            f"Evidence shows service crash, memory exhaustion, or unhandled exception.",
                        ))

                elif cause.cause_type == CauseType.ALERT_PATTERN.value:
                    if item.source_type == "alert":
                        supporting_items.append((
                            item,
                            0.75,
                            f"Alert '{item.summary}' contributes to firing alert pattern.",
                        ))

            # ── DETERMINISTIC FORMULA ────────────────────────────────────────
            # Base score
            base_score = 0.15 if cause.cause_type != CauseType.UNKNOWN.value else 0.05

            # Temporal factor: maximum correlation score with incident onset
            related_corr = [
                c.score for c in correlations
                if any(c.source_evidence_id == x[0].source_id for x in supporting_items)
            ]
            temporal_factor = max(related_corr) if related_corr else 0.3

            # Service match factor
            service_match_factor = 1.0 if cause.service_id == incident.service_id else 0.2

            # Incident attachment factor
            incident_attachment_factor = 0.9 if supporting_items else 0.1

            # Reliability factor based on highest supporting reliability
            reliabilities = [x[0].reliability for x in supporting_items]
            if "HIGH" in reliabilities:
                reliability_factor = 1.0
            elif "MEDIUM" in reliabilities:
                reliability_factor = 0.6
            else:
                reliability_factor = 0.3

            # Supporting vs contradicting contribution
            supporting_sum = sum(x[1] for x in supporting_items)
            supporting_factor = min(1.0, supporting_sum / (len(supporting_items) or 1))
            contradicting_factor = min(1.0, sum(x[1] for x in contradicting_items))

            raw_score = (
                base_score
                + (temporal_factor * WEIGHT_TEMPORAL)
                + (service_match_factor * WEIGHT_SERVICE_MATCH)
                + (incident_attachment_factor * WEIGHT_INCIDENT_ATTACHMENT)
                + (reliability_factor * WEIGHT_RELIABILITY)
                + (supporting_factor * WEIGHT_SUPPORTING_EVIDENCE)
                - (contradicting_factor * PENALTY_CONTRADICTING)
            )
            # Clamp strictly between 0.0 and 1.0
            final_score = max(0.0, min(1.0, round(raw_score, 4)))
            confidence_band = calculate_confidence_band(final_score)

            status = (
                HypothesisStatus.SUPPORTED.value
                if final_score >= 0.60
                else (HypothesisStatus.CANDIDATE.value if final_score >= 0.30 else HypothesisStatus.WEAKENED.value)
            )

            cause.score = final_score
            cause.status = status

            hypo = InvestigationHypothesis(
                id=hypo_id,
                organization_id=organization_id,
                investigation_run_id=run_id,
                candidate_cause_id=cause.id,
                title=cause.title,
                explanation=(
                    f"Hypothesis evaluated with confidence score {final_score:.2f} ({confidence_band.value}). "
                    f"Supported by {len(supporting_items)} telemetry artifacts; "
                    f"{len(contradicting_items)} contradicting artifacts."
                ),
                confidence=confidence_band.value,
                score=final_score,
                rank=1,  # Set in ranking step below
                status=status,
            )
            hypotheses.append(hypo)

            # Record links
            for item, contrib, expl in supporting_items:
                evidence_links.append(
                    HypothesisEvidence(
                        organization_id=organization_id,
                        investigation_run_id=run_id,
                        hypothesis_id=hypo_id,
                        evidence_type=item.evidence_type,
                        evidence_id=item.source_id,
                        relationship=EvidenceRelationship.SUPPORTING.value,
                        contribution=round(contrib, 2),
                        explanation=expl,
                    )
                )

            for item, contrib, expl in contradicting_items:
                evidence_links.append(
                    HypothesisEvidence(
                        organization_id=organization_id,
                        investigation_run_id=run_id,
                        hypothesis_id=hypo_id,
                        evidence_type=item.evidence_type,
                        evidence_id=item.source_id,
                        relationship=EvidenceRelationship.CONTRADICTING.value,
                        contribution=round(-contrib, 2),
                        explanation=expl,
                    )
                )

        # Deterministic Ranking: score DESC, id ASC tie-breaker
        ranked = sorted(hypotheses, key=lambda h: (-h.score, h.id))
        for rank_idx, h in enumerate(ranked, start=1):
            h.rank = rank_idx

        return ranked, evidence_links
