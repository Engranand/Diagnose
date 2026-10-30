"""Comprehensive test suite for Milestone 9: LLM Investigation & Evidence-Grounded RCA."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.evidence import EvidenceReliability, EvidenceType, compute_evidence_hash
from diagnose.domain.investigation import (
    ConfidenceBand,
    HypothesisStatus,
    InvestigationStatus,
)
from diagnose.domain.llm import (
    AnalysisStatus,
    LLMError,
    LLMProviderUnavailableError,
    LLMTimeoutError,
    LLMValidationError,
    PROMPT_VERSION,
)
from diagnose.domain.roles import Role
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
from diagnose.llm.providers.mock import MockLLMProvider
from diagnose.llm.validator import validate_analysis
from diagnose.models.audit_log import AuditLog
from diagnose.models.evidence import Evidence
from diagnose.models.incident import Incident
from diagnose.models.investigation import InvestigationRun
from diagnose.models.investigation_analysis import InvestigationAnalysis
from diagnose.schemas.llm import HypothesisAssessment, InvestigationAnalysisOutput
from diagnose.services.investigation import InvestigationService
from diagnose.services.investigation_analysis import InvestigationAnalysisService
from tests.factories import (
    auth_headers_for,
    create_test_incident,
    create_test_organization,
    create_test_service,
    create_test_user,
)


def _build_dummy_context(
    investigation_id: uuid.UUID | None = None,
    valid_evidence_ids: list[str] | None = None,
    valid_hypothesis_ids: list[str] | None = None,
) -> InvestigationContext:
    inv_id = str(investigation_id or uuid.uuid4())
    ev_ids = valid_evidence_ids or ["ev-1", "ev-2", "ev-3"]
    hypo_ids = valid_hypothesis_ids or [str(uuid.uuid4())]

    return InvestigationContext(
        investigation_id=inv_id,
        run_number=1,
        completed_at="2026-10-31T01:00:00Z",
        incident=SanitizedIncident(
            id=str(uuid.uuid4()),
            incident_number=1,
            title="Database Connection Pool Exhaustion",
            severity="CRITICAL",
            status="RESOLVED",
            detected_at="2026-10-31T00:50:00Z",
        ),
        service=SanitizedService(
            id=str(uuid.uuid4()),
            name="checkout-api",
            slug="checkout-api",
            tier="CRITICAL",
        ),
        timeline=[
            SanitizedTimelineEvent(
                timestamp="2026-10-31T00:48:00Z",
                source_id=ev_ids[0],
                source_type="evidence",
                event_type="DEPLOYMENT",
                summary="Deploy v2.14.0",
                reliability="HIGH",
            )
        ],
        correlations=[
            SanitizedCorrelation(
                source_evidence_id=ev_ids[0],
                target_evidence_id=ev_ids[1] if len(ev_ids) > 1 else ev_ids[0],
                correlation_type="TEMPORAL",
                strength="STRONG",
                score=0.90,
                explanation="Deployment preceded failure",
            )
        ],
        candidate_causes=[
            SanitizedCandidateCause(
                id=str(uuid.uuid4()),
                cause_type="DEPLOYMENT",
                title="Recent Deployment Regression",
            )
        ],
        hypotheses=[
            SanitizedHypothesis(
                id=hypo_ids[0],
                title="Recent Deployment Regression",
                explanation="Deployment completed shortly before incident",
                confidence="HIGH",
                score=0.82,
                rank=1,
                status="SUPPORTED",
                evidence_links=[
                    SanitizedHypothesisEvidence(
                        evidence_id=ev_ids[0],
                        evidence_type="DEPLOYMENT",
                        relationship="SUPPORTING",
                        contribution=0.80,
                        explanation="Deployment observed 2m before incident",
                    )
                ],
            )
        ],
        valid_evidence_ids=ev_ids,
        valid_hypothesis_ids=hypo_ids,
    )


# ── 1. PROVIDER ABSTRACTION & MOCK TESTS ─────────────────────────────────────


@pytest.mark.asyncio
async def test_provider_abstraction_and_mock_provider() -> None:
    """Requirement 1 & 2: Provider abstraction and MockLLMProvider."""
    provider = MockLLMProvider(model_name="mock-test-model")
    assert isinstance(provider, LLMProvider)
    assert provider.provider_name == "mock"
    assert provider.model_name == "mock-test-model"
    assert await provider.health_check() is True

    context = _build_dummy_context()
    output, meta = await provider.generate_analysis(
        context=context,
        system_prompt=SYSTEM_PROMPT,
        user_prompt=build_user_prompt(context),
    )

    assert isinstance(output, InvestigationAnalysisOutput)
    assert output.summary is not None
    assert output.primary_hypothesis_id == uuid.UUID(context.hypotheses[0].id)
    assert len(output.hypothesis_assessments) == len(context.hypotheses)
    # Output must cite ONLY valid evidence IDs
    for ref in output.supporting_evidence:
        assert ref in context.valid_evidence_ids


# ── 2. CONTEXT SERIALIZATION & INPUT HASH ────────────────────────────────────


def test_deterministic_context_generation_and_input_hash() -> None:
    """Requirement 10 & 11: Context determinism and input hash reproducibility."""
    ctx1 = _build_dummy_context()
    ctx2 = _build_dummy_context(
        investigation_id=uuid.UUID(ctx1.investigation_id),
        valid_evidence_ids=list(ctx1.valid_evidence_ids),
        valid_hypothesis_ids=list(ctx1.valid_hypothesis_ids),
    )
    # Match incident and service IDs
    ctx2.incident = ctx1.incident
    ctx2.service = ctx1.service
    ctx2.timeline = ctx1.timeline
    ctx2.correlations = ctx1.correlations
    ctx2.candidate_causes = ctx1.candidate_causes
    ctx2.hypotheses = ctx1.hypotheses

    h1 = ctx1.compute_input_hash("mock", "mock-gpt-4o", PROMPT_VERSION)
    h2 = ctx2.compute_input_hash("mock", "mock-gpt-4o", PROMPT_VERSION)
    assert h1 == h2
    assert len(h1) == 64

    # Any change in context or prompt version changes hash
    h3 = ctx1.compute_input_hash("mock", "mock-gpt-4o", "m9-v2")
    assert h1 != h3


# ── 3. POST-GENERATION CLAIM & EVIDENCE VALIDATION ────────────────────────────


def test_structured_output_validation_passes_valid_refs() -> None:
    """Requirement 4: Valid evidence references and hypothesis IDs pass validation."""
    context = _build_dummy_context()
    output = InvestigationAnalysisOutput(
        summary="Clear root cause from telemetry.",
        primary_hypothesis_id=uuid.UUID(context.hypotheses[0].id),
        hypothesis_assessments=[
            HypothesisAssessment(
                hypothesis_id=uuid.UUID(context.hypotheses[0].id),
                assessment="Strongly supported",
                reasoning="Direct deployment telemetry matches timeline",
                evidence_refs=[context.valid_evidence_ids[0]],
                confidence_band=ConfidenceBand.HIGH,
            )
        ],
        key_findings=["Deployment succeeded"],
        supporting_evidence=[context.valid_evidence_ids[0]],
        contradicting_evidence=[],
        missing_evidence=[],
        next_checks=[],
        remediation_suggestions=["Roll back deployment"],
        limitations="None",
        model_metadata={},
    )
    # Should not raise
    validate_analysis(output, context)


def test_unknown_evidence_ref_rejection() -> None:
    """Requirement 5: Fabricated/unsupplied evidence ID causes validation failure."""
    context = _build_dummy_context()
    output = InvestigationAnalysisOutput(
        summary="Analysis claiming invented log.",
        primary_hypothesis_id=uuid.UUID(context.hypotheses[0].id),
        hypothesis_assessments=[],
        key_findings=[],
        supporting_evidence=["fabricated-log-event-1234"],  # NOT in context.valid_evidence_ids
        contradicting_evidence=[],
        missing_evidence=[],
        next_checks=[],
        remediation_suggestions=[],
        limitations="None",
        model_metadata={},
    )
    with pytest.raises(LLMValidationError, match="Fabricated evidence ref"):
        validate_analysis(output, context)


def test_unknown_hypothesis_id_rejection() -> None:
    """Requirement 8: Referencing a non-existent hypothesis causes validation failure."""
    context = _build_dummy_context()
    foreign_hypo_id = uuid.uuid4()
    output = InvestigationAnalysisOutput(
        summary="Analysis referencing unknown hypothesis.",
        primary_hypothesis_id=foreign_hypo_id,
        hypothesis_assessments=[],
        key_findings=[],
        supporting_evidence=[context.valid_evidence_ids[0]],
        contradicting_evidence=[],
        missing_evidence=[],
        next_checks=[],
        remediation_suggestions=[],
        limitations="None",
        model_metadata={},
    )
    with pytest.raises(LLMValidationError, match="Fabricated primary_hypothesis_id"):
        validate_analysis(output, context)


def test_output_size_limits_enforced() -> None:
    """Requirement 21: Output constraints and length limits are enforced."""
    context = _build_dummy_context()
    oversized_summary = "A" * 6000
    from pydantic import ValidationError as PydanticValidationError

    with pytest.raises((LLMValidationError, PydanticValidationError)):
        InvestigationAnalysisOutput(
            summary=oversized_summary,
            primary_hypothesis_id=uuid.UUID(context.hypotheses[0].id),
            hypothesis_assessments=[],
            key_findings=[],
            supporting_evidence=[context.valid_evidence_ids[0]],
            contradicting_evidence=[],
            missing_evidence=[],
            next_checks=[],
            remediation_suggestions=[],
            limitations="None",
            model_metadata={},
        )


# ── 4. END-TO-END PIPELINE & PERSISTENCE ──────────────────────────────────────


@pytest.mark.asyncio
async def test_end_to_end_mock_analysis_execution_and_persistence(
    db_session: AsyncSession,
) -> None:
    """Requirement 22 & 23: Complete M9 analysis flow with persistence, audit, and hash."""
    org = await create_test_organization(db_session)
    user = await create_test_user(db_session, org.id, role=Role.ENGINEER)
    service = await create_test_service(db_session, org.id, name="order-service")
    incident = await create_test_incident(db_session, org.id, service.id, title="Order Drop")

    # Add evidence artifact
    t0 = datetime(2026, 10, 31, 2, 0, 0, tzinfo=timezone.utc)
    ev = Evidence(
        id=uuid.uuid4(),
        organization_id=org.id,
        incident_id=incident.id,
        title="Deployment order-service v1.2",
        evidence_type=EvidenceType.DEPLOYMENT.value,
        source="ci",
        content="Deploy v1.2",
        observed_at=t0,
        reliability=EvidenceReliability.HIGH.value,
        structured_data={"version": "1.2"},
        evidence_hash=compute_evidence_hash(
            incident_id=incident.id,
            evidence_type=EvidenceType.DEPLOYMENT.value,
            source="ci",
            content="Deploy v1.2",
            structured_data={"version": "1.2"},
            observed_at=t0,
        ),
    )
    db_session.add(ev)
    await db_session.commit()

    # Create & execute M8 investigation
    inv_service = InvestigationService()
    run = await inv_service.create_investigation(
        db_session, org.id, incident.id, actor_user_id=user.id
    )
    executed_run = await inv_service.execute_investigation(
        db_session, org.id, run.id, actor_user_id=user.id
    )
    assert executed_run.status == InvestigationStatus.COMPLETED.value

    # Execute M9 LLM Analysis
    analysis_service = InvestigationAnalysisService()
    analysis = await analysis_service.execute_analysis(
        session=db_session,
        organization_id=org.id,
        investigation_id=run.id,
        actor_user_id=user.id,
    )

    assert analysis.status == AnalysisStatus.COMPLETED.value
    assert analysis.prompt_version == PROMPT_VERSION
    assert analysis.model_provider == "mock"
    assert analysis.summary is not None
    assert analysis.structured_output is not None
    assert len(analysis.input_hash) == 64
    assert len(analysis.output_hash or "") == 64
    assert analysis.error is None

    # Verify M8 run remained COMPLETED
    fresh_run = await inv_service.get_investigation(db_session, org.id, run.id)
    assert fresh_run.status == InvestigationStatus.COMPLETED.value


# ── 5. IDEMPOTENCY & DUPLICATE ANALYSIS AVOIDANCE ─────────────────────────────


@pytest.mark.asyncio
async def test_duplicate_completed_analysis_prevention_idempotency(
    db_session: AsyncSession,
) -> None:
    """Requirement 12: Calling analysis twice returns identical completed record."""
    org = await create_test_organization(db_session)
    user = await create_test_user(db_session, org.id, role=Role.ENGINEER)
    service = await create_test_service(db_session, org.id)
    incident = await create_test_incident(db_session, org.id, service.id)

    inv_service = InvestigationService()
    run = await inv_service.create_investigation(db_session, org.id, incident.id)
    await inv_service.execute_investigation(db_session, org.id, run.id)

    analysis_service = InvestigationAnalysisService()
    first_analysis = await analysis_service.execute_analysis(
        session=db_session,
        organization_id=org.id,
        investigation_id=run.id,
        actor_user_id=user.id,
    )

    # Second call without force_refresh returns the exact same object
    second_analysis = await analysis_service.execute_analysis(
        session=db_session,
        organization_id=org.id,
        investigation_id=run.id,
        force_refresh=False,
        actor_user_id=user.id,
    )

    assert second_analysis.id == first_analysis.id
    assert second_analysis.input_hash == first_analysis.input_hash

    # Count database records - exactly 1 must exist
    analyses, total = await analysis_service.analysis_repo.list_analyses(
        db_session, org.id, run.id
    )
    assert total == 1


# ── 6. PROVIDER FAILURE HANDLING & ERROR ISOLATION ────────────────────────────


@pytest.mark.asyncio
async def test_provider_timeout_handling(
    db_session: AsyncSession,
) -> None:
    """Requirement 13 & 16: Timeout marks analysis FAILED without modifying M8 run."""
    org = await create_test_organization(db_session)
    service = await create_test_service(db_session, org.id)
    incident = await create_test_incident(db_session, org.id, service.id)

    inv_service = InvestigationService()
    run = await inv_service.create_investigation(db_session, org.id, incident.id)
    await inv_service.execute_investigation(db_session, org.id, run.id)

    timeout_provider = MockLLMProvider(simulate_timeout=True)
    analysis_service = InvestigationAnalysisService(llm_provider=timeout_provider)

    with pytest.raises(LLMTimeoutError):
        await analysis_service.execute_analysis(
            session=db_session,
            organization_id=org.id,
            investigation_id=run.id,
        )

    # Verify analysis record was marked FAILED
    analyses, total = await analysis_service.analysis_repo.list_analyses(
        db_session, org.id, run.id
    )
    assert total == 1
    assert analyses[0].status == AnalysisStatus.FAILED.value
    assert "timeout" in (analyses[0].error or "").lower()

    # CRITICAL: M8 investigation remains COMPLETED
    fresh_run = await inv_service.get_investigation(db_session, org.id, run.id)
    assert fresh_run.status == InvestigationStatus.COMPLETED.value


@pytest.mark.asyncio
async def test_invalid_json_handling(
    db_session: AsyncSession,
) -> None:
    """Requirement 14: Invalid JSON output marks analysis FAILED."""
    org = await create_test_organization(db_session)
    service = await create_test_service(db_session, org.id)
    incident = await create_test_incident(db_session, org.id, service.id)

    inv_service = InvestigationService()
    run = await inv_service.create_investigation(db_session, org.id, incident.id)
    await inv_service.execute_investigation(db_session, org.id, run.id)

    bad_json_provider = MockLLMProvider(simulate_invalid_json=True)
    analysis_service = InvestigationAnalysisService(llm_provider=bad_json_provider)

    with pytest.raises(LLMValidationError):
        await analysis_service.execute_analysis(
            session=db_session,
            organization_id=org.id,
            investigation_id=run.id,
        )

    analyses, total = await analysis_service.analysis_repo.list_analyses(
        db_session, org.id, run.id
    )
    assert analyses[0].status == AnalysisStatus.FAILED.value


@pytest.mark.asyncio
async def test_fabricated_evidence_fails_and_marks_analysis_failed(
    db_session: AsyncSession,
) -> None:
    """Requirement 5 & 7: LLM citing nonexistent evidence ID is rejected and failed."""
    org = await create_test_organization(db_session)
    service = await create_test_service(db_session, org.id)
    incident = await create_test_incident(db_session, org.id, service.id)

    inv_service = InvestigationService()
    run = await inv_service.create_investigation(db_session, org.id, incident.id)
    await inv_service.execute_investigation(db_session, org.id, run.id)

    hallucinating_provider = MockLLMProvider(simulate_unknown_evidence_ref=True)
    analysis_service = InvestigationAnalysisService(llm_provider=hallucinating_provider)

    with pytest.raises(LLMValidationError, match="Fabricated evidence ref"):
        await analysis_service.execute_analysis(
            session=db_session,
            organization_id=org.id,
            investigation_id=run.id,
        )

    analyses, _ = await analysis_service.analysis_repo.list_analyses(
        db_session, org.id, run.id
    )
    assert analyses[0].status == AnalysisStatus.FAILED.value
    assert "Fabricated evidence ref" in (analyses[0].error or "")


# ── 7. RBAC & TENANT ISOLATION (API TESTS) ───────────────────────────────────


@pytest.mark.asyncio
async def test_rbac_and_tenant_isolation_api(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Requirement 17 & 18: RBAC checks and cross-tenant enumeration resistance (404)."""
    org_a = await create_test_organization(db_session, name="Org Alpha")
    org_b = await create_test_organization(db_session, name="Org Beta")

    admin_a = await create_test_user(db_session, org_a.id, role=Role.ADMIN)
    viewer_a = await create_test_user(db_session, org_a.id, role=Role.VIEWER)
    engineer_b = await create_test_user(db_session, org_b.id, role=Role.ENGINEER)

    service_a = await create_test_service(db_session, org_a.id)
    incident_a = await create_test_incident(db_session, org_a.id, service_a.id)

    inv_service = InvestigationService()
    run_a = await inv_service.create_investigation(db_session, org_a.id, incident_a.id)
    await inv_service.execute_investigation(db_session, org_a.id, run_a.id)

    headers_admin_a = auth_headers_for(admin_a)
    headers_viewer_a = auth_headers_for(viewer_a)
    headers_engineer_b = auth_headers_for(engineer_b)

    # 1. VIEWER cannot execute analysis -> 403 Forbidden
    resp_viewer = await client.post(
        f"/api/v1/investigations/{run_a.id}/analysis",
        headers=headers_viewer_a,
    )
    assert resp_viewer.status_code == 403

    # 2. ADMIN executes analysis -> 200 OK
    resp_admin = await client.post(
        f"/api/v1/investigations/{run_a.id}/analysis",
        headers=headers_admin_a,
    )
    assert resp_admin.status_code == 200
    analysis_data = resp_admin.json()
    analysis_id = analysis_data["id"]
    assert analysis_data["status"] == "COMPLETED"

    # 3. VIEWER can read analysis -> 200 OK
    resp_read = await client.get(
        f"/api/v1/investigations/{run_a.id}/analysis",
        headers=headers_viewer_a,
    )
    assert resp_read.status_code == 200
    assert resp_read.json()["id"] == analysis_id

    # 4. CROSS-TENANT Isolation: Org B engineer accessing Org A analysis returns 404
    resp_cross_get = await client.get(
        f"/api/v1/investigations/{run_a.id}/analysis",
        headers=headers_engineer_b,
    )
    assert resp_cross_get.status_code == 404

    resp_cross_post = await client.post(
        f"/api/v1/investigations/{run_a.id}/analysis",
        headers=headers_engineer_b,
    )
    assert resp_cross_post.status_code == 404

    resp_cross_id = await client.get(
        f"/api/v1/investigations/{run_a.id}/analysis/{analysis_id}",
        headers=headers_engineer_b,
    )
    assert resp_cross_id.status_code == 404


# ── 8. AUDIT EVENTS & SECRETS SANITIZATION ───────────────────────────────────


@pytest.mark.asyncio
async def test_audit_events_and_secret_redaction(
    db_session: AsyncSession,
) -> None:
    """Requirement 19 & 20: Audit events recorded and secrets never present in logs."""
    org = await create_test_organization(db_session)
    user = await create_test_user(db_session, org.id, role=Role.ENGINEER)
    service = await create_test_service(db_session, org.id)
    incident = await create_test_incident(db_session, org.id, service.id)

    inv_service = InvestigationService()
    run = await inv_service.create_investigation(db_session, org.id, incident.id)
    await inv_service.execute_investigation(db_session, org.id, run.id)

    analysis_service = InvestigationAnalysisService()
    analysis = await analysis_service.execute_analysis(
        session=db_session,
        organization_id=org.id,
        investigation_id=run.id,
        actor_user_id=user.id,
    )

    # Query audit logs for this analysis entity
    stmt = (
        select(AuditLog)
        .where(
            AuditLog.organization_id == org.id,
            AuditLog.entity_id == analysis.id,
        )
        .order_by(AuditLog.created_at.asc())
    )
    res = await db_session.execute(stmt)
    entries = res.scalars().all()
    actions = [e.action for e in entries]

    assert "LLM_ANALYSIS_CREATED" in actions
    assert "LLM_ANALYSIS_STARTED" in actions
    assert "LLM_ANALYSIS_COMPLETED" in actions

    # Verify no secret tokens / passwords / authorization headers in audit payloads
    forbidden = ["api_key", "password", "token", "secret", "authorization"]
    for e in entries:
        payload_str = str(e.new_values).lower()
        for f in forbidden:
            assert f not in payload_str, f"Forbidden keyword '{f}' leaked into audit payload: {payload_str}"
