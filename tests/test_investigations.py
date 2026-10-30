"""Comprehensive test suite for Milestone 8: Deterministic Root-Cause Analysis & Evidence Correlation."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.alerts import AlertSeverity, AlertStatus
from diagnose.domain.evidence import EvidenceReliability, EvidenceType
from diagnose.domain.investigation import (
    ConfidenceBand,
    CorrelationStrength,
    CorrelationType,
    EvidenceRelationship,
    HypothesisStatus,
    InvestigationStatus,
    InvestigationStepType,
    calculate_confidence_band,
)
from diagnose.domain.roles import Role
from diagnose.models.alert import Alert
from diagnose.models.evidence import Evidence
from diagnose.models.incident import Incident
from diagnose.models.incident_event import IncidentEvent
from diagnose.models.investigation import InvestigationRun
from diagnose.services.investigation import InvestigationService, NormalizedEvidenceItem
from tests.factories import (
    auth_headers_for,
    create_test_incident,
    create_test_organization,
    create_test_service,
    create_test_user,
)


# ── 1. DOMAIN TESTS ──────────────────────────────────────────────────────────


def test_confidence_bands_mapping() -> None:
    """Requirement 11: Score mapping to deterministic confidence bands."""
    assert calculate_confidence_band(0.00) == ConfidenceBand.LOW
    assert calculate_confidence_band(0.29) == ConfidenceBand.LOW
    assert calculate_confidence_band(0.30) == ConfidenceBand.MEDIUM
    assert calculate_confidence_band(0.59) == ConfidenceBand.MEDIUM
    assert calculate_confidence_band(0.60) == ConfidenceBand.HIGH
    assert calculate_confidence_band(0.79) == ConfidenceBand.HIGH
    assert calculate_confidence_band(0.80) == ConfidenceBand.VERY_HIGH
    assert calculate_confidence_band(1.00) == ConfidenceBand.VERY_HIGH


# ── 2. EVIDENCE COLLECTION & TIMELINE ORDERING ────────────────────────────────


@pytest.mark.asyncio
async def test_timeline_ordering_and_deterministic_tie_breaking(
    db_session: AsyncSession,
) -> None:
    """Requirement 4: Timeline sorts strictly by timestamp ASC, source_id ASC tie-breaker."""
    service = InvestigationService()
    run_id = uuid.uuid4()
    org_id = uuid.uuid4()

    t0 = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(seconds=10)

    # Intentionally out-of-order items with tie at t1
    items = [
        NormalizedEvidenceItem(
            source_type="evidence",
            source_id="id-z-later",
            timestamp=t1,
            service_id=None,
            summary="Item Z",
            reliability="HIGH",
            evidence_type="LOG",
            content_text="Z",
            metadata={},
        ),
        NormalizedEvidenceItem(
            source_type="evidence",
            source_id="id-a-earlier",
            timestamp=t0,
            service_id=None,
            summary="Item A",
            reliability="HIGH",
            evidence_type="DEPLOYMENT",
            content_text="A",
            metadata={},
        ),
        NormalizedEvidenceItem(
            source_type="evidence",
            source_id="id-b-tie",
            timestamp=t1,
            service_id=None,
            summary="Item B",
            reliability="HIGH",
            evidence_type="ALERT",
            content_text="B",
            metadata={},
        ),
    ]

    timeline = service._build_normalized_timeline(run_id, org_id, items)

    assert len(timeline) == 3
    # 1st: t0 (id-a-earlier)
    assert timeline[0].source_id == "id-a-earlier"
    assert timeline[0].timestamp == t0
    # 2nd: t1 tie-breaker id-b-tie < id-z-later
    assert timeline[1].source_id == "id-b-tie"
    assert timeline[1].timestamp == t1
    # 3rd: t1 id-z-later
    assert timeline[2].source_id == "id-z-later"
    assert timeline[2].timestamp == t1


# ── 3. FULL INVESTIGATION EXECUTION & CORRELATION ────────────────────────────


@pytest.mark.asyncio
async def test_full_deterministic_investigation_execution(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requirements 1–12: Complete execution reproducing correlations, hypotheses, scores, and timeline."""
    org = await create_test_organization(db_session, name="RCA Org")
    user = await create_test_user(db_session, org.id, role=Role.ADMIN)
    svc = await create_test_service(db_session, org.id, name="Checkout API", slug="checkout-api")

    now = datetime(2026, 10, 31, 14, 0, 0, tzinfo=timezone.utc)

    # 1. Deployment evidence at T0
    t0_dep = now
    ev_dep = Evidence(
        id=uuid.uuid4(),
        organization_id=org.id,
        incident_id=uuid.uuid4(),  # placeholder, set after incident creation
        evidence_type=EvidenceType.DEPLOYMENT.value,
        source="ci/cd",
        title="Production release v2.4.1",
        content="Deployment of release v2.4.1 completed successfully to checkout-api",
        evidence_hash=uuid.uuid4().hex,
        observed_at=t0_dep,
        reliability=EvidenceReliability.HIGH.value,
    )

    # 2. Database timeout evidence at T0 + 20s
    t1_db = t0_dep + timedelta(seconds=20)
    ev_db = Evidence(
        id=uuid.uuid4(),
        organization_id=org.id,
        incident_id=uuid.uuid4(),
        evidence_type=EvidenceType.LOG.value,
        source="datadog",
        title="Database Connection Pool Exhausted",
        content="Database connection timeout: pool exhausted on postgres upstream dependency",
        evidence_hash=uuid.uuid4().hex,
        observed_at=t1_db,
        reliability=EvidenceReliability.HIGH.value,
    )

    # 3. Incident created at T0 + 45s
    t_inc = t0_dep + timedelta(seconds=45)
    inc = Incident(
        id=uuid.uuid4(),
        organization_id=org.id,
        service_id=svc.id,
        incident_number=101,
        title="High Error Rate on Checkout API",
        description="Checkout API error rate exceeded 15% threshold",
        severity="CRITICAL",
        status="INVESTIGATING",
        detected_at=t_inc,
    )
    db_session.add(inc)
    await db_session.flush()

    # Link evidence to this incident
    ev_dep.incident_id = inc.id
    ev_db.incident_id = inc.id
    db_session.add_all([ev_dep, ev_db])

    # 4. Error alert at T0 + 30s
    t2_alert = t0_dep + timedelta(seconds=30)
    alert = Alert(
        id=uuid.uuid4(),
        organization_id=org.id,
        service_id=svc.id,
        incident_id=inc.id,
        fingerprint=f"alert-500-{uuid.uuid4().hex[:6]}",
        source="prometheus",
        alert_type="http_5xx",
        title="HTTP 500 Spike on Checkout API",
        message="5xx rate at 22% on /checkout endpoint",
        severity=AlertSeverity.CRITICAL.value,
        status=AlertStatus.FIRING.value,
        first_seen_at=t2_alert,
        last_seen_at=t2_alert,
    )
    db_session.add(alert)

    # 5. Incident event at T0 + 60s
    ie = IncidentEvent(
        id=uuid.uuid4(),
        organization_id=org.id,
        incident_id=inc.id,
        event_type="INCIDENT_ACKNOWLEDGED",
        message="On-call engineer acknowledged incident",
        created_at=t0_dep + timedelta(seconds=60),
    )
    db_session.add(ie)
    await db_session.commit()

    headers = auth_headers_for(user)

    # ── CREATE INVESTIGATION ─────────────────────────────────────────────────
    resp_create = await client.post(
        f"/api/v1/incidents/{inc.id}/investigations",
        headers=headers,
    )
    assert resp_create.status_code == 201
    run_data = resp_create.json()
    assert run_data["status"] == "PENDING"
    assert run_data["run_number"] == 1
    run_id = run_data["id"]

    # ── EXECUTE INVESTIGATION ────────────────────────────────────────────────
    resp_run = await client.post(
        f"/api/v1/investigations/{run_id}/run",
        headers=headers,
    )
    assert resp_run.status_code == 200
    run_detail = resp_run.json()
    assert run_detail["status"] == "COMPLETED"
    assert run_detail["started_at"] is not None
    assert run_detail["completed_at"] is not None

    # Verify executed steps
    steps = run_detail["steps"]
    assert len(steps) == 6
    step_types = [s["step_type"] for s in steps]
    assert step_types == [
        "EVIDENCE_COLLECTION",
        "TIMELINE_BUILD",
        "CORRELATION",
        "HYPOTHESIS_GENERATION",
        "HYPOTHESIS_SCORING",
        "FINALIZATION",
    ]
    for s in steps:
        assert s["status"] == "COMPLETED"

    # ── TIMELINE ENDPOINT ────────────────────────────────────────────────────
    resp_timeline = await client.get(
        f"/api/v1/investigations/{run_id}/timeline",
        headers=headers,
    )
    assert resp_timeline.status_code == 200
    timeline = resp_timeline.json()["items"]
    assert len(timeline) >= 4
    # Chronological verification
    for i in range(len(timeline) - 1):
        assert timeline[i]["timestamp"] <= timeline[i + 1]["timestamp"]

    # First event should be the deployment
    assert timeline[0]["event_type"] == "DEPLOYMENT"

    # ── CORRELATIONS ENDPOINT ────────────────────────────────────────────────
    resp_corr = await client.get(
        f"/api/v1/investigations/{run_id}/correlations",
        headers=headers,
    )
    assert resp_corr.status_code == 200
    correlations = resp_corr.json()["items"]
    assert len(correlations) > 0
    # Must contain strong temporal and service correlations
    assert any(c["correlation_type"] == "TEMPORAL" and c["strength"] == "STRONG" for c in correlations)
    assert any(c["correlation_type"] == "SERVICE" and c["strength"] == "STRONG" for c in correlations)
    # Check explanation is present
    for c in correlations:
        assert len(c["explanation"]) > 0
        assert 0.0 <= c["score"] <= 1.0

    # ── HYPOTHESES ENDPOINT ──────────────────────────────────────────────────
    resp_hypo = await client.get(
        f"/api/v1/investigations/{run_id}/hypotheses",
        headers=headers,
    )
    assert resp_hypo.status_code == 200
    hypotheses = resp_hypo.json()
    assert len(hypotheses) >= 2

    # Verify ranking and scores
    for idx, h in enumerate(hypotheses):
        assert h["rank"] == idx + 1
        assert 0.0 <= h["score"] <= 1.0
        assert h["confidence"] in ["LOW", "MEDIUM", "HIGH", "VERY_HIGH"]
        assert len(h["evidence_links"]) > 0

    top_hypo = hypotheses[0]
    # Deployment regression should rank high due to proximity
    assert "Deployment" in top_hypo["title"] or "Dependency" in top_hypo["title"]
    assert top_hypo["status"] in ["SUPPORTED", "CANDIDATE"]

    # Supporting evidence links should have positive contribution
    sup_links = [l for l in top_hypo["evidence_links"] if l["relationship"] == "SUPPORTING"]
    assert len(sup_links) > 0
    for l in sup_links:
        assert l["contribution"] > 0
        assert len(l["explanation"]) > 0


# ── 4. CONCURRENCY & IDEMPOTENCY ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_duplicate_active_investigation_prevention(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requirement 13: Two active investigations for the same incident cannot run concurrently."""
    org = await create_test_organization(db_session)
    user = await create_test_user(db_session, org.id, role=Role.ADMIN)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)

    headers = auth_headers_for(user)

    # Create 1st run
    r1 = await client.post(f"/api/v1/incidents/{inc.id}/investigations", headers=headers)
    assert r1.status_code == 201

    # Attempt to create 2nd run while 1st is still PENDING -> 409 Conflict
    r2 = await client.post(f"/api/v1/incidents/{inc.id}/investigations", headers=headers)
    assert r2.status_code == 409
    assert r2.json()["error"]["code"] == "CONFLICT"
    assert "already in progress" in r2.json()["error"]["message"]


@pytest.mark.asyncio
async def test_repeated_execution_idempotency(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requirement 13: Re-running a completed investigation does not duplicate artifacts."""
    org = await create_test_organization(db_session)
    user = await create_test_user(db_session, org.id, role=Role.ADMIN)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)

    headers = auth_headers_for(user)

    # Create & Run
    r_create = await client.post(f"/api/v1/incidents/{inc.id}/investigations", headers=headers)
    run_id = r_create.json()["id"]
    r_run1 = await client.post(f"/api/v1/investigations/{run_id}/run", headers=headers)
    assert r_run1.status_code == 200

    # Fetch counts
    t1 = (await client.get(f"/api/v1/investigations/{run_id}/timeline", headers=headers)).json()["total"]
    c1 = (await client.get(f"/api/v1/investigations/{run_id}/correlations", headers=headers)).json()["total"]
    h1 = len((await client.get(f"/api/v1/investigations/{run_id}/hypotheses", headers=headers)).json())

    # Execute again (idempotent call on completed run)
    r_run2 = await client.post(f"/api/v1/investigations/{run_id}/run", headers=headers)
    assert r_run2.status_code == 200

    # Ensure artifact counts are identical (no duplicate rows)
    t2 = (await client.get(f"/api/v1/investigations/{run_id}/timeline", headers=headers)).json()["total"]
    c2 = (await client.get(f"/api/v1/investigations/{run_id}/correlations", headers=headers)).json()["total"]
    h2 = len((await client.get(f"/api/v1/investigations/{run_id}/hypotheses", headers=headers)).json())

    assert t1 == t2
    assert c1 == c2
    assert h1 == h2


# ── 5. TENANT ISOLATION ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cross_tenant_investigation_isolation(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requirement 17: Tenant A cannot create or access Tenant B's investigation artifacts."""
    org_a = await create_test_organization(db_session, name="Tenant A")
    org_b = await create_test_organization(db_session, name="Tenant B")

    user_a = await create_test_user(db_session, org_a.id, role=Role.ADMIN)
    user_b = await create_test_user(db_session, org_b.id, role=Role.ADMIN)

    svc_b = await create_test_service(db_session, org_b.id)
    inc_b = await create_test_incident(db_session, org_b.id, svc_b.id)

    headers_a = auth_headers_for(user_a)
    headers_b = auth_headers_for(user_b)

    # 1. Tenant A attempts to create investigation on Tenant B's incident -> 404
    r_foreign_create = await client.post(
        f"/api/v1/incidents/{inc_b.id}/investigations",
        headers=headers_a,
    )
    assert r_foreign_create.status_code == 404
    assert r_foreign_create.json()["error"]["code"] == "NOT_FOUND"

    # Tenant B creates and runs investigation
    r_b_create = await client.post(
        f"/api/v1/incidents/{inc_b.id}/investigations",
        headers=headers_b,
    )
    assert r_b_create.status_code == 201
    run_b_id = r_b_create.json()["id"]

    await client.post(f"/api/v1/investigations/{run_b_id}/run", headers=headers_b)

    # 2. Tenant A attempts to view Tenant B's investigation -> 404
    r_get = await client.get(f"/api/v1/investigations/{run_b_id}", headers=headers_a)
    assert r_get.status_code == 404
    assert r_get.json()["error"]["code"] == "NOT_FOUND"

    # 3. Tenant A attempts to view Tenant B's timeline -> 404
    r_time = await client.get(f"/api/v1/investigations/{run_b_id}/timeline", headers=headers_a)
    assert r_time.status_code == 404
    assert r_time.json()["error"]["code"] == "NOT_FOUND"

    # 4. Tenant A attempts to view Tenant B's correlations -> 404
    r_corr = await client.get(f"/api/v1/investigations/{run_b_id}/correlations", headers=headers_a)
    assert r_corr.status_code == 404
    assert r_corr.json()["error"]["code"] == "NOT_FOUND"

    # 5. Tenant A attempts to view Tenant B's hypotheses -> 404
    r_hypo = await client.get(f"/api/v1/investigations/{run_b_id}/hypotheses", headers=headers_a)
    assert r_hypo.status_code == 404
    assert r_hypo.json()["error"]["code"] == "NOT_FOUND"


# ── 6. ROLE-BASED ACCESS CONTROL (RBAC) ──────────────────────────────────────


@pytest.mark.asyncio
async def test_investigation_rbac_permissions(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requirement 14: ADMIN/ENGINEER/RESPONDER can create/run; VIEWER can only view."""
    org = await create_test_organization(db_session)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)
    engineer = await create_test_user(db_session, org.id, role=Role.ENGINEER)
    responder = await create_test_user(db_session, org.id, role=Role.RESPONDER)
    viewer = await create_test_user(db_session, org.id, role=Role.VIEWER)

    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)

    # 1. VIEWER cannot create investigation -> 403
    r_v_create = await client.post(
        f"/api/v1/incidents/{inc.id}/investigations",
        headers=auth_headers_for(viewer),
    )
    assert r_v_create.status_code == 403
    assert r_v_create.json()["error"]["code"] == "FORBIDDEN"

    # 2. RESPONDER can create investigation -> 201
    r_resp_create = await client.post(
        f"/api/v1/incidents/{inc.id}/investigations",
        headers=auth_headers_for(responder),
    )
    assert r_resp_create.status_code == 201
    run_id = r_resp_create.json()["id"]

    # 3. VIEWER cannot execute investigation -> 403
    r_v_run = await client.post(
        f"/api/v1/investigations/{run_id}/run",
        headers=auth_headers_for(viewer),
    )
    assert r_v_run.status_code == 403

    # 4. ENGINEER can execute investigation -> 200
    r_eng_run = await client.post(
        f"/api/v1/investigations/{run_id}/run",
        headers=auth_headers_for(engineer),
    )
    assert r_eng_run.status_code == 200

    # 5. VIEWER can read investigation results -> 200
    r_v_view = await client.get(
        f"/api/v1/investigations/{run_id}",
        headers=auth_headers_for(viewer),
    )
    assert r_v_view.status_code == 200
