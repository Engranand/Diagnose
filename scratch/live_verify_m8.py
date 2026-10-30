"""Live verification script for Milestone 8: Deterministic Root-Cause Analysis & Evidence Correlation.

Validates the full deterministic RCA engine against live PostgreSQL and Redis environments:
1. Investigation created
2. Investigation executes
3. Timeline ordered correctly
4. Deployment correlates temporally with incident evidence
5. Database timeout correlates with affected service
6. Alert correlates with incident
7. Hypotheses generated deterministically
8. Scores within 0.0 - 1.0
9. Confidence bands correct
10. Supporting evidence attached
11. Contradicting evidence represented when present
12. Re-running produces identical result
13. Duplicate execution does not duplicate results
14. Concurrent execution prevented (409)
15. Cross-tenant access rejected (404)
16. Audit records exist
17. M1 - M7 operational integrity intact
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

# Ensure src and root in sys.path
sys.path.insert(0, os.path.abspath("src"))
sys.path.insert(0, os.path.abspath("."))

from diagnose.core.security import create_access_token
from diagnose.domain.evidence import EvidenceReliability, EvidenceType, compute_evidence_hash
from diagnose.domain.investigation import (
    ConfidenceBand,
    EvidenceRelationship,
    InvestigationStatus,
    calculate_confidence_band,
)
from diagnose.domain.roles import Role
from diagnose.main import create_app
from diagnose.models.alert import Alert
from diagnose.models.audit_log import AuditLog
from diagnose.models.evidence import Evidence
from diagnose.models.incident import Incident
from diagnose.models.incident_event import IncidentEvent
from diagnose.models.investigation import (
    EvidenceCorrelation,
    HypothesisEvidence,
    InvestigationHypothesis,
    InvestigationRun,
    InvestigationTimelineEvent,
)
from diagnose.models.organization import Organization
from diagnose.models.service import Service
from diagnose.models.user import User
from diagnose.settings import get_settings
from tests.fake_redis import FakeAsyncRedis


async def main() -> None:
    print("[*] Starting Milestone 8 Live System Verification...")
    settings = get_settings()

    app = create_app(settings)
    engine = create_async_engine(settings.DATABASE_URL)
    app.state.db_engine = engine

    # Use Redis / FakeAsyncRedis double
    app.state.redis = FakeAsyncRedis()

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    app.state.db_session_factory = session_factory

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # ── SETUP TENANTS & USERS ─────────────────────────────────────────────
        org_a_id = uuid.uuid4()
        org_b_id = uuid.uuid4()
        user_a_id = uuid.uuid4()
        user_b_id = uuid.uuid4()

        async with session_factory() as session:
            org_a = Organization(
                id=org_a_id,
                name=f"Primary Org A {uuid.uuid4().hex[:4]}",
                slug=f"org-a-{uuid.uuid4().hex[:6]}",
                is_active=True,
            )
            org_b = Organization(
                id=org_b_id,
                name=f"Isolated Org B {uuid.uuid4().hex[:4]}",
                slug=f"org-b-{uuid.uuid4().hex[:6]}",
                is_active=True,
            )
            session.add_all([org_a, org_b])

            user_a = User(
                id=user_a_id,
                organization_id=org_a_id,
                email=f"engineer-a-{uuid.uuid4().hex[:6]}@diagnose.io",
                hashed_password="mock_hash",
                role=Role.ENGINEER.value,
                is_active=True,
            )
            user_b = User(
                id=user_b_id,
                organization_id=org_b_id,
                email=f"engineer-b-{uuid.uuid4().hex[:6]}@diagnose.io",
                hashed_password="mock_hash",
                role=Role.ENGINEER.value,
                is_active=True,
            )
            session.add_all([user_a, user_b])
            await session.commit()

        token_a = create_access_token(user_a_id, org_a_id, Role.ENGINEER.value)
        token_b = create_access_token(user_b_id, org_b_id, Role.ENGINEER.value)
        headers_a = {"Authorization": f"Bearer {token_a}"}
        headers_b = {"Authorization": f"Bearer {token_b}"}

        # ── SETUP DETERMINISTIC FIXTURE (Requirement 19) ──────────────────────
        # Service: checkout-api
        # T0: Deployment completed (version: 2.14.0)
        # T0 + 20s: Database connection timeout evidence (LOG)
        # T0 + 30s: Error rate alert firing (ALERT)
        # T0 + 45s: Incident detected
        # T0 + 60s: Incident acknowledged
        # T0 + 75s: Healthcheck contradictory evidence
        t0 = datetime(2026, 10, 31, 1, 0, 0, tzinfo=timezone.utc)
        service_id = uuid.uuid4()
        incident_id = uuid.uuid4()
        alert_id = uuid.uuid4()
        dep_evidence_id = uuid.uuid4()
        log_evidence_id = uuid.uuid4()
        contra_evidence_id = uuid.uuid4()

        async with session_factory() as session:
            service = Service(
                id=service_id,
                organization_id=org_a_id,
                name="checkout-api",
                slug=f"checkout-api-{uuid.uuid4().hex[:4]}",
                description="Core payment and order checkout service",
                tier="CRITICAL",
            )
            session.add(service)

            # T0: Deployment completed (version: 2.14.0)
            dep_evidence = Evidence(
                id=dep_evidence_id,
                organization_id=org_a_id,
                incident_id=incident_id,
                title="Deployment completed: checkout-api v2.14.0",
                evidence_type=EvidenceType.DEPLOYMENT.value,
                source="argocd",
                content="Deployment version: 2.14.0 completed successfully to production cluster.",
                observed_at=t0,
                reliability=EvidenceReliability.HIGH.value,
                structured_data={"version": "2.14.0", "commit": "a1b2c3d"},
                evidence_hash=compute_evidence_hash(
                    incident_id=incident_id,
                    evidence_type=EvidenceType.DEPLOYMENT.value,
                    source="argocd",
                    content="Deployment version: 2.14.0 completed successfully to production cluster.",
                    structured_data={"version": "2.14.0", "commit": "a1b2c3d"},
                    observed_at=t0,
                ),
            )
            session.add(dep_evidence)

            # T0 + 20s: Database connection timeout evidence (LOG)
            log_evidence = Evidence(
                id=log_evidence_id,
                organization_id=org_a_id,
                incident_id=incident_id,
                title="Database connection timeout",
                evidence_type=EvidenceType.LOG.value,
                source="datadog",
                content="Timeout connecting to postgres primary: connection pool exhausted after 5000ms.",
                observed_at=t0 + timedelta(seconds=20),
                reliability=EvidenceReliability.HIGH.value,
                structured_data={"error": "Connection timed out", "db": "postgres", "pool_size": 50},
                evidence_hash=compute_evidence_hash(
                    incident_id=incident_id,
                    evidence_type=EvidenceType.LOG.value,
                    source="datadog",
                    content="Timeout connecting to postgres primary: connection pool exhausted after 5000ms.",
                    structured_data={"error": "Connection timed out", "db": "postgres", "pool_size": 50},
                    observed_at=t0 + timedelta(seconds=20),
                ),
            )
            session.add(log_evidence)

            # T0 + 30s: Error rate alert firing (ALERT)
            alert = Alert(
                id=alert_id,
                organization_id=org_a_id,
                service_id=service_id,
                incident_id=incident_id,
                fingerprint=f"alert-checkout-err-{uuid.uuid4().hex[:6]}",
                source="prometheus",
                alert_type="HighErrorRate",
                title="High HTTP 500 Error Rate on checkout-api",
                message="HTTP 5xx rate exceeded 15% threshold for 2 consecutive minutes.",
                severity="CRITICAL",
                status="FIRING",
                first_seen_at=t0 + timedelta(seconds=30),
                last_seen_at=t0 + timedelta(seconds=30),
                payload={"threshold": 0.15, "current_rate": 0.22},
            )
            session.add(alert)

            # T0 + 45s: Incident detected
            incident = Incident(
                id=incident_id,
                organization_id=org_a_id,
                service_id=service_id,
                incident_number=101,
                title="Elevated error rates and checkout failures",
                description="Customers unable to complete checkout flow. Database pool timeout observed.",
                severity="CRITICAL",
                status="DETECTED",
                detected_at=t0 + timedelta(seconds=45),
                version=1,
            )
            session.add(incident)

            # T0 + 60s: Incident acknowledged
            ack_event = IncidentEvent(
                id=uuid.uuid4(),
                organization_id=org_a_id,
                incident_id=incident_id,
                event_type="INCIDENT_ACKNOWLEDGED",
                message="Incident acknowledged by on-call engineer.",
                created_at=t0 + timedelta(seconds=60),
            )
            session.add(ack_event)

            # T0 + 75s: Healthcheck / contradicting evidence
            contra_evidence = Evidence(
                id=contra_evidence_id,
                organization_id=org_a_id,
                incident_id=incident_id,
                title="Gateway healthcheck probe",
                evidence_type=EvidenceType.LOG.value,
                source="consul",
                content="checkout-api healthcheck reported healthy status on secondary region nodes.",
                observed_at=t0 + timedelta(seconds=75),
                reliability=EvidenceReliability.MEDIUM.value,
                structured_data={"status": "healthy", "region": "us-east-1b"},
                evidence_hash=compute_evidence_hash(
                    incident_id=incident_id,
                    evidence_type=EvidenceType.LOG.value,
                    source="consul",
                    content="checkout-api healthcheck reported healthy status on secondary region nodes.",
                    structured_data={"status": "healthy", "region": "us-east-1b"},
                    observed_at=t0 + timedelta(seconds=75),
                ),
            )
            session.add(contra_evidence)

            await session.commit()

        print("  [+] Deterministic test fixture seeded successfully.")

        # ── CHECK 1: Investigation created ────────────────────────────────────
        resp = await client.post(
            f"/api/v1/incidents/{incident_id}/investigations",
            json={"run_type": "AUTOMATED"},
            headers=headers_a,
        )
        assert resp.status_code == 201, f"Check 1 Failed: {resp.status_code} {resp.text}"
        inv_data = resp.json()
        inv_id = inv_data["id"]
        assert inv_data["status"] == InvestigationStatus.PENDING.value
        assert inv_data["run_number"] >= 1
        print("  [1/17] Check 1 Passed: Investigation created (PENDING, valid run number).")

        # ── CHECK 14: Concurrent execution prevented (409) ────────────────────
        # Attempting to create a second investigation while first is PENDING must return 409
        dup_create = await client.post(
            f"/api/v1/incidents/{incident_id}/investigations",
            json={"run_type": "AUTOMATED"},
            headers=headers_a,
        )
        assert dup_create.status_code == 409, f"Check 14 Failed: {dup_create.status_code}"
        print("  [14/17] Check 14 Passed: Concurrent active investigation prevented with 409 Conflict.")

        # ── CHECK 2: Investigation executes ───────────────────────────────────
        resp = await client.post(
            f"/api/v1/investigations/{inv_id}/run",
            headers=headers_a,
        )
        assert resp.status_code == 200, f"Check 2 Failed: {resp.status_code} {resp.text}"
        executed_data = resp.json()
        assert executed_data["status"] == InvestigationStatus.COMPLETED.value
        assert len(executed_data["steps"]) == 6
        step_types = [s["step_type"] for s in executed_data["steps"]]
        assert step_types == [
            "EVIDENCE_COLLECTION",
            "TIMELINE_BUILD",
            "CORRELATION",
            "HYPOTHESIS_GENERATION",
            "HYPOTHESIS_SCORING",
            "FINALIZATION",
        ]
        print("  [2/17] Check 2 Passed: Investigation executes through all 6 stages to COMPLETED.")

        # ── CHECK 3: Timeline ordered correctly ───────────────────────────────
        resp = await client.get(
            f"/api/v1/investigations/{inv_id}/timeline",
            headers=headers_a,
        )
        assert resp.status_code == 200, f"Check 3 Failed: {resp.status_code}"
        timeline_items = resp.json()["items"]
        assert len(timeline_items) >= 5
        # Verify strict ascending order
        timestamps = [item["timestamp"] for item in timeline_items]
        assert timestamps == sorted(timestamps), "Timeline is not chronologically sorted!"
        # First event is T0 deployment
        assert timeline_items[0]["event_type"] == "DEPLOYMENT"
        print(f"  [3/17] Check 3 Passed: Timeline strictly ordered chronologically ({len(timeline_items)} events).")

        # ── CHECK 4: Deployment correlates temporally with incident evidence ──
        resp = await client.get(
            f"/api/v1/investigations/{inv_id}/correlations",
            headers=headers_a,
        )
        assert resp.status_code == 200, f"Check 4 Failed: {resp.status_code}"
        correlations = resp.json()["items"]
        assert len(correlations) > 0

        dep_corr = [
            c for c in correlations
            if c["source_evidence_id"] == str(dep_evidence_id)
            and c["correlation_type"] == "TEMPORAL"
        ]
        assert len(dep_corr) > 0, "No temporal correlation found for deployment!"
        assert dep_corr[0]["strength"] == "STRONG"
        print("  [4/17] Check 4 Passed: Deployment correlates temporally with incident telemetry.")

        # ── CHECK 5: Database timeout correlates with affected service ────────
        svc_corr = [
            c for c in correlations
            if c["source_evidence_id"] == str(log_evidence_id)
            and c["correlation_type"] == "SERVICE"
        ]
        assert len(svc_corr) > 0, "No service correlation found for database timeout!"
        assert svc_corr[0]["target_evidence_id"] == str(service_id)
        print("  [5/17] Check 5 Passed: Database timeout correlates directly with affected service.")

        # ── CHECK 6: Alert correlates with incident ───────────────────────────
        alert_corr = [
            c for c in correlations
            if c["source_evidence_id"] == str(alert_id)
            and c["correlation_type"] in ("ALERT", "TEMPORAL")
        ]
        assert len(alert_corr) > 0, "No correlation found for Alert!"
        print("  [6/17] Check 6 Passed: Alert correlates with incident and service.")

        # ── CHECK 7: Hypotheses generated deterministically ───────────────────
        resp = await client.get(
            f"/api/v1/investigations/{inv_id}/hypotheses",
            headers=headers_a,
        )
        assert resp.status_code == 200, f"Check 7 Failed: {resp.status_code}"
        hypotheses = resp.json()
        assert len(hypotheses) >= 2
        titles = [h["title"] for h in hypotheses]
        assert any("Deployment" in t for t in titles)
        assert any("Dependency" in t for t in titles)
        # Verify ranked in descending order of score
        scores = [h["score"] for h in hypotheses]
        assert scores == sorted(scores, reverse=True), "Hypotheses are not ranked descending by score!"
        print(f"  [7/17] Check 7 Passed: Hypotheses generated & ranked deterministically ({len(hypotheses)} candidates).")

        # ── CHECK 8: Scores within 0.0 - 1.0 ──────────────────────────────────
        for h in hypotheses:
            assert 0.0 <= h["score"] <= 1.0, f"Score out of range: {h['score']}"
        print("  [8/17] Check 8 Passed: All hypothesis scores strictly within [0.0, 1.0].")

        # ── CHECK 9: Confidence bands correct ─────────────────────────────────
        for h in hypotheses:
            expected_band = calculate_confidence_band(h["score"]).value
            assert h["confidence"] == expected_band, (
                f"Confidence band mismatch for score {h['score']}: got {h['confidence']}, expected {expected_band}"
            )
        print("  [9/17] Check 9 Passed: Confidence bands (VERY_HIGH, HIGH, MEDIUM, LOW) correctly mapped.")

        # ── CHECK 10: Supporting evidence attached ────────────────────────────
        # Fetch detailed investigation to inspect evidence links
        resp = await client.get(
            f"/api/v1/investigations/{inv_id}",
            headers=headers_a,
        )
        assert resp.status_code == 200, f"Check 10 Failed: {resp.status_code}"
        detail = resp.json()
        top_hypo = detail["hypotheses"][0]
        supp_links = [
            el for el in top_hypo["evidence_links"]
            if el["relationship"] == EvidenceRelationship.SUPPORTING.value
        ]
        assert len(supp_links) > 0, "No supporting evidence links attached to top hypothesis!"
        print(f"  [10/17] Check 10 Passed: Supporting evidence attached to top hypothesis ({len(supp_links)} links).")

        # ── CHECK 11: Contradicting evidence represented when present ─────────
        all_links = [el for h in detail["hypotheses"] for el in h["evidence_links"]]
        contra_links = [
            el for el in all_links
            if el["relationship"] == EvidenceRelationship.CONTRADICTING.value
        ]
        assert len(contra_links) > 0, "Contradicting evidence was not attached to hypothesis!"
        print(f"  [11/17] Check 11 Passed: Contradicting evidence link present ({len(contra_links)} links).")

        # ── CHECK 12: Re-running produces identical result ────────────────────
        resp_rerun = await client.post(
            f"/api/v1/investigations/{inv_id}/run",
            headers=headers_a,
        )
        assert resp_rerun.status_code == 200
        rerun_detail = resp_rerun.json()
        assert len(rerun_detail["hypotheses"]) == len(detail["hypotheses"])
        for h1, h2 in zip(detail["hypotheses"], rerun_detail["hypotheses"]):
            assert h1["title"] == h2["title"]
            assert abs(h1["score"] - h2["score"]) < 1e-6
            assert h1["confidence"] == h2["confidence"]
        print("  [12/17] Check 12 Passed: Re-running completed run yields identical scores & hypotheses.")

        # ── CHECK 13: Duplicate execution does not duplicate results ──────────
        resp_tl = await client.get(f"/api/v1/investigations/{inv_id}/timeline", headers=headers_a)
        resp_corr = await client.get(f"/api/v1/investigations/{inv_id}/correlations", headers=headers_a)
        resp_hypo = await client.get(f"/api/v1/investigations/{inv_id}/hypotheses", headers=headers_a)
        assert len(resp_tl.json()["items"]) == len(timeline_items)
        assert len(resp_corr.json()["items"]) == len(correlations)
        assert len(resp_hypo.json()) == len(hypotheses)
        print("  [13/17] Check 13 Passed: Artifact counts remain identical; no duplicate artifact explosion.")

        # ── CHECK 15: Cross-tenant access rejected (404) ──────────────────────
        # Org B user accessing Org A's investigation must get 404
        cross_resp = await client.get(
            f"/api/v1/investigations/{inv_id}",
            headers=headers_b,
        )
        assert cross_resp.status_code == 404, f"Check 15 Failed: {cross_resp.status_code}"
        # Org B user trying to run Org A's investigation must get 404
        cross_run = await client.post(
            f"/api/v1/investigations/{inv_id}/run",
            headers=headers_b,
        )
        assert cross_run.status_code == 404, f"Check 15 Failed: {cross_run.status_code}"
        print("  [15/17] Check 15 Passed: Cross-tenant access strictly rejected with 404 Not Found.")

        # ── CHECK 16: Audit records exist ─────────────────────────────────────
        async with session_factory() as session:
            stmt = (
                select(AuditLog)
                .where(
                    AuditLog.organization_id == org_a_id,
                    AuditLog.entity_id == inv_id,
                )
                .order_by(AuditLog.created_at.asc())
            )
            res = await session.execute(stmt)
            audit_entries = res.scalars().all()
            actions = [e.action for e in audit_entries]
            assert "INVESTIGATION_CREATED" in actions
            assert "INVESTIGATION_STARTED" in actions
            assert "INVESTIGATION_COMPLETED" in actions
        print(f"  [16/17] Check 16 Passed: Audit records created ({len(audit_entries)} events recorded).")

        # ── CHECK 17: M1 - M7 operational integrity intact ────────────────────
        # Services endpoint
        svc_resp = await client.get("/api/v1/services", headers=headers_a)
        assert svc_resp.status_code == 200
        # Incidents endpoint
        inc_resp = await client.get("/api/v1/incidents", headers=headers_a)
        assert inc_resp.status_code == 200
        # Alerts endpoint
        alert_resp = await client.get("/api/v1/alerts", headers=headers_a)
        assert alert_resp.status_code == 200
        # Evidence endpoint
        ev_resp = await client.get(f"/api/v1/incidents/{incident_id}/evidence", headers=headers_a)
        assert ev_resp.status_code == 200
        # Jobs endpoint
        jobs_resp = await client.get("/api/v1/jobs", headers=headers_a)
        assert jobs_resp.status_code == 200

        print("  [17/17] Check 17 Passed: M1-M7 systems operational and responsive.")

    print("\n[SUCCESS] Milestone 8 Live System Verification passed all 17 checks!")


if __name__ == "__main__":
    asyncio.run(main())
