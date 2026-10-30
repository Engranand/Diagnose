"""Tests for Alert entity, idempotent ingestion, lifecycle, and incident association."""

from __future__ import annotations

import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.roles import Role
from diagnose.models.alert import Alert
from diagnose.models.audit_log import AuditLog
from tests.factories import (
    auth_headers_for,
    create_test_alert,
    create_test_incident,
    create_test_organization,
    create_test_service,
    create_test_user,
)


@pytest.mark.asyncio
async def test_admin_can_create_alert(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """ADMIN role can successfully ingest an alert."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    payload = {
        "service_id": str(svc.id),
        "fingerprint": f"fp-admin-{uuid.uuid4().hex[:6]}",
        "source": "prometheus",
        "alert_type": "high_error_rate",
        "title": "5xx error rate exceeded 5%",
        "message": "Elevated 500 responses detected on checkout",
        "severity": "CRITICAL",
        "payload": {"rate": 0.058, "threshold": 0.05},
    }
    response = await client.post(
        "/api/v1/alerts",
        json=payload,
        headers=auth_headers_for(admin),
    )
    assert response.status_code == 201
    data = response.json()
    assert data["fingerprint"] == payload["fingerprint"]
    assert data["status"] == "FIRING"
    assert data["severity"] == "CRITICAL"
    assert data["organization_id"] == str(org.id)
    assert data["service_id"] == str(svc.id)
    assert data["first_seen_at"] is not None
    assert data["last_seen_at"] is not None


@pytest.mark.asyncio
async def test_engineer_can_create_alert(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """ENGINEER role can successfully ingest an alert."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    engineer = await create_test_user(db_session, org.id, role=Role.ENGINEER)

    response = await client.post(
        "/api/v1/alerts",
        json={
            "service_id": str(svc.id),
            "fingerprint": f"fp-eng-{uuid.uuid4().hex[:6]}",
            "source": "datadog",
            "alert_type": "high_latency",
            "title": "P99 Latency > 1000ms",
            "severity": "HIGH",
        },
        headers=auth_headers_for(engineer),
    )
    assert response.status_code == 201
    assert response.json()["status"] == "FIRING"


@pytest.mark.asyncio
async def test_responder_cannot_create_alert_403(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """RESPONDER cannot ingest alerts via manage:alerts (403 Forbidden)."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    responder = await create_test_user(db_session, org.id, role=Role.RESPONDER)

    response = await client.post(
        "/api/v1/alerts",
        json={
            "service_id": str(svc.id),
            "fingerprint": f"fp-resp-{uuid.uuid4().hex[:6]}",
            "source": "pagerduty",
            "alert_type": "test",
            "title": "Test Alert",
        },
        headers=auth_headers_for(responder),
    )
    assert response.status_code == 403
    assert "manage:alerts" in response.json()["error"]["message"]


@pytest.mark.asyncio
async def test_viewer_cannot_mutate_alerts_403(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """VIEWER role cannot ingest or update alerts (403 Forbidden)."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    viewer = await create_test_user(db_session, org.id, role=Role.VIEWER)

    # Ingestion attempt
    r1 = await client.post(
        "/api/v1/alerts",
        json={
            "service_id": str(svc.id),
            "fingerprint": "viewer-fp",
            "source": "test",
            "alert_type": "test",
            "title": "Viewer Alert",
        },
        headers=auth_headers_for(viewer),
    )
    assert r1.status_code == 403

    # Update attempt
    alert = await create_test_alert(db_session, org.id, svc.id)
    r2 = await client.patch(
        f"/api/v1/alerts/{alert.id}",
        json={"title": "Hacked Title"},
        headers=auth_headers_for(viewer),
    )
    assert r2.status_code == 403


@pytest.mark.asyncio
async def test_all_authenticated_roles_can_view_alerts(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """All authenticated roles (ADMIN, ENGINEER, RESPONDER, VIEWER) can view alerts."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    alert = await create_test_alert(db_session, org.id, svc.id, title="Visible Alert")

    for role in [Role.ADMIN, Role.ENGINEER, Role.RESPONDER, Role.VIEWER]:
        user = await create_test_user(db_session, org.id, role=role)

        # List
        r_list = await client.get("/api/v1/alerts", headers=auth_headers_for(user))
        assert r_list.status_code == 200
        alert_ids = [a["id"] for a in r_list.json()["items"]]
        assert str(alert.id) in alert_ids

        # Get by ID
        r_get = await client.get(f"/api/v1/alerts/{alert.id}", headers=auth_headers_for(user))
        assert r_get.status_code == 200
        assert r_get.json()["title"] == "Visible Alert"


@pytest.mark.asyncio
async def test_idempotent_duplicate_fingerprint_ingestion(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Re-ingesting the same fingerprint updates last_seen_at idempotently without duplicating rows."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    fp = f"idempotent-fp-{uuid.uuid4().hex[:6]}"

    # First ingestion -> 201 Created
    r1 = await client.post(
        "/api/v1/alerts",
        json={
            "service_id": str(svc.id),
            "fingerprint": fp,
            "source": "prometheus",
            "alert_type": "cpu_high",
            "title": "CPU > 90%",
            "severity": "HIGH",
            "message": "First alert occurrence",
        },
        headers=auth_headers_for(admin),
    )
    assert r1.status_code == 201
    first_alert = r1.json()
    alert_id = first_alert["id"]
    first_seen = first_alert["first_seen_at"]
    initial_last_seen = first_alert["last_seen_at"]

    # Second ingestion of SAME fingerprint -> 200 OK (idempotent update)
    r2 = await client.post(
        "/api/v1/alerts",
        json={
            "service_id": str(svc.id),
            "fingerprint": fp,
            "source": "prometheus",
            "alert_type": "cpu_high",
            "title": "CPU > 90% (recurring)",
            "severity": "CRITICAL",  # Severity escalation allowed
            "message": "Second alert occurrence with updated info",
        },
        headers=auth_headers_for(admin),
    )
    assert r2.status_code == 200
    second_alert = r2.json()
    assert second_alert["id"] == alert_id
    assert second_alert["first_seen_at"] == first_seen
    assert second_alert["severity"] == "CRITICAL"
    assert second_alert["message"] == "Second alert occurrence with updated info"
    assert second_alert["last_seen_at"] >= initial_last_seen

    # Verify database only has exactly 1 row for this fingerprint
    q = select(Alert).where(Alert.organization_id == org.id, Alert.fingerprint == fp)
    alerts = (await db_session.execute(q)).scalars().all()
    assert len(alerts) == 1


@pytest.mark.asyncio
async def test_alert_filtering_and_pagination(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Alert listing supports filters for status, severity, service, source, and pagination."""
    org = await create_test_organization(db_session)
    svc1 = await create_test_service(db_session, org.id, name="Svc 1")
    svc2 = await create_test_service(db_session, org.id, name="Svc 2")
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    await create_test_alert(db_session, org.id, svc1.id, severity="CRITICAL", status="FIRING", source="grafana")
    await create_test_alert(db_session, org.id, svc1.id, severity="LOW", status="RESOLVED", source="prometheus")
    await create_test_alert(db_session, org.id, svc2.id, severity="CRITICAL", status="FIRING", source="grafana")

    # Filter severity CRITICAL
    r_crit = await client.get("/api/v1/alerts?severity=CRITICAL", headers=auth_headers_for(admin))
    assert r_crit.status_code == 200
    assert r_crit.json()["total"] == 2

    # Filter source grafana
    r_src = await client.get("/api/v1/alerts?source=grafana", headers=auth_headers_for(admin))
    assert r_src.status_code == 200
    assert r_src.json()["total"] == 2

    # Filter service svc2
    r_svc = await client.get(f"/api/v1/alerts?service_id={svc2.id}", headers=auth_headers_for(admin))
    assert r_svc.status_code == 200
    assert r_svc.json()["total"] == 1

    # Pagination
    r_page = await client.get("/api/v1/alerts?page=1&page_size=2", headers=auth_headers_for(admin))
    assert r_page.status_code == 200
    data = r_page.json()
    assert len(data["items"]) == 2
    assert data["total"] == 3
    assert data["pages"] == 2


@pytest.mark.asyncio
async def test_cross_tenant_alert_isolation_404(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Tenant A cannot read, update, or reference Tenant B alerts/services/incidents."""
    org_a = await create_test_organization(db_session, name="Org A")
    org_b = await create_test_organization(db_session, name="Org B")

    svc_a = await create_test_service(db_session, org_a.id)
    svc_b = await create_test_service(db_session, org_b.id)

    admin_a = await create_test_user(db_session, org_a.id, role=Role.ADMIN)
    alert_b = await create_test_alert(db_session, org_b.id, svc_b.id)

    # 1. Tenant A cannot GET Tenant B alert
    r1 = await client.get(f"/api/v1/alerts/{alert_b.id}", headers=auth_headers_for(admin_a))
    assert r1.status_code == 404

    # 2. Tenant A cannot PATCH Tenant B alert
    r2 = await client.patch(
        f"/api/v1/alerts/{alert_b.id}", json={"title": "Hacked"}, headers=auth_headers_for(admin_a)
    )
    assert r2.status_code == 404

    # 3. Tenant A cannot create an alert pointing to Tenant B's service
    r3 = await client.post(
        "/api/v1/alerts",
        json={
            "service_id": str(svc_b.id),
            "fingerprint": "cross-tenant-svc",
            "source": "datadog",
            "alert_type": "error",
            "title": "Cross Tenant Service Alert",
        },
        headers=auth_headers_for(admin_a),
    )
    assert r3.status_code == 404


@pytest.mark.asyncio
async def test_alert_incident_association(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Associating an alert with an incident verifies service match and records audit logs."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    svc_other = await create_test_service(db_session, org.id, name="Other Service")

    responder = await create_test_user(db_session, org.id, role=Role.RESPONDER)

    alert = await create_test_alert(db_session, org.id, svc.id)
    inc_same_svc = await create_test_incident(db_session, org.id, svc.id)
    inc_diff_svc = await create_test_incident(db_session, org.id, svc_other.id)

    # 1. Service mismatch rejected (409 Conflict)
    r_mismatch = await client.post(
        f"/api/v1/alerts/{alert.id}/incident",
        json={"incident_id": str(inc_diff_svc.id)},
        headers=auth_headers_for(responder),
    )
    assert r_mismatch.status_code == 409
    assert "does not match incident service" in r_mismatch.json()["error"]["message"]

    # 2. Valid association succeeds (200 OK)
    r_match = await client.post(
        f"/api/v1/alerts/{alert.id}/incident",
        json={"incident_id": str(inc_same_svc.id)},
        headers=auth_headers_for(responder),
    )
    assert r_match.status_code == 200
    assert r_match.json()["incident_id"] == str(inc_same_svc.id)

    # 3. Verify audit log recorded
    q = select(AuditLog).where(
        AuditLog.organization_id == org.id,
        AuditLog.entity_id == alert.id,
        AuditLog.action == "ALERT_ASSOCIATED_WITH_INCIDENT",
    )
    audit = (await db_session.execute(q)).scalar_one_or_none()
    assert audit is not None
    assert audit.new_values["incident_id"] == str(inc_same_svc.id)


@pytest.mark.asyncio
async def test_alert_database_constraints(db_session: AsyncSession) -> None:
    """Verify PostgreSQL check constraints and unique fingerprint per tenant."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    org_id = org.id
    svc_id = svc.id

    # 1. Check constraint: invalid severity rejected
    a_bad_sev = Alert(
        organization_id=org_id,
        service_id=svc_id,
        fingerprint=f"bad-sev-{uuid.uuid4().hex[:6]}",
        source="test",
        alert_type="test",
        title="Bad Severity",
        severity="INSANE",
    )
    db_session.add(a_bad_sev)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()

    # 2. Check constraint: invalid status rejected
    a_bad_stat = Alert(
        organization_id=org_id,
        service_id=svc_id,
        fingerprint=f"bad-stat-{uuid.uuid4().hex[:6]}",
        source="test",
        alert_type="test",
        title="Bad Status",
        status="UNKNOWN_STATUS",
    )
    db_session.add(a_bad_stat)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()

    # 3. Unique constraint: duplicate (organization_id, fingerprint) rejected at DB level
    dup_fp = f"dup-fp-{uuid.uuid4().hex[:6]}"
    a1 = Alert(
        organization_id=org_id,
        service_id=svc_id,
        fingerprint=dup_fp,
        source="test",
        alert_type="test",
        title="First Alert",
    )
    db_session.add(a1)
    await db_session.commit()

    a2 = Alert(
        organization_id=org_id,
        service_id=svc_id,
        fingerprint=dup_fp,
        source="test",
        alert_type="test",
        title="Second Alert Duplicate",
    )
    db_session.add(a2)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()
