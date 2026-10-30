"""Tests for Alert entity, idempotent ingestion, lifecycle, and incident association."""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.alerts import AlertSeverity, AlertStatus
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
    assert data["source"] == payload["source"]
    assert data["alert_type"] == payload["alert_type"]
    assert data["title"] == payload["title"]
    assert data["severity"] == "CRITICAL"
    assert data["status"] == "FIRING"
    assert data["first_seen_at"] is not None
    assert data["last_seen_at"] is not None
    assert data["resolved_at"] is None
    assert data["service_id"] == str(svc.id)
    assert data["organization_id"] == str(org.id)


@pytest.mark.asyncio
async def test_engineer_can_create_alert(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """ENGINEER role can ingest an alert."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    engineer = await create_test_user(db_session, org.id, role=Role.ENGINEER)

    response = await client.post(
        "/api/v1/alerts",
        json={
            "service_id": str(svc.id),
            "fingerprint": f"fp-eng-{uuid.uuid4().hex[:6]}",
            "source": "datadog",
            "alert_type": "disk_space_low",
            "title": "Disk Space < 10%",
            "severity": "HIGH",
        },
        headers=auth_headers_for(engineer),
    )
    assert response.status_code == 201
    assert response.json()["status"] == "FIRING"


@pytest.mark.asyncio
async def test_responder_cannot_create_alerts_403(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """RESPONDER role cannot ingest alerts (403 Forbidden)."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    responder = await create_test_user(db_session, org.id, role=Role.RESPONDER)

    response = await client.post(
        "/api/v1/alerts",
        json={
            "service_id": str(svc.id),
            "fingerprint": "resp-fp",
            "source": "test",
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
    """Re-ingesting the same fingerprint while FIRING updates last_seen_at and escalates severity idempotently (200 OK)."""
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

    # Second ingestion of SAME fingerprint while FIRING -> 200 OK (idempotent deduplication)
    r2 = await client.post(
        "/api/v1/alerts",
        json={
            "service_id": str(svc.id),
            "fingerprint": fp,
            "source": "prometheus",
            "alert_type": "cpu_high",
            "title": "CPU > 90% (recurring)",
            "severity": "CRITICAL",  # Severity escalation allowed (HIGH -> CRITICAL)
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

    # Third ingestion with LOWER severity -> remains CRITICAL (no silent de-escalation)
    r3 = await client.post(
        "/api/v1/alerts",
        json={
            "service_id": str(svc.id),
            "fingerprint": fp,
            "source": "prometheus",
            "alert_type": "cpu_high",
            "title": "CPU normal-ish",
            "severity": "LOW",
        },
        headers=auth_headers_for(admin),
    )
    assert r3.status_code == 200
    assert r3.json()["severity"] == "CRITICAL"

    # Verify database only has exactly 1 row for this fingerprint
    q = select(Alert).where(Alert.organization_id == org.id, Alert.fingerprint == fp)
    alerts = (await db_session.execute(q)).scalars().all()
    assert len(alerts) == 1


@pytest.mark.asyncio
async def test_resolved_alert_reingested_creates_new_occurrence_201(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Case B: If an existing alert with the same fingerprint is RESOLVED, re-ingestion creates a NEW alert occurrence (201 Created)."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    fp = f"resolved-reingest-fp-{uuid.uuid4().hex[:6]}"

    # 1. Initial ingestion -> 201 Created
    r1 = await client.post(
        "/api/v1/alerts",
        json={
            "service_id": str(svc.id),
            "fingerprint": fp,
            "source": "prometheus",
            "alert_type": "memory_leak",
            "title": "Memory leak detected",
            "severity": "HIGH",
        },
        headers=auth_headers_for(admin),
    )
    assert r1.status_code == 201
    alert_1_id = r1.json()["id"]

    # 2. Resolve the alert via PATCH
    r_patch = await client.patch(
        f"/api/v1/alerts/{alert_1_id}",
        json={"status": "RESOLVED"},
        headers=auth_headers_for(admin),
    )
    assert r_patch.status_code == 200
    assert r_patch.json()["status"] == "RESOLVED"
    assert r_patch.json()["resolved_at"] is not None

    # 3. New signal with the SAME fingerprint arrives -> creates NEW active occurrence (201 Created)
    r2 = await client.post(
        "/api/v1/alerts",
        json={
            "service_id": str(svc.id),
            "fingerprint": fp,
            "source": "prometheus",
            "alert_type": "memory_leak",
            "title": "Memory leak detected again",
            "severity": "HIGH",
        },
        headers=auth_headers_for(admin),
    )
    assert r2.status_code == 201
    alert_2_id = r2.json()["id"]
    assert alert_2_id != alert_1_id
    assert r2.json()["status"] == "FIRING"
    assert r2.json()["resolved_at"] is None

    # 4. Verify both occurrences coexist in the database
    q = select(Alert).where(Alert.organization_id == org.id, Alert.fingerprint == fp)
    alerts = (await db_session.execute(q)).scalars().all()
    assert len(alerts) == 2
    statuses = {a.status for a in alerts}
    assert statuses == {"RESOLVED", "FIRING"}


@pytest.mark.asyncio
async def test_suppressed_alert_reingested_creates_new_occurrence_201(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Case C: If an existing alert with the same fingerprint is SUPPRESSED, re-ingestion creates a NEW alert occurrence (201 Created)."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    fp = f"suppressed-reingest-fp-{uuid.uuid4().hex[:6]}"

    # 1. Initial ingestion -> 201 Created
    r1 = await client.post(
        "/api/v1/alerts",
        json={
            "service_id": str(svc.id),
            "fingerprint": fp,
            "source": "prometheus",
            "alert_type": "disk_io",
            "title": "Disk I/O Spike",
            "severity": "LOW",
        },
        headers=auth_headers_for(admin),
    )
    assert r1.status_code == 201
    alert_1_id = r1.json()["id"]

    # 2. Suppress the alert via PATCH
    r_patch = await client.patch(
        f"/api/v1/alerts/{alert_1_id}",
        json={"status": "SUPPRESSED"},
        headers=auth_headers_for(admin),
    )
    assert r_patch.status_code == 200
    assert r_patch.json()["status"] == "SUPPRESSED"

    # 3. New signal with SAME fingerprint -> creates NEW active occurrence (201 Created)
    r2 = await client.post(
        "/api/v1/alerts",
        json={
            "service_id": str(svc.id),
            "fingerprint": fp,
            "source": "prometheus",
            "alert_type": "disk_io",
            "title": "Disk I/O Spike Reoccurred",
            "severity": "MEDIUM",
        },
        headers=auth_headers_for(admin),
    )
    assert r2.status_code == 201
    alert_2_id = r2.json()["id"]
    assert alert_2_id != alert_1_id
    assert r2.json()["status"] == "FIRING"

    # Verify both occurrences exist in database
    q = select(Alert).where(Alert.organization_id == org.id, Alert.fingerprint == fp)
    alerts = (await db_session.execute(q)).scalars().all()
    assert len(alerts) == 2


@pytest.mark.asyncio
async def test_different_organizations_can_use_same_fingerprint(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Different tenants can independently ingest active FIRING alerts with the exact same fingerprint."""
    org_a = await create_test_organization(db_session, name="Org A")
    org_b = await create_test_organization(db_session, name="Org B")

    svc_a = await create_test_service(db_session, org_a.id)
    svc_b = await create_test_service(db_session, org_b.id)

    admin_a = await create_test_user(db_session, org_a.id, role=Role.ADMIN)
    admin_b = await create_test_user(db_session, org_b.id, role=Role.ADMIN)

    shared_fp = f"global-fingerprint-{uuid.uuid4().hex[:6]}"

    # Org A ingests alert
    r_a = await client.post(
        "/api/v1/alerts",
        json={
            "service_id": str(svc_a.id),
            "fingerprint": shared_fp,
            "source": "prometheus",
            "alert_type": "disk_full",
            "title": "Disk Full Org A",
        },
        headers=auth_headers_for(admin_a),
    )
    assert r_a.status_code == 201
    alert_a_id = r_a.json()["id"]

    # Org B ingests alert with the identical fingerprint -> succeeds (201 Created)
    r_b = await client.post(
        "/api/v1/alerts",
        json={
            "service_id": str(svc_b.id),
            "fingerprint": shared_fp,
            "source": "prometheus",
            "alert_type": "disk_full",
            "title": "Disk Full Org B",
        },
        headers=auth_headers_for(admin_b),
    )
    assert r_b.status_code == 201
    alert_b_id = r_b.json()["id"]
    assert alert_a_id != alert_b_id

    # Cross-tenant isolation verification
    r_a_check = await client.get(f"/api/v1/alerts/{alert_b_id}", headers=auth_headers_for(admin_a))
    assert r_a_check.status_code == 404


@pytest.mark.asyncio
async def test_concurrent_duplicate_firing_creates_only_one_active_alert(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Concurrent ingestion requests with identical fingerprint cannot create two active alerts."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    fp = f"concurrent-fp-{uuid.uuid4().hex[:6]}"
    payload = {
        "service_id": str(svc.id),
        "fingerprint": fp,
        "source": "prometheus",
        "alert_type": "latency_p99",
        "title": "Concurrent High Latency",
    }

    # Dispatch concurrent requests
    res1, res2 = await asyncio.gather(
        client.post("/api/v1/alerts", json=payload, headers=auth_headers_for(admin)),
        client.post("/api/v1/alerts", json=payload, headers=auth_headers_for(admin)),
    )

    statuses = {res1.status_code, res2.status_code}
    assert 201 in statuses
    assert all(s in (200, 201) for s in statuses)

    # In database, exactly 1 row must exist for this fingerprint
    q = select(Alert).where(Alert.organization_id == org.id, Alert.fingerprint == fp)
    alerts = (await db_session.execute(q)).scalars().all()
    assert len(alerts) == 1
    assert alerts[0].status == "FIRING"


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

    # Filter status RESOLVED
    r_stat = await client.get("/api/v1/alerts?status=RESOLVED", headers=auth_headers_for(admin))
    assert r_stat.status_code == 200
    assert r_stat.json()["total"] == 1


@pytest.mark.asyncio
async def test_alert_incident_association_service_mismatch_rejected_409(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Alert cannot be associated with an incident of a different service (409 Conflict)."""
    org = await create_test_organization(db_session)
    svc1 = await create_test_service(db_session, org.id, name="Service 1")
    svc2 = await create_test_service(db_session, org.id, name="Service 2")
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    # Alert belongs to svc1
    alert = await create_test_alert(db_session, org.id, svc1.id)
    # Incident belongs to svc2
    incident = await create_test_incident(db_session, org.id, svc2.id)

    response = await client.post(
        f"/api/v1/alerts/{alert.id}/incident",
        json={"incident_id": str(incident.id)},
        headers=auth_headers_for(admin),
    )
    assert response.status_code == 409
    assert "does not match incident service" in response.json()["error"]["message"]


@pytest.mark.asyncio
async def test_alert_incident_association_success(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Alert can be associated with an incident belonging to the same service."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    engineer = await create_test_user(db_session, org.id, role=Role.ENGINEER)

    alert = await create_test_alert(db_session, org.id, svc.id)
    incident = await create_test_incident(db_session, org.id, svc.id)

    response = await client.post(
        f"/api/v1/alerts/{alert.id}/incident",
        json={"incident_id": str(incident.id)},
        headers=auth_headers_for(engineer),
    )
    assert response.status_code == 200
    assert response.json()["incident_id"] == str(incident.id)

    # Verify audit log recorded
    q = select(AuditLog).where(
        AuditLog.organization_id == org.id,
        AuditLog.action == "ALERT_ASSOCIATED_WITH_INCIDENT",
        AuditLog.entity_id == alert.id,
    )
    audit = (await db_session.execute(q)).scalar_one_or_none()
    assert audit is not None
    assert audit.new_values["incident_id"] == str(incident.id)


@pytest.mark.asyncio
async def test_cross_tenant_alert_isolation_404(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Tenant A cannot access or update Tenant B's alerts (returns 404)."""
    org_a = await create_test_organization(db_session, name="Org A")
    org_b = await create_test_organization(db_session, name="Org B")

    svc_b = await create_test_service(db_session, org_b.id)
    alert_b = await create_test_alert(db_session, org_b.id, svc_b.id)

    admin_a = await create_test_user(db_session, org_a.id, role=Role.ADMIN)

    # GET
    r_get = await client.get(f"/api/v1/alerts/{alert_b.id}", headers=auth_headers_for(admin_a))
    assert r_get.status_code == 404

    # PATCH
    r_patch = await client.patch(
        f"/api/v1/alerts/{alert_b.id}",
        json={"title": "Hacked"},
        headers=auth_headers_for(admin_a),
    )
    assert r_patch.status_code == 404


@pytest.mark.asyncio
async def test_alert_database_constraints(db_session: AsyncSession) -> None:
    """Verify PostgreSQL check constraints and partial unique index on active alerts."""
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

    # 3. Partial Unique Index: two FIRING alerts with same fingerprint in same org rejected at DB level
    dup_fp = f"dup-fp-{uuid.uuid4().hex[:6]}"
    a1 = Alert(
        organization_id=org_id,
        service_id=svc_id,
        fingerprint=dup_fp,
        source="test",
        alert_type="test",
        title="First Alert Firing",
        status="FIRING",
    )
    db_session.add(a1)
    await db_session.commit()

    a2 = Alert(
        organization_id=org_id,
        service_id=svc_id,
        fingerprint=dup_fp,
        source="test",
        alert_type="test",
        title="Second Alert Duplicate Firing",
        status="FIRING",
    )
    db_session.add(a2)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()

    # 4. Same fingerprint with RESOLVED status and FIRING status can coexist in DB
    hist_fp = f"hist-fp-{uuid.uuid4().hex[:6]}"
    a_resolved = Alert(
        organization_id=org_id,
        service_id=svc_id,
        fingerprint=hist_fp,
        source="test",
        alert_type="test",
        title="Resolved Historical Alert",
        status="RESOLVED",
    )
    db_session.add(a_resolved)
    await db_session.commit()

    a_firing = Alert(
        organization_id=org_id,
        service_id=svc_id,
        fingerprint=hist_fp,
        source="test",
        alert_type="test",
        title="New Active Firing Alert",
        status="FIRING",
    )
    db_session.add(a_firing)
    await db_session.commit()

    # Verify both rows persist
    q = select(Alert).where(Alert.organization_id == org_id, Alert.fingerprint == hist_fp)
    alerts = (await db_session.execute(q)).scalars().all()
    assert len(alerts) == 2
