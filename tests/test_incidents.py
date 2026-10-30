"""Tests for Incident entity, lifecycle state machine, timeline events, and RBAC."""

from __future__ import annotations

import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.incidents import IncidentSeverity, IncidentStatus
from diagnose.domain.roles import Role
from diagnose.models.audit_log import AuditLog
from diagnose.models.incident import Incident
from diagnose.models.incident_event import IncidentEvent
from diagnose.models.organization import Organization
from tests.factories import (
    auth_headers_for,
    create_test_incident,
    create_test_organization,
    create_test_service,
    create_test_user,
)


@pytest.mark.asyncio
async def test_admin_can_create_incident(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """ADMIN role can successfully create an incident."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    payload = {
        "title": "Payment Gateway 504 Gateway Timeout",
        "description": "Inbound payments failing with 504 upstream error",
        "service_id": str(svc.id),
        "severity": "CRITICAL",
    }
    response = await client.post(
        "/api/v1/incidents",
        json=payload,
        headers=auth_headers_for(admin),
    )
    assert response.status_code == 201
    data = response.json()
    assert data["title"] == payload["title"]
    assert data["service_id"] == str(svc.id)
    assert data["severity"] == "CRITICAL"
    assert data["status"] == "DETECTED"
    assert data["incident_number"] == 1
    assert data["detected_at"] is not None
    assert data["acknowledged_at"] is None
    assert data["resolved_at"] is None
    assert data["closed_at"] is None


@pytest.mark.asyncio
async def test_engineer_can_create_incident(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """ENGINEER role can successfully create an incident."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    engineer = await create_test_user(db_session, org.id, role=Role.ENGINEER)

    response = await client.post(
        "/api/v1/incidents",
        json={
            "title": "Auth token latency spike",
            "service_id": str(svc.id),
            "severity": "HIGH",
        },
        headers=auth_headers_for(engineer),
    )
    assert response.status_code == 201
    assert response.json()["status"] == "DETECTED"


@pytest.mark.asyncio
async def test_responder_can_create_incident(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """RESPONDER role can successfully declare an incident."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    responder = await create_test_user(db_session, org.id, role=Role.RESPONDER)

    response = await client.post(
        "/api/v1/incidents",
        json={
            "title": "Database connection pool exhaustion",
            "service_id": str(svc.id),
            "severity": "CRITICAL",
        },
        headers=auth_headers_for(responder),
    )
    assert response.status_code == 201
    assert response.json()["status"] == "DETECTED"


@pytest.mark.asyncio
async def test_viewer_cannot_create_incident_403(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """VIEWER role cannot create an incident (403 Forbidden)."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    viewer = await create_test_user(db_session, org.id, role=Role.VIEWER)

    response = await client.post(
        "/api/v1/incidents",
        json={
            "title": "Viewer unauthorized declaration",
            "service_id": str(svc.id),
            "severity": "LOW",
        },
        headers=auth_headers_for(viewer),
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_initial_status_is_detected(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Any newly created incident is always initialized in DETECTED status."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    response = await client.post(
        "/api/v1/incidents",
        json={
            "title": "Initial status check",
            "service_id": str(svc.id),
            "severity": "MEDIUM",
            "status": "RESOLVED",  # Attempt to spoof initial status
        },
        headers=auth_headers_for(admin),
    )
    assert response.status_code == 201
    assert response.json()["status"] == "DETECTED"


@pytest.mark.asyncio
async def test_lifecycle_full_happy_path(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Execute the full valid lifecycle transition chain:
    DETECTED -> ACKNOWLEDGED -> INVESTIGATING -> IDENTIFIED -> MITIGATING -> RESOLVED -> CLOSED.
    """
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    # 1. Create (DETECTED)
    res = await client.post(
        "/api/v1/incidents",
        json={"title": "Full lifecycle incident", "service_id": str(svc.id), "severity": "HIGH"},
        headers=auth_headers_for(admin),
    )
    assert res.status_code == 201
    inc_id = res.json()["id"]

    # 2. DETECTED -> ACKNOWLEDGED
    r2 = await client.post(
        f"/api/v1/incidents/{inc_id}/transition",
        json={"target_status": "ACKNOWLEDGED", "message": "On-call paged and acknowledged"},
        headers=auth_headers_for(admin),
    )
    assert r2.status_code == 200
    assert r2.json()["status"] == "ACKNOWLEDGED"
    assert r2.json()["acknowledged_at"] is not None

    # 3. ACKNOWLEDGED -> INVESTIGATING
    r3 = await client.post(
        f"/api/v1/incidents/{inc_id}/transition",
        json={"target_status": "INVESTIGATING", "message": "Examining logs and traces"},
        headers=auth_headers_for(admin),
    )
    assert r3.status_code == 200
    assert r3.json()["status"] == "INVESTIGATING"

    # 4. INVESTIGATING -> IDENTIFIED
    r4 = await client.post(
        f"/api/v1/incidents/{inc_id}/transition",
        json={"target_status": "IDENTIFIED", "message": "Root cause identified as bad canary config"},
        headers=auth_headers_for(admin),
    )
    assert r4.status_code == 200
    assert r4.json()["status"] == "IDENTIFIED"

    # 5. IDENTIFIED -> MITIGATING
    r5 = await client.post(
        f"/api/v1/incidents/{inc_id}/transition",
        json={"target_status": "MITIGATING", "message": "Rolling back canary build"},
        headers=auth_headers_for(admin),
    )
    assert r5.status_code == 200
    assert r5.json()["status"] == "MITIGATING"

    # 6. MITIGATING -> RESOLVED
    r6 = await client.post(
        f"/api/v1/incidents/{inc_id}/transition",
        json={"target_status": "RESOLVED", "message": "Error rates returned to normal baseline"},
        headers=auth_headers_for(admin),
    )
    assert r6.status_code == 200
    assert r6.json()["status"] == "RESOLVED"
    assert r6.json()["resolved_at"] is not None

    # 7. RESOLVED -> CLOSED
    r7 = await client.post(
        f"/api/v1/incidents/{inc_id}/transition",
        json={"target_status": "CLOSED", "message": "Post-mortem completed; incident closed"},
        headers=auth_headers_for(admin),
    )
    assert r7.status_code == 200
    assert r7.json()["status"] == "CLOSED"
    assert r7.json()["closed_at"] is not None


@pytest.mark.asyncio
async def test_shortcut_investigating_to_mitigating(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Test valid branch: INVESTIGATING -> MITIGATING directly without IDENTIFIED."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    inc = await create_test_incident(db_session, org.id, svc.id, status="INVESTIGATING")

    resp = await client.post(
        f"/api/v1/incidents/{inc.id}/transition",
        json={"target_status": "MITIGATING", "message": "Direct mitigation engaged"},
        headers=auth_headers_for(admin),
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "MITIGATING"


@pytest.mark.asyncio
async def test_reopen_resolved_to_investigating(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Test re-opening incident: RESOLVED -> INVESTIGATING clears resolved_at."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    # Start at RESOLVED
    inc = await create_test_incident(db_session, org.id, svc.id, status="RESOLVED")

    # Re-open
    resp = await client.post(
        f"/api/v1/incidents/{inc.id}/transition",
        json={"target_status": "INVESTIGATING", "message": "Issue recurred after initial mitigation"},
        headers=auth_headers_for(admin),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "INVESTIGATING"
    assert data["resolved_at"] is None  # Timestamp cleanly cleared to avoid contradiction


@pytest.mark.asyncio
async def test_invalid_state_transitions_rejected(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Verify state machine rejects invalid jumps with 409 Conflict."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    # 1. DETECTED -> INVESTIGATING is invalid (must ACKNOWLEDGE first)
    inc1 = await create_test_incident(db_session, org.id, svc.id, status="DETECTED")
    r1 = await client.post(
        f"/api/v1/incidents/{inc1.id}/transition",
        json={"target_status": "INVESTIGATING"},
        headers=auth_headers_for(admin),
    )
    assert r1.status_code == 409
    assert "Invalid state transition" in r1.json()["error"]["message"]

    # 2. DETECTED -> RESOLVED is invalid
    r2 = await client.post(
        f"/api/v1/incidents/{inc1.id}/transition",
        json={"target_status": "RESOLVED"},
        headers=auth_headers_for(admin),
    )
    assert r2.status_code == 409

    # 3. ACKNOWLEDGED -> RESOLVED is invalid
    inc2 = await create_test_incident(db_session, org.id, svc.id, status="ACKNOWLEDGED")
    r3 = await client.post(
        f"/api/v1/incidents/{inc2.id}/transition",
        json={"target_status": "RESOLVED"},
        headers=auth_headers_for(admin),
    )
    assert r3.status_code == 409


@pytest.mark.asyncio
async def test_closed_incident_cannot_transition(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """CLOSED incident is a terminal state; all transitions are rejected (409 Conflict)."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    inc = await create_test_incident(db_session, org.id, svc.id, status="CLOSED")

    for target in ["INVESTIGATING", "RESOLVED", "DETECTED", "CLOSED"]:
        resp = await client.post(
            f"/api/v1/incidents/{inc.id}/transition",
            json={"target_status": target},
            headers=auth_headers_for(admin),
        )
        assert resp.status_code == 409


@pytest.mark.asyncio
async def test_closed_incident_metadata_update_rejected(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Modifying metadata of a CLOSED incident is prohibited."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    inc = await create_test_incident(db_session, org.id, svc.id, status="CLOSED")

    resp = await client.patch(
        f"/api/v1/incidents/{inc.id}",
        json={"title": "Attempting to change closed title"},
        headers=auth_headers_for(admin),
    )
    assert resp.status_code == 409
    assert "Cannot modify a closed incident" in resp.json()["error"]["message"]


@pytest.mark.asyncio
async def test_incident_and_events_atomicity(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Creation and transitions atomically append IncidentEvent and AuditLog records."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    # Create incident
    res = await client.post(
        "/api/v1/incidents",
        json={"title": "Audited Incident", "service_id": str(svc.id), "severity": "HIGH"},
        headers=auth_headers_for(admin),
    )
    assert res.status_code == 201
    inc_id = uuid.UUID(res.json()["id"])

    # Transition to ACKNOWLEDGED
    r_ack = await client.post(
        f"/api/v1/incidents/{inc_id}/transition",
        json={"target_status": "ACKNOWLEDGED", "message": "Acknowledged by primary on-call"},
        headers=auth_headers_for(admin),
    )
    assert r_ack.status_code == 200

    # Verify timeline events
    q_events = (
        select(IncidentEvent)
        .where(IncidentEvent.incident_id == inc_id)
        .order_by(IncidentEvent.created_at.asc())
    )
    events = (await db_session.execute(q_events)).scalars().all()
    assert len(events) == 2
    assert events[0].event_type == "INCIDENT_CREATED"
    assert events[0].to_status == "DETECTED"
    assert events[1].event_type == "STATUS_CHANGED"
    assert events[1].from_status == "DETECTED"
    assert events[1].to_status == "ACKNOWLEDGED"
    assert events[1].message == "Acknowledged by primary on-call"

    # Verify audit logs
    q_audit = (
        select(AuditLog)
        .where(AuditLog.entity_id == inc_id)
        .order_by(AuditLog.created_at.asc())
    )
    audits = (await db_session.execute(q_audit)).scalars().all()
    actions = [a.action for a in audits]
    assert "INCIDENT_CREATED" in actions
    assert "INCIDENT_STATUS_CHANGED" in actions


@pytest.mark.asyncio
async def test_incident_assignment_flow(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Incident assignment updates assigned_user_id and generates events and audit logs."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)
    engineer = await create_test_user(db_session, org.id, role=Role.ENGINEER)

    inc = await create_test_incident(db_session, org.id, svc.id)

    # Assign to engineer
    resp = await client.post(
        f"/api/v1/incidents/{inc.id}/assign",
        json={"assigned_user_id": str(engineer.id)},
        headers=auth_headers_for(admin),
    )
    assert resp.status_code == 200
    assert resp.json()["assigned_user_id"] == str(engineer.id)

    # Unassign
    resp_unassign = await client.post(
        f"/api/v1/incidents/{inc.id}/assign",
        json={"assigned_user_id": None},
        headers=auth_headers_for(admin),
    )
    assert resp_unassign.status_code == 200
    assert resp_unassign.json()["assigned_user_id"] is None


@pytest.mark.asyncio
async def test_cross_tenant_isolation_404(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Tenant A cannot read, modify, or attach resources to Tenant B's incidents (returns 404)."""
    org_a = await create_test_organization(db_session, name="Org A")
    org_b = await create_test_organization(db_session, name="Org B")

    svc_a = await create_test_service(db_session, org_a.id, name="Svc A")
    svc_b = await create_test_service(db_session, org_b.id, name="Svc B")

    admin_a = await create_test_user(db_session, org_a.id, role=Role.ADMIN)
    user_b = await create_test_user(db_session, org_b.id, role=Role.ENGINEER)

    inc_b = await create_test_incident(db_session, org_b.id, svc_b.id)

    # 1. Tenant A cannot GET Tenant B incident
    r1 = await client.get(
        f"/api/v1/incidents/{inc_b.id}",
        headers=auth_headers_for(admin_a),
    )
    assert r1.status_code == 404

    # 2. Tenant A cannot PATCH Tenant B incident
    r2 = await client.patch(
        f"/api/v1/incidents/{inc_b.id}",
        json={"title": "Hacked Title"},
        headers=auth_headers_for(admin_a),
    )
    assert r2.status_code == 404

    # 3. Tenant A cannot view Tenant B incident events
    r3 = await client.get(
        f"/api/v1/incidents/{inc_b.id}/events",
        headers=auth_headers_for(admin_a),
    )
    assert r3.status_code == 404

    # 4. Tenant A cannot create an incident pointing to Tenant B's service
    r4 = await client.post(
        "/api/v1/incidents",
        json={"title": "Cross-tenant service", "service_id": str(svc_b.id)},
        headers=auth_headers_for(admin_a),
    )
    assert r4.status_code == 404

    # 5. Tenant A cannot assign Tenant B's user
    r5 = await client.post(
        "/api/v1/incidents",
        json={
            "title": "Cross-tenant user",
            "service_id": str(svc_a.id),
            "assigned_user_id": str(user_b.id),
        },
        headers=auth_headers_for(admin_a),
    )
    assert r5.status_code == 404


@pytest.mark.asyncio
async def test_client_cannot_spoof_organization_id(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Client-provided organization_id in body is ignored; token tenant is authoritative."""
    org_a = await create_test_organization(db_session)
    org_b = await create_test_organization(db_session)

    svc_a = await create_test_service(db_session, org_a.id)
    admin_a = await create_test_user(db_session, org_a.id, role=Role.ADMIN)

    response = await client.post(
        "/api/v1/incidents",
        json={
            "title": "Tenant spoof attempt",
            "service_id": str(svc_a.id),
            "organization_id": str(org_b.id),
        },
        headers=auth_headers_for(admin_a),
    )
    assert response.status_code == 201
    assert response.json()["organization_id"] == str(org_a.id)


@pytest.mark.asyncio
async def test_incident_filters_and_pagination(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Incident list query parameters filter by status, severity, service, and paginate."""
    org = await create_test_organization(db_session)
    svc1 = await create_test_service(db_session, org.id, name="Svc 1")
    svc2 = await create_test_service(db_session, org.id, name="Svc 2")
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    # Create 3 incidents
    await create_test_incident(db_session, org.id, svc1.id, severity="CRITICAL", status="DETECTED")
    await create_test_incident(db_session, org.id, svc1.id, severity="LOW", status="RESOLVED")
    await create_test_incident(db_session, org.id, svc2.id, severity="CRITICAL", status="ACKNOWLEDGED")

    # Filter by severity
    resp_crit = await client.get("/api/v1/incidents?severity=CRITICAL", headers=auth_headers_for(admin))
    assert resp_crit.status_code == 200
    assert resp_crit.json()["total"] == 2

    # Filter by service
    resp_svc2 = await client.get(f"/api/v1/incidents?service_id={svc2.id}", headers=auth_headers_for(admin))
    assert resp_svc2.status_code == 200
    assert resp_svc2.json()["total"] == 1

    # Pagination
    resp_page = await client.get("/api/v1/incidents?page=1&page_size=2", headers=auth_headers_for(admin))
    assert resp_page.status_code == 200
    data = resp_page.json()
    assert len(data["items"]) == 2
    assert data["total"] == 3
    assert data["pages"] == 2


@pytest.mark.asyncio
async def test_database_level_incident_constraints(db_session: AsyncSession) -> None:
    """Verify PostgreSQL check constraints and uniqueness at DB level."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    org_id = org.id
    svc_id = svc.id

    # 1. Check constraint: invalid status rejected
    inc_bad_status = Incident(
        organization_id=org_id,
        service_id=svc_id,
        incident_number=101,
        title="Bad Status",
        severity="MEDIUM",
        status="INVALID_STATUS",
    )
    db_session.add(inc_bad_status)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()

    # 2. Check constraint: invalid severity rejected
    inc_bad_sev = Incident(
        organization_id=org_id,
        service_id=svc_id,
        incident_number=102,
        title="Bad Severity",
        severity="SUPER_CRITICAL",
        status="DETECTED",
    )
    db_session.add(inc_bad_sev)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()

    # 3. Check constraint: empty title rejected
    inc_empty_title = Incident(
        organization_id=org_id,
        service_id=svc_id,
        incident_number=103,
        title="",
        severity="MEDIUM",
        status="DETECTED",
    )
    db_session.add(inc_empty_title)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()

    # 4. Unique constraint: duplicate incident_number per tenant rejected
    inc1 = Incident(
        organization_id=org_id,
        service_id=svc_id,
        incident_number=999,
        title="First 999",
        severity="LOW",
        status="DETECTED",
    )
    db_session.add(inc1)
    await db_session.commit()

    inc2 = Incident(
        organization_id=org_id,
        service_id=svc_id,
        incident_number=999,
        title="Second 999",
        severity="LOW",
        status="DETECTED",
    )
    db_session.add(inc2)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()

    # 5. Foreign key cascade: deleting organization cascades to incidents and events
    org_to_del = await create_test_organization(db_session)
    svc_to_del = await create_test_service(db_session, org_to_del.id)
    inc_to_del = await create_test_incident(db_session, org_to_del.id, svc_to_del.id)
    inc_id = inc_to_del.id

    await db_session.delete(org_to_del)
    await db_session.commit()

    found = await db_session.get(Incident, inc_id)
    assert found is None
