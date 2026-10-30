"""Tests for Evidence entity, content hashing, immutability, and tenant scoping."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.evidence import compute_evidence_hash
from diagnose.domain.roles import Role
from diagnose.models.audit_log import AuditLog
from diagnose.models.evidence import Evidence
from tests.factories import (
    auth_headers_for,
    create_test_evidence,
    create_test_incident,
    create_test_organization,
    create_test_service,
    create_test_user,
)


@pytest.mark.asyncio
async def test_admin_can_create_evidence(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """ADMIN role can successfully attach evidence to an incident."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    payload = {
        "evidence_type": "LOG",
        "source": "kubernetes",
        "title": "OOMKilled log line",
        "content": "Pod payment-api-7b8f99-x2k1 terminated with exit code 137 (OOMKilled)",
        "structured_data": {"pod": "payment-api-7b8f99-x2k1", "exit_code": 137},
        "reliability": "HIGH",
    }
    response = await client.post(
        f"/api/v1/incidents/{inc.id}/evidence",
        json=payload,
        headers=auth_headers_for(admin),
    )
    assert response.status_code == 201
    data = response.json()
    assert data["title"] == payload["title"]
    assert data["evidence_type"] == "LOG"
    assert data["evidence_hash"] is not None
    assert len(data["evidence_hash"]) == 64
    assert data["collected_by_user_id"] == str(admin.id)
    assert data["incident_id"] == str(inc.id)
    assert data["organization_id"] == str(org.id)


@pytest.mark.asyncio
async def test_engineer_and_responder_can_create_evidence(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """ENGINEER and RESPONDER roles can both attach evidence."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)

    engineer = await create_test_user(db_session, org.id, role=Role.ENGINEER)
    responder = await create_test_user(db_session, org.id, role=Role.RESPONDER)

    # Engineer
    r_eng = await client.post(
        f"/api/v1/incidents/{inc.id}/evidence",
        json={
            "evidence_type": "METRIC",
            "source": "datadog",
            "title": "Heap Memory Usage",
            "structured_data": {"metric": "jvm.heap.used", "value": 98.4},
        },
        headers=auth_headers_for(engineer),
    )
    assert r_eng.status_code == 201

    # Responder
    r_resp = await client.post(
        f"/api/v1/incidents/{inc.id}/evidence",
        json={
            "evidence_type": "CONFIG",
            "source": "github",
            "title": "Recent Deployment Config Change",
            "content": "JVM -Xmx changed from 4g to 1g in values.yaml",
        },
        headers=auth_headers_for(responder),
    )
    assert r_resp.status_code == 201


@pytest.mark.asyncio
async def test_viewer_cannot_create_evidence_403(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """VIEWER role cannot attach evidence (403 Forbidden)."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    viewer = await create_test_user(db_session, org.id, role=Role.VIEWER)

    response = await client.post(
        f"/api/v1/incidents/{inc.id}/evidence",
        json={
            "evidence_type": "LOG",
            "source": "test",
            "title": "Viewer Evidence Attempt",
        },
        headers=auth_headers_for(viewer),
    )
    assert response.status_code == 403
    assert "add:evidence" in response.json()["error"]["message"]


@pytest.mark.asyncio
async def test_all_authenticated_roles_can_view_evidence(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """All authenticated roles (ADMIN, ENGINEER, RESPONDER, VIEWER) can view evidence."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    evidence = await create_test_evidence(db_session, org.id, inc.id, title="Shared Artifact")

    for role in [Role.ADMIN, Role.ENGINEER, Role.RESPONDER, Role.VIEWER]:
        user = await create_test_user(db_session, org.id, role=role)

        # List by incident
        r_list = await client.get(
            f"/api/v1/incidents/{inc.id}/evidence",
            headers=auth_headers_for(user),
        )
        assert r_list.status_code == 200
        ids = [e["id"] for e in r_list.json()["items"]]
        assert str(evidence.id) in ids

        # Get by ID
        r_get = await client.get(
            f"/api/v1/evidence/{evidence.id}",
            headers=auth_headers_for(user),
        )
        assert r_get.status_code == 200
        assert r_get.json()["title"] == "Shared Artifact"


@pytest.mark.asyncio
async def test_duplicate_evidence_hash_rejected_409(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Submitting duplicate evidence with identical content/hash yields 409 Conflict."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    payload = {
        "evidence_type": "TRACE",
        "source": "jaeger",
        "title": "Root Span Trace",
        "content": "Trace ID: 4bf92f3577b34da6a3ce929d0e0e4736",
        "structured_data": {"duration_ms": 3500},
    }

    # 1. First submission succeeds (201)
    r1 = await client.post(
        f"/api/v1/incidents/{inc.id}/evidence",
        json=payload,
        headers=auth_headers_for(admin),
    )
    assert r1.status_code == 201

    # 2. Exact duplicate submission rejected (409 Conflict)
    r2 = await client.post(
        f"/api/v1/incidents/{inc.id}/evidence",
        json=payload,
        headers=auth_headers_for(admin),
    )
    assert r2.status_code == 409
    assert "Duplicate evidence artifact" in r2.json()["error"]["message"]


@pytest.mark.asyncio
async def test_evidence_immutability_no_update_or_delete(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Evidence is append-only: PATCH and DELETE requests are rejected (405 Method Not Allowed)."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)
    evidence = await create_test_evidence(db_session, org.id, inc.id)

    # Attempt PATCH
    r_patch = await client.patch(
        f"/api/v1/evidence/{evidence.id}",
        json={"title": "Altered Title"},
        headers=auth_headers_for(admin),
    )
    assert r_patch.status_code in (404, 405)

    # Attempt DELETE
    r_delete = await client.delete(
        f"/api/v1/evidence/{evidence.id}",
        headers=auth_headers_for(admin),
    )
    assert r_delete.status_code in (404, 405)


@pytest.mark.asyncio
async def test_cross_tenant_evidence_isolation_404(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Tenant A cannot view or attach evidence to Tenant B's incidents (returns 404)."""
    org_a = await create_test_organization(db_session, name="Org A")
    org_b = await create_test_organization(db_session, name="Org B")

    svc_b = await create_test_service(db_session, org_b.id)
    inc_b = await create_test_incident(db_session, org_b.id, svc_b.id)
    ev_b = await create_test_evidence(db_session, org_b.id, inc_b.id)

    admin_a = await create_test_user(db_session, org_a.id, role=Role.ADMIN)

    # 1. Tenant A cannot GET Tenant B evidence
    r1 = await client.get(
        f"/api/v1/evidence/{ev_b.id}",
        headers=auth_headers_for(admin_a),
    )
    assert r1.status_code == 404

    # 2. Tenant A cannot list Tenant B incident evidence
    r2 = await client.get(
        f"/api/v1/incidents/{inc_b.id}/evidence",
        headers=auth_headers_for(admin_a),
    )
    assert r2.status_code == 404

    # 3. Tenant A cannot attach evidence to Tenant B incident
    r3 = await client.post(
        f"/api/v1/incidents/{inc_b.id}/evidence",
        json={"evidence_type": "LOG", "source": "test", "title": "Unauthorized"},
        headers=auth_headers_for(admin_a),
    )
    assert r3.status_code == 404


@pytest.mark.asyncio
async def test_evidence_audit_logging(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Evidence creation records audit entries without storing oversized content."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    r = await client.post(
        f"/api/v1/incidents/{inc.id}/evidence",
        json={
            "evidence_type": "DOCUMENT",
            "source": "runbook",
            "title": "Failover Procedure",
            "content": "Extremely detailed 50-step disaster recovery procedure..." * 10,
        },
        headers=auth_headers_for(admin),
    )
    assert r.status_code == 201
    ev_id = uuid.UUID(r.json()["id"])

    # Query audit entry
    q = select(AuditLog).where(
        AuditLog.organization_id == org.id,
        AuditLog.entity_id == ev_id,
        AuditLog.action == "EVIDENCE_CREATED",
    )
    audit = (await db_session.execute(q)).scalar_one_or_none()
    assert audit is not None
    assert audit.new_values["incident_id"] == str(inc.id)
    assert audit.new_values["evidence_hash"] is not None
    assert "content" not in audit.new_values  # Content omitted from audit log for security/size hygiene


@pytest.mark.asyncio
async def test_evidence_database_constraints(db_session: AsyncSession) -> None:
    """Verify PostgreSQL check constraints and unique hash per tenant."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    org_id = org.id
    inc_id = inc.id

    # 1. Check constraint: invalid evidence_type rejected
    ev_bad_type = Evidence(
        organization_id=org_id,
        incident_id=inc_id,
        evidence_type="INVALID_TYPE",
        source="test",
        title="Bad Type",
        evidence_hash=uuid.uuid4().hex,
    )
    db_session.add(ev_bad_type)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()

    # 2. Check constraint: invalid reliability rejected
    ev_bad_rel = Evidence(
        organization_id=org_id,
        incident_id=inc_id,
        evidence_type="LOG",
        source="test",
        title="Bad Reliability",
        reliability="INVALID",
        evidence_hash=uuid.uuid4().hex,
    )
    db_session.add(ev_bad_rel)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()

    # 3. Unique constraint: duplicate hash in same tenant rejected at DB level
    dup_hash = uuid.uuid4().hex
    ev1 = Evidence(
        organization_id=org_id,
        incident_id=inc_id,
        evidence_type="LOG",
        source="test",
        title="First Evidence",
        evidence_hash=dup_hash,
    )
    db_session.add(ev1)
    await db_session.commit()

    ev2 = Evidence(
        organization_id=org_id,
        incident_id=inc_id,
        evidence_type="LOG",
        source="test",
        title="Second Evidence Duplicate Hash",
        evidence_hash=dup_hash,
    )
    db_session.add(ev2)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()
