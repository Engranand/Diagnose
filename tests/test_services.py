"""Tests for Service catalog entity, RBAC, tenant isolation, and audit logging."""

from __future__ import annotations

import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.roles import Role
from diagnose.domain.services import ServiceTier
from diagnose.models.audit_log import AuditLog
from diagnose.models.organization import Organization
from diagnose.models.service import Service
from tests.factories import (
    auth_headers_for,
    create_test_organization,
    create_test_service,
    create_test_user,
)


@pytest.mark.asyncio
async def test_admin_can_create_service(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """ADMIN role can successfully create a service."""
    org = await create_test_organization(db_session)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    payload = {
        "name": "Payment Gateway",
        "slug": f"payment-gateway-{uuid.uuid4().hex[:6]}",
        "description": "Core payment service",
        "tier": "CRITICAL",
    }
    response = await client.post(
        "/api/v1/services",
        json=payload,
        headers=auth_headers_for(admin),
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == payload["name"]
    assert data["slug"] == payload["slug"]
    assert data["tier"] == "CRITICAL"
    assert data["is_active"] is True
    assert data["organization_id"] == str(org.id)


@pytest.mark.asyncio
async def test_engineer_can_create_service(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """ENGINEER role can successfully create a service."""
    org = await create_test_organization(db_session)
    engineer = await create_test_user(db_session, org.id, role=Role.ENGINEER)

    payload = {
        "name": "Auth Service",
        "slug": f"auth-service-{uuid.uuid4().hex[:6]}",
        "tier": "HIGH",
    }
    response = await client.post(
        "/api/v1/services",
        json=payload,
        headers=auth_headers_for(engineer),
    )
    assert response.status_code == 201
    assert response.json()["slug"] == payload["slug"]


@pytest.mark.asyncio
async def test_responder_cannot_create_service_403(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """RESPONDER cannot create services (403 Forbidden)."""
    org = await create_test_organization(db_session)
    responder = await create_test_user(db_session, org.id, role=Role.RESPONDER)

    response = await client.post(
        "/api/v1/services",
        json={"name": "Test Service", "slug": "test-svc", "tier": "LOW"},
        headers=auth_headers_for(responder),
    )
    assert response.status_code == 403
    assert "manage:services" in response.json()["error"]["message"]


@pytest.mark.asyncio
async def test_viewer_cannot_create_service_403(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """VIEWER cannot create services (403 Forbidden)."""
    org = await create_test_organization(db_session)
    viewer = await create_test_user(db_session, org.id, role=Role.VIEWER)

    response = await client.post(
        "/api/v1/services",
        json={"name": "Test Service", "slug": "test-svc", "tier": "LOW"},
        headers=auth_headers_for(viewer),
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_unauthenticated_cannot_create_service_401(client: AsyncClient) -> None:
    """Unauthenticated requests cannot create services (401 Unauthorized)."""
    response = await client.post(
        "/api/v1/services",
        json={"name": "Test Service", "slug": "test-svc", "tier": "LOW"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_all_authenticated_roles_can_view_services(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """All authenticated roles (ADMIN, ENGINEER, RESPONDER, VIEWER) can view services."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id, name="Shared Catalog Service")

    for role in [Role.ADMIN, Role.ENGINEER, Role.RESPONDER, Role.VIEWER]:
        user = await create_test_user(db_session, org.id, role=role)
        # List
        list_resp = await client.get(
            "/api/v1/services",
            headers=auth_headers_for(user),
        )
        assert list_resp.status_code == 200
        service_ids = [s["id"] for s in list_resp.json()]
        assert str(svc.id) in service_ids

        # Get by ID
        get_resp = await client.get(
            f"/api/v1/services/{svc.id}",
            headers=auth_headers_for(user),
        )
        assert get_resp.status_code == 200
        assert get_resp.json()["name"] == "Shared Catalog Service"


@pytest.mark.asyncio
async def test_service_list_is_strictly_tenant_scoped(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Services belonging to Org B must NEVER appear in Org A's service list."""
    org_a = await create_test_organization(db_session, name="Org A")
    org_b = await create_test_organization(db_session, name="Org B")

    svc_a = await create_test_service(db_session, org_a.id, name="Service A")
    svc_b = await create_test_service(db_session, org_b.id, name="Service B")

    user_a = await create_test_user(db_session, org_a.id, role=Role.ADMIN)

    response = await client.get(
        "/api/v1/services",
        headers=auth_headers_for(user_a),
    )
    assert response.status_code == 200
    returned_ids = [s["id"] for s in response.json()]
    assert str(svc_a.id) in returned_ids
    assert str(svc_b.id) not in returned_ids


@pytest.mark.asyncio
async def test_cross_tenant_get_service_returns_404(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Tenant A requesting Tenant B's service by ID receives 404 Not Found."""
    org_a = await create_test_organization(db_session)
    org_b = await create_test_organization(db_session)

    svc_b = await create_test_service(db_session, org_b.id, name="Org B Secret Service")
    user_a = await create_test_user(db_session, org_a.id, role=Role.ADMIN)

    response = await client.get(
        f"/api/v1/services/{svc_b.id}",
        headers=auth_headers_for(user_a),
    )
    assert response.status_code == 404
    assert "not found" in response.json()["error"]["message"].lower()


@pytest.mark.asyncio
async def test_service_filters_by_is_active_and_tier(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Filter queries by is_active and tier work accurately."""
    org = await create_test_organization(db_session)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    s1 = await create_test_service(
        db_session, org.id, name="S1", slug=f"s1-{uuid.uuid4().hex[:6]}", tier="CRITICAL", is_active=True
    )
    s2 = await create_test_service(
        db_session, org.id, name="S2", slug=f"s2-{uuid.uuid4().hex[:6]}", tier="LOW", is_active=False
    )

    # Filter active only
    resp_active = await client.get(
        "/api/v1/services?is_active=true",
        headers=auth_headers_for(admin),
    )
    ids_active = [s["id"] for s in resp_active.json()]
    assert str(s1.id) in ids_active
    assert str(s2.id) not in ids_active

    # Filter inactive only
    resp_inactive = await client.get(
        "/api/v1/services?is_active=false",
        headers=auth_headers_for(admin),
    )
    ids_inactive = [s["id"] for s in resp_inactive.json()]
    assert str(s2.id) in ids_inactive
    assert str(s1.id) not in ids_inactive

    # Filter tier CRITICAL
    resp_crit = await client.get(
        "/api/v1/services?tier=CRITICAL",
        headers=auth_headers_for(admin),
    )
    ids_crit = [s["id"] for s in resp_crit.json()]
    assert str(s1.id) in ids_crit
    assert str(s2.id) not in ids_crit


@pytest.mark.asyncio
async def test_admin_and_engineer_can_update_service(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """ADMIN and ENGINEER can update service metadata."""
    org = await create_test_organization(db_session)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)
    engineer = await create_test_user(db_session, org.id, role=Role.ENGINEER)

    svc = await create_test_service(db_session, org.id, name="Original Name", tier="LOW")

    # Admin update
    resp_admin = await client.patch(
        f"/api/v1/services/{svc.id}",
        json={"name": "Updated by Admin", "tier": "MEDIUM"},
        headers=auth_headers_for(admin),
    )
    assert resp_admin.status_code == 200
    assert resp_admin.json()["name"] == "Updated by Admin"
    assert resp_admin.json()["tier"] == "MEDIUM"

    # Engineer update
    resp_eng = await client.patch(
        f"/api/v1/services/{svc.id}",
        json={"description": "Updated by Engineer", "tier": "HIGH"},
        headers=auth_headers_for(engineer),
    )
    assert resp_eng.status_code == 200
    assert resp_eng.json()["description"] == "Updated by Engineer"
    assert resp_eng.json()["tier"] == "HIGH"


@pytest.mark.asyncio
async def test_responder_and_viewer_cannot_update_service_403(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """RESPONDER and VIEWER receive 403 Forbidden on update."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)

    responder = await create_test_user(db_session, org.id, role=Role.RESPONDER)
    viewer = await create_test_user(db_session, org.id, role=Role.VIEWER)

    for user in [responder, viewer]:
        resp = await client.patch(
            f"/api/v1/services/{svc.id}",
            json={"name": "Hacked Name"},
            headers=auth_headers_for(user),
        )
        assert resp.status_code == 403


@pytest.mark.asyncio
async def test_cross_tenant_patch_returns_404(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Tenant A cannot modify Tenant B's service (returns 404)."""
    org_a = await create_test_organization(db_session)
    org_b = await create_test_organization(db_session)

    svc_b = await create_test_service(db_session, org_b.id, name="Org B Service")
    user_a = await create_test_user(db_session, org_a.id, role=Role.ADMIN)

    response = await client.patch(
        f"/api/v1/services/{svc_b.id}",
        json={"name": "Unauthorized Modify Attempt"},
        headers=auth_headers_for(user_a),
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_admin_and_engineer_can_deactivate_service(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Deactivation via is_active=false succeeds for ADMIN and ENGINEER."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id, is_active=True)

    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    resp = await client.patch(
        f"/api/v1/services/{svc.id}",
        json={"is_active": False},
        headers=auth_headers_for(admin),
    )
    assert resp.status_code == 200
    assert resp.json()["is_active"] is False


@pytest.mark.asyncio
async def test_duplicate_slug_same_organization_returns_409(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Registering a service with an existing slug in the same organization yields 409 Conflict."""
    org = await create_test_organization(db_session)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    slug = f"unique-svc-{uuid.uuid4().hex[:6]}"
    await create_test_service(db_session, org.id, slug=slug)

    response = await client.post(
        "/api/v1/services",
        json={"name": "Duplicate Slug Service", "slug": slug, "tier": "MEDIUM"},
        headers=auth_headers_for(admin),
    )
    assert response.status_code == 409
    assert "already exists" in response.json()["error"]["message"]


@pytest.mark.asyncio
async def test_same_slug_different_organizations_allowed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The same slug can exist concurrently across different organizations."""
    org_a = await create_test_organization(db_session)
    org_b = await create_test_organization(db_session)

    admin_a = await create_test_user(db_session, org_a.id, role=Role.ADMIN)
    admin_b = await create_test_user(db_session, org_b.id, role=Role.ADMIN)

    shared_slug = f"shared-slug-{uuid.uuid4().hex[:6]}"

    resp_a = await client.post(
        "/api/v1/services",
        json={"name": "Org A Service", "slug": shared_slug, "tier": "HIGH"},
        headers=auth_headers_for(admin_a),
    )
    assert resp_a.status_code == 201

    resp_b = await client.post(
        "/api/v1/services",
        json={"name": "Org B Service", "slug": shared_slug, "tier": "LOW"},
        headers=auth_headers_for(admin_b),
    )
    assert resp_b.status_code == 201


@pytest.mark.asyncio
async def test_validation_errors_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Invalid input payloads return 422 Unprocessable Entity."""
    org = await create_test_organization(db_session)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    # Empty name
    r1 = await client.post(
        "/api/v1/services",
        json={"name": "   ", "slug": "valid-slug", "tier": "MEDIUM"},
        headers=auth_headers_for(admin),
    )
    assert r1.status_code == 422

    # Invalid slug (uppercase, spaces)
    r2 = await client.post(
        "/api/v1/services",
        json={"name": "Valid Name", "slug": "INVALID SLUG!", "tier": "MEDIUM"},
        headers=auth_headers_for(admin),
    )
    assert r2.status_code == 422

    # Invalid tier
    r3 = await client.post(
        "/api/v1/services",
        json={"name": "Valid Name", "slug": "valid-slug", "tier": "ULTRA"},
        headers=auth_headers_for(admin),
    )
    assert r3.status_code == 422


@pytest.mark.asyncio
async def test_client_organization_id_ignored_on_create(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Client attempting to inject another organization_id is ignored; tenant from token is used."""
    org_a = await create_test_organization(db_session)
    org_b = await create_test_organization(db_session)

    admin_a = await create_test_user(db_session, org_a.id, role=Role.ADMIN)

    slug = f"spoof-svc-{uuid.uuid4().hex[:6]}"
    response = await client.post(
        "/api/v1/services",
        json={
            "name": "Spoofed Service",
            "slug": slug,
            "tier": "MEDIUM",
            "organization_id": str(org_b.id),
        },
        headers=auth_headers_for(admin_a),
    )
    assert response.status_code == 201
    assert response.json()["organization_id"] == str(org_a.id)


@pytest.mark.asyncio
async def test_service_lifecycle_audit_logging(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Mutations generate atomic audit log records with old and new values."""
    org = await create_test_organization(db_session)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    slug = f"audit-svc-{uuid.uuid4().hex[:6]}"

    # 1. Create
    resp_create = await client.post(
        "/api/v1/services",
        json={"name": "Audited Service", "slug": slug, "tier": "HIGH"},
        headers=auth_headers_for(admin),
    )
    assert resp_create.status_code == 201
    svc_id = uuid.UUID(resp_create.json()["id"])

    # Verify audit record for SERVICE_CREATED
    q_create = select(AuditLog).where(
        AuditLog.organization_id == org.id,
        AuditLog.entity_id == svc_id,
        AuditLog.action == "SERVICE_CREATED",
    )
    res_create = await db_session.execute(q_create)
    audit_create = res_create.scalar_one_or_none()
    assert audit_create is not None
    assert audit_create.actor_user_id == admin.id
    assert audit_create.new_values["name"] == "Audited Service"
    assert audit_create.new_values["tier"] == "HIGH"
    assert audit_create.old_values is None

    # 2. Update
    resp_update = await client.patch(
        f"/api/v1/services/{svc_id}",
        json={"name": "Renamed Service", "tier": "CRITICAL"},
        headers=auth_headers_for(admin),
    )
    assert resp_update.status_code == 200

    q_update = select(AuditLog).where(
        AuditLog.organization_id == org.id,
        AuditLog.entity_id == svc_id,
        AuditLog.action == "SERVICE_UPDATED",
    )
    res_update = await db_session.execute(q_update)
    audit_update = res_update.scalar_one_or_none()
    assert audit_update is not None
    assert audit_update.old_values["name"] == "Audited Service"
    assert audit_update.new_values["name"] == "Renamed Service"
    assert audit_update.new_values["tier"] == "CRITICAL"

    # 3. Deactivate
    resp_deact = await client.patch(
        f"/api/v1/services/{svc_id}",
        json={"is_active": False},
        headers=auth_headers_for(admin),
    )
    assert resp_deact.status_code == 200

    q_deact = select(AuditLog).where(
        AuditLog.organization_id == org.id,
        AuditLog.entity_id == svc_id,
        AuditLog.action == "SERVICE_DEACTIVATED",
    )
    res_deact = await db_session.execute(q_deact)
    audit_deact = res_deact.scalar_one_or_none()
    assert audit_deact is not None
    assert audit_deact.old_values["is_active"] is True
    assert audit_deact.new_values["is_active"] is False


@pytest.mark.asyncio
async def test_database_level_service_constraints(db_session: AsyncSession) -> None:
    """Verify PostgreSQL check constraints and uniqueness at DB level."""
    org = await create_test_organization(db_session)
    org_id = org.id

    # 1. Check constraint: invalid tier rejected by PostgreSQL
    svc_bad_tier = Service(
        organization_id=org_id,
        name="Bad Tier Svc",
        slug=f"bad-tier-{uuid.uuid4().hex[:6]}",
        tier="INVALID_TIER",
        is_active=True,
    )
    db_session.add(svc_bad_tier)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()

    # 2. Check constraint: empty name rejected by PostgreSQL
    svc_empty_name = Service(
        organization_id=org_id,
        name="",
        slug=f"empty-name-{uuid.uuid4().hex[:6]}",
        tier="MEDIUM",
        is_active=True,
    )
    db_session.add(svc_empty_name)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()

    # 3. Unique constraint: duplicate (organization_id, slug) rejected by PostgreSQL
    dup_slug = f"dup-slug-{uuid.uuid4().hex[:6]}"
    s1 = Service(
        organization_id=org_id,
        name="S1",
        slug=dup_slug,
        tier="MEDIUM",
        is_active=True,
    )
    db_session.add(s1)
    await db_session.commit()

    s2 = Service(
        organization_id=org_id,
        name="S2",
        slug=dup_slug,
        tier="HIGH",
        is_active=True,
    )
    db_session.add(s2)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()

    # 4. Foreign key cascade: deleting organization cascades to services
    org_to_delete = await create_test_organization(db_session)
    org_del_id = org_to_delete.id
    svc_to_cascade = await create_test_service(db_session, org_del_id)
    svc_id = svc_to_cascade.id

    await db_session.delete(org_to_delete)
    await db_session.commit()

    found = await db_session.get(Service, svc_id)
    assert found is None
