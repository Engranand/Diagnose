"""Tests for strict tenant isolation across organizations."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.roles import Role
from tests.factories import (
    auth_headers_for,
    create_test_organization,
    create_test_user,
)


@pytest.mark.asyncio
async def test_admin_cannot_access_other_organization_users(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Admin of Org A must not see users of Org B in GET /api/v1/users."""
    org_a = await create_test_organization(db_session, name="Org Alpha")
    org_b = await create_test_organization(db_session, name="Org Beta")

    admin_a = await create_test_user(
        db_session, org_a.id, email="admin.a@alpha.local", role=Role.ADMIN
    )
    user_b = await create_test_user(
        db_session, org_b.id, email="member.b@beta.local", role=Role.ENGINEER
    )

    # Admin A requests user list
    response = await client.get(
        "/api/v1/users",
        headers=auth_headers_for(admin_a),
    )
    assert response.status_code == 200
    returned_emails = [u["email"] for u in response.json()]
    assert "admin.a@alpha.local" in returned_emails
    # Must NOT contain Org B user
    assert "member.b@beta.local" not in returned_emails


@pytest.mark.asyncio
async def test_admin_cannot_modify_other_organization_user(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Admin of Org A updating a user ID in Org B must receive 404 (non-disclosure)."""
    org_a = await create_test_organization(db_session, name="Org Alpha")
    org_b = await create_test_organization(db_session, name="Org Beta")

    admin_a = await create_test_user(db_session, org_a.id, role=Role.ADMIN)
    user_b = await create_test_user(
        db_session, org_b.id, role=Role.ENGINEER, full_name="Original Name"
    )

    response = await client.patch(
        f"/api/v1/users/{user_b.id}",
        headers=auth_headers_for(admin_a),
        json={"full_name": "Tampered Name"},
    )

    # Must return 404 NOT_FOUND — to Admin A, user_b does not exist
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"

    # Verify user_b was untouched
    await db_session.refresh(user_b)
    assert user_b.full_name == "Original Name"


@pytest.mark.asyncio
async def test_created_user_is_strictly_bound_to_jwt_organization(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Even if an attacker supplies organization_id in payloads, the JWT org rules."""
    org_a = await create_test_organization(db_session, name="Org Alpha")
    org_b = await create_test_organization(db_session, name="Org Beta")

    admin_a = await create_test_user(db_session, org_a.id, role=Role.ADMIN)

    # Attempt to pass an arbitrary organization_id in request body
    response = await client.post(
        "/api/v1/users",
        headers=auth_headers_for(admin_a),
        json={
            "email": "victim@beta.local",
            "password": "Password123!",
            "role": "ENGINEER",
            "organization_id": str(org_b.id),  # Malicious attempt
        },
    )

    assert response.status_code == 201
    created_data = response.json()
    # The created user MUST belong to Org A, never Org B!
    assert created_data["organization_id"] == str(org_a.id)
    assert created_data["organization_id"] != str(org_b.id)
