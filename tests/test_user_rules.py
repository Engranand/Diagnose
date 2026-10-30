"""Tests for user rules, role modifications, and self-update limitations."""

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
async def test_admin_cannot_modify_own_role(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An admin must not be permitted to demote or alter their own role."""
    org = await create_test_organization(db_session)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    response = await client.patch(
        f"/api/v1/users/{admin.id}",
        headers=auth_headers_for(admin),
        json={"role": "VIEWER"},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"

    # Confirm role was not altered
    await db_session.refresh(admin)
    assert admin.role == Role.ADMIN.value


@pytest.mark.asyncio
async def test_user_self_update_cannot_alter_role_or_org(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """PATCH /users/me only accepts profile updates (full_name), ignoring or rejecting role/org."""
    org = await create_test_organization(db_session)
    user = await create_test_user(
        db_session, org.id, role=Role.ENGINEER, full_name="Original Name"
    )

    response = await client.patch(
        "/api/v1/users/me",
        headers=auth_headers_for(user),
        json={
            "full_name": "Updated Name",
            "role": "ADMIN",  # Should be ignored / schema ignores extra
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["full_name"] == "Updated Name"
    # Role remains unchanged
    assert data["role"] == Role.ENGINEER.value
    assert data["organization_id"] == str(org.id)

    await db_session.refresh(user)
    assert user.role == Role.ENGINEER.value
    assert user.full_name == "Updated Name"


@pytest.mark.asyncio
async def test_admin_can_deactivate_and_reactivate_user(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Deactivated users must be blocked from logging in immediately."""
    org = await create_test_organization(db_session)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)
    target_pwd = "TargetPassword123!"
    target = await create_test_user(
        db_session, org.id, role=Role.RESPONDER, password=target_pwd
    )

    # 1. Deactivate target user
    deact_res = await client.patch(
        f"/api/v1/users/{target.id}",
        headers=auth_headers_for(admin),
        json={"is_active": False},
    )
    assert deact_res.status_code == 200
    assert deact_res.json()["is_active"] is False

    # 2. Deactivated user cannot authenticate
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": target.email, "password": target_pwd},
    )
    assert login_res.status_code == 401

    # 3. Reactivate target user
    react_res = await client.patch(
        f"/api/v1/users/{target.id}",
        headers=auth_headers_for(admin),
        json={"is_active": True},
    )
    assert react_res.status_code == 200
    assert react_res.json()["is_active"] is True

    # 4. Reactivated user can authenticate again
    login_ok = await client.post(
        "/api/v1/auth/login",
        json={"email": target.email, "password": target_pwd},
    )
    assert login_ok.status_code == 200
    assert "access_token" in login_ok.json()
