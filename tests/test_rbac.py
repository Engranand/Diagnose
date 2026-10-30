"""Tests for Role-Based Access Control (RBAC)."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.roles import (
    ROLE_PERMISSIONS,
    Permission,
    Role,
    has_permission,
)
from tests.factories import (
    auth_headers_for,
    create_test_organization,
    create_test_user,
)


def test_domain_rbac_matrix_complete() -> None:
    """Verify domain permission matrix matches specifications."""
    # ADMIN has all permissions
    for perm in Permission:
        assert has_permission(Role.ADMIN, perm)

    # ENGINEER permissions
    assert has_permission(Role.ENGINEER, Permission.CREATE_INCIDENT)
    assert has_permission(Role.ENGINEER, Permission.TRANSITION_INCIDENT)
    assert has_permission(Role.ENGINEER, Permission.CLOSE_INCIDENT)
    assert has_permission(Role.ENGINEER, Permission.ADD_EVIDENCE)
    assert has_permission(Role.ENGINEER, Permission.MANAGE_SERVICES)
    assert has_permission(Role.ENGINEER, Permission.VIEW_INCIDENTS)
    assert not has_permission(Role.ENGINEER, Permission.MANAGE_ORGANIZATION)
    assert not has_permission(Role.ENGINEER, Permission.MANAGE_USERS)
    assert not has_permission(Role.ENGINEER, Permission.VIEW_AUDIT_LOGS)

    # RESPONDER permissions
    assert has_permission(Role.RESPONDER, Permission.CREATE_INCIDENT)
    assert has_permission(Role.RESPONDER, Permission.TRANSITION_INCIDENT)
    assert has_permission(Role.RESPONDER, Permission.ADD_EVIDENCE)
    assert has_permission(Role.RESPONDER, Permission.VIEW_INCIDENTS)
    assert not has_permission(Role.RESPONDER, Permission.CLOSE_INCIDENT)
    assert not has_permission(Role.RESPONDER, Permission.MANAGE_ORGANIZATION)
    assert not has_permission(Role.RESPONDER, Permission.MANAGE_USERS)

    # VIEWER permissions
    assert has_permission(Role.VIEWER, Permission.VIEW_INCIDENTS)
    assert not has_permission(Role.VIEWER, Permission.CREATE_INCIDENT)
    assert not has_permission(Role.VIEWER, Permission.MANAGE_ORGANIZATION)
    assert not has_permission(Role.VIEWER, Permission.MANAGE_USERS)


@pytest.mark.asyncio
async def test_admin_can_manage_organization(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    org = await create_test_organization(db_session, name="Old Name")
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    response = await client.patch(
        "/api/v1/organizations/me",
        headers=auth_headers_for(admin),
        json={"name": "New Name Updated"},
    )
    assert response.status_code == 200
    assert response.json()["name"] == "New Name Updated"


@pytest.mark.asyncio
@pytest.mark.parametrize("role", [Role.ENGINEER, Role.RESPONDER, Role.VIEWER])
async def test_non_admin_cannot_manage_organization(
    client: AsyncClient, db_session: AsyncSession, role: Role
) -> None:
    org = await create_test_organization(db_session)
    user = await create_test_user(db_session, org.id, role=role)

    response = await client.patch(
        "/api/v1/organizations/me",
        headers=auth_headers_for(user),
        json={"name": "Should Fail"},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_admin_can_list_and_create_users(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    org = await create_test_organization(db_session)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    # Create new user
    create_res = await client.post(
        "/api/v1/users",
        headers=auth_headers_for(admin),
        json={
            "email": "new.member@demo.local",
            "password": "StrongPassword123!",
            "role": "ENGINEER",
            "full_name": "New Member",
        },
    )
    assert create_res.status_code == 201
    assert create_res.json()["email"] == "new.member@demo.local"
    assert create_res.json()["role"] == "ENGINEER"

    # List users
    list_res = await client.get(
        "/api/v1/users",
        headers=auth_headers_for(admin),
    )
    assert list_res.status_code == 200
    emails = [u["email"] for u in list_res.json()]
    assert "new.member@demo.local" in emails


@pytest.mark.asyncio
@pytest.mark.parametrize("role", [Role.ENGINEER, Role.RESPONDER, Role.VIEWER])
async def test_non_admin_cannot_manage_users(
    client: AsyncClient, db_session: AsyncSession, role: Role
) -> None:
    org = await create_test_organization(db_session)
    user = await create_test_user(db_session, org.id, role=role)

    # Cannot list users
    list_res = await client.get(
        "/api/v1/users",
        headers=auth_headers_for(user),
    )
    assert list_res.status_code == 403
    assert list_res.json()["error"]["code"] == "FORBIDDEN"

    # Cannot create user
    create_res = await client.post(
        "/api/v1/users",
        headers=auth_headers_for(user),
        json={
            "email": "unauthorized@demo.local",
            "password": "Password123!",
            "role": "VIEWER",
        },
    )
    assert create_res.status_code == 403
    assert create_res.json()["error"]["code"] == "FORBIDDEN"
