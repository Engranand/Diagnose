"""Tests for authentication and JWT handling."""

from __future__ import annotations

from datetime import timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.core.security import create_access_token
from diagnose.domain.roles import Role
from tests.factories import (
    auth_headers_for,
    create_test_organization,
    create_test_user,
)


@pytest.mark.asyncio
async def test_login_success(client: AsyncClient, db_session: AsyncSession) -> None:
    org = await create_test_organization(db_session)
    password = "CorrectPassword123!"
    user = await create_test_user(
        db_session, organization_id=org.id, password=password, role=Role.ENGINEER
    )

    response = await client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": password},
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_invalid_password(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    org = await create_test_organization(db_session)
    user = await create_test_user(
        db_session, organization_id=org.id, password="SecretPassword123!"
    )

    response = await client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": "WrongPassword!"},
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"


@pytest.mark.asyncio
async def test_login_nonexistent_user(client: AsyncClient) -> None:
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@example.com", "password": "AnyPassword123!"},
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"


@pytest.mark.asyncio
async def test_login_inactive_user_rejected(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    org = await create_test_organization(db_session)
    password = "Password123!"
    user = await create_test_user(
        db_session,
        organization_id=org.id,
        password=password,
        is_active=False,
    )

    response = await client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": password},
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"


@pytest.mark.asyncio
async def test_get_me_success(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    org = await create_test_organization(db_session)
    user = await create_test_user(
        db_session,
        organization_id=org.id,
        role=Role.ENGINEER,
        full_name="Alice Engineer",
    )
    headers = auth_headers_for(user)

    response = await client.get("/api/v1/users/me", headers=headers)

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(user.id)
    assert data["email"] == user.email
    assert data["role"] == Role.ENGINEER.value
    assert data["organization_id"] == str(org.id)
    assert data["full_name"] == "Alice Engineer"


@pytest.mark.asyncio
async def test_get_me_unauthenticated(client: AsyncClient) -> None:
    response = await client.get("/api/v1/users/me")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"


@pytest.mark.asyncio
async def test_get_me_invalid_token(client: AsyncClient) -> None:
    headers = {"Authorization": "Bearer not-a-valid-jwt-token"}
    response = await client.get("/api/v1/users/me", headers=headers)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"


@pytest.mark.asyncio
async def test_get_me_expired_token(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    org = await create_test_organization(db_session)
    user = await create_test_user(db_session, organization_id=org.id)

    # Token with negative expiry
    expired_token = create_access_token(
        user_id=user.id,
        organization_id=user.organization_id,
        role=user.role,
        expires_delta=timedelta(seconds=-10),
    )

    response = await client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"
    assert "expired" in response.json()["error"]["message"].lower()
