"""Tests for audit trail recording and secret hygiene."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.roles import Role
from diagnose.models.audit_log import AuditLog
from tests.factories import (
    auth_headers_for,
    create_test_organization,
    create_test_user,
)


@pytest.mark.asyncio
async def test_audit_recorded_on_user_creation_without_secrets(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """User creation must produce an audit record that contains zero secrets."""
    org = await create_test_organization(db_session)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    raw_password = "SuperSecretPassword123!"
    create_res = await client.post(
        "/api/v1/users",
        headers=auth_headers_for(admin),
        json={
            "email": "audit.test@example.com",
            "password": raw_password,
            "role": "ENGINEER",
            "full_name": "Audit Test",
        },
    )
    assert create_res.status_code == 201
    created_id = create_res.json()["id"]

    # Verify audit log in DB
    stmt = (
        select(AuditLog)
        .where(
            AuditLog.organization_id == org.id,
            AuditLog.entity_id == created_id,
            AuditLog.action == "USER_CREATED",
        )
    )
    result = await db_session.execute(stmt)
    audit = result.scalar_one_or_none()

    assert audit is not None
    assert audit.actor_user_id == admin.id
    assert audit.entity_type == "USER"
    assert audit.new_values is not None
    assert audit.new_values["email"] == "audit.test@example.com"
    assert audit.new_values["role"] == "ENGINEER"

    # CRITICAL: Verify NO passwords, hashes or tokens anywhere in audit log
    audit_str = str(audit.new_values) + str(audit.old_values)
    assert raw_password not in audit_str
    assert "password" not in audit.new_values
    assert "hashed_password" not in audit.new_values


@pytest.mark.asyncio
async def test_audit_recorded_on_role_change_and_deactivation(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Role modification and deactivation emit specialized audit actions."""
    org = await create_test_organization(db_session)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)
    target = await create_test_user(db_session, org.id, role=Role.VIEWER)

    # 1. Change role to RESPONDER
    res1 = await client.patch(
        f"/api/v1/users/{target.id}",
        headers=auth_headers_for(admin),
        json={"role": "RESPONDER"},
    )
    assert res1.status_code == 200

    stmt1 = select(AuditLog).where(
        AuditLog.organization_id == org.id,
        AuditLog.entity_id == target.id,
        AuditLog.action == "USER_ROLE_CHANGED",
    )
    audit1 = (await db_session.execute(stmt1)).scalar_one_or_none()
    assert audit1 is not None
    assert audit1.old_values["role"] == Role.VIEWER.value
    assert audit1.new_values["role"] == Role.RESPONDER.value

    # 2. Deactivate user
    res2 = await client.patch(
        f"/api/v1/users/{target.id}",
        headers=auth_headers_for(admin),
        json={"is_active": False},
    )
    assert res2.status_code == 200

    stmt2 = select(AuditLog).where(
        AuditLog.organization_id == org.id,
        AuditLog.entity_id == target.id,
        AuditLog.action == "USER_DEACTIVATED",
    )
    audit2 = (await db_session.execute(stmt2)).scalar_one_or_none()
    assert audit2 is not None
    assert audit2.old_values["is_active"] is True
    assert audit2.new_values["is_active"] is False


@pytest.mark.asyncio
async def test_audit_recorded_on_organization_update(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Updating organization emits ORGANIZATION_UPDATED audit record."""
    org = await create_test_organization(db_session, name="Alpha Co")
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    res = await client.patch(
        "/api/v1/organizations/me",
        headers=auth_headers_for(admin),
        json={"name": "Alpha Corp International"},
    )
    assert res.status_code == 200

    stmt = select(AuditLog).where(
        AuditLog.organization_id == org.id,
        AuditLog.entity_id == org.id,
        AuditLog.action == "ORGANIZATION_UPDATED",
    )
    audit = (await db_session.execute(stmt)).scalar_one_or_none()
    assert audit is not None
    assert audit.actor_user_id == admin.id
    assert audit.old_values["name"] == "Alpha Co"
    assert audit.new_values["name"] == "Alpha Corp International"
