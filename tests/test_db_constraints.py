"""Tests for PostgreSQL schema constraints and database integrity."""

from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.core.security import hash_password
from diagnose.models.organization import Organization
from diagnose.models.user import User
from tests.factories import create_test_organization


@pytest.mark.asyncio
async def test_duplicate_organization_slug_raises_integrity_error(
    db_session: AsyncSession,
) -> None:
    """Duplicate organization slug must trigger unique constraint violation."""
    import uuid
    unique_slug = f"unique-slug-{uuid.uuid4().hex}"
    await create_test_organization(db_session, slug=unique_slug)

    with pytest.raises(IntegrityError):
        dup_org = Organization(name="Another Org", slug=unique_slug)
        db_session.add(dup_org)
        await db_session.commit()

    await db_session.rollback()


@pytest.mark.asyncio
async def test_duplicate_email_in_same_organization_raises_integrity_error(
    db_session: AsyncSession,
) -> None:
    """Email uniqueness scoped to organization must prevent duplicates."""
    org = await create_test_organization(db_session)

    user1 = User(
        organization_id=org.id,
        email="shared@example.com",
        hashed_password=hash_password("pwd"),
        role="ENGINEER",
    )
    db_session.add(user1)
    await db_session.commit()

    with pytest.raises(IntegrityError):
        user2 = User(
            organization_id=org.id,
            email="shared@example.com",
            hashed_password=hash_password("pwd"),
            role="VIEWER",
        )
        db_session.add(user2)
        await db_session.commit()

    await db_session.rollback()


@pytest.mark.asyncio
async def test_same_email_in_different_organizations_is_allowed(
    db_session: AsyncSession,
) -> None:
    """Same email in two distinct organizations must succeed."""
    org1 = await create_test_organization(db_session)
    org2 = await create_test_organization(db_session)

    user1 = User(
        organization_id=org1.id,
        email="multi.org@example.com",
        hashed_password=hash_password("pwd"),
        role="ENGINEER",
    )
    user2 = User(
        organization_id=org2.id,
        email="multi.org@example.com",
        hashed_password=hash_password("pwd"),
        role="ADMIN",
    )
    db_session.add_all([user1, user2])
    await db_session.commit()

    assert user1.id != user2.id


@pytest.mark.asyncio
async def test_invalid_role_triggers_check_constraint(
    db_session: AsyncSession,
) -> None:
    """Inserting an invalid role string must trigger check constraint."""
    org = await create_test_organization(db_session)

    with pytest.raises(IntegrityError):
        invalid_user = User(
            organization_id=org.id,
            email="invalid.role@example.com",
            hashed_password=hash_password("pwd"),
            role="SUPERUSER",  # Not in valid enum
        )
        db_session.add(invalid_user)
        await db_session.commit()

    await db_session.rollback()


@pytest.mark.asyncio
async def test_empty_organization_name_triggers_check_constraint(
    db_session: AsyncSession,
) -> None:
    """Empty organization name must trigger check constraint."""
    with pytest.raises(IntegrityError):
        invalid_org = Organization(name="", slug="valid-slug")
        db_session.add(invalid_org)
        await db_session.commit()

    await db_session.rollback()
