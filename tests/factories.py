"""Test data factories and helpers."""

from __future__ import annotations

import uuid
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.core.security import create_access_token, hash_password
from diagnose.domain.roles import Role
from diagnose.models.incident import Incident
from diagnose.models.organization import Organization
from diagnose.models.service import Service
from diagnose.models.user import User


async def create_test_organization(
    session: AsyncSession,
    name: str | None = None,
    slug: str | None = None,
    is_active: bool = True,
) -> Organization:
    """Create and persist an organization for tests."""
    uid = uuid.uuid4().hex[:8]
    org = Organization(
        name=name or f"Test Org {uid}",
        slug=slug or f"test-org-{uid}",
        is_active=is_active,
    )
    session.add(org)
    await session.commit()
    await session.refresh(org)
    return org


async def create_test_user(
    session: AsyncSession,
    organization_id: UUID,
    email: str | None = None,
    password: str = "TestPassword123!",
    role: Role = Role.VIEWER,
    full_name: str | None = "Test User",
    is_active: bool = True,
) -> User:
    """Create and persist a user for tests."""
    uid = uuid.uuid4().hex[:8]
    user = User(
        organization_id=organization_id,
        email=email or f"user-{uid}@example.com",
        hashed_password=hash_password(password),
        role=role.value if isinstance(role, Role) else role,
        full_name=full_name,
        is_active=is_active,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


def auth_token_for(user: User) -> str:
    """Generate a valid JWT token for a given user."""
    return create_access_token(
        user_id=user.id,
        organization_id=user.organization_id,
        role=user.role,
    )


def auth_headers_for(user: User) -> dict[str, str]:
    """Return HTTP Authorization header for the user."""
    token = auth_token_for(user)
    return {"Authorization": f"Bearer {token}"}


async def create_test_service(
    session: AsyncSession,
    organization_id: UUID,
    name: str | None = None,
    slug: str | None = None,
    tier: str = "MEDIUM",
    is_active: bool = True,
    description: str | None = "Test service description",
) -> Service:
    """Create and persist a service for tests."""
    uid = uuid.uuid4().hex[:8]
    service = Service(
        organization_id=organization_id,
        name=name or f"Test Service {uid}",
        slug=slug or f"service-{uid}",
        description=description,
        tier=tier,
        is_active=is_active,
    )
    session.add(service)
    await session.commit()
    await session.refresh(service)
    return service


async def create_test_incident(
    session: AsyncSession,
    organization_id: UUID,
    service_id: UUID,
    title: str | None = None,
    severity: str = "MEDIUM",
    status: str = "DETECTED",
    incident_number: int | None = None,
    assigned_user_id: UUID | None = None,
) -> Incident:
    """Create and persist an incident for tests."""
    uid = uuid.uuid4().hex[:8]
    if incident_number is None:
        from sqlalchemy import func, select
        num_stmt = select(func.coalesce(func.max(Incident.incident_number), 0) + 1).where(
            Incident.organization_id == organization_id
        )
        incident_number = int((await session.execute(num_stmt)).scalar_one())

    incident = Incident(
        organization_id=organization_id,
        service_id=service_id,
        incident_number=incident_number,
        title=title or f"Test Incident {uid}",
        description=f"Incident description {uid}",
        severity=severity,
        status=status,
        assigned_user_id=assigned_user_id,
        version=1,
    )
    session.add(incident)
    await session.commit()
    await session.refresh(incident)
    return incident
