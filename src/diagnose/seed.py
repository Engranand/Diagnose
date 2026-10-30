"""Development-only database seeder.

DO NOT RUN IN PRODUCTION.
Creates demo organization and users with standard development passwords.
"""

from __future__ import annotations

import asyncio
from typing import NamedTuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.core.security import hash_password
from diagnose.db.session import create_engine, create_session_factory
from diagnose.domain.roles import Role
from diagnose.domain.services import ServiceTier
from diagnose.models.organization import Organization
from diagnose.models.service import Service
from diagnose.models.user import User
from diagnose.settings import get_settings


class DemoUserSpec(NamedTuple):
    email: str
    password: str
    role: Role
    full_name: str


class DemoServiceSpec(NamedTuple):
    name: str
    slug: str
    description: str
    tier: ServiceTier


DEMO_SERVICES: list[DemoServiceSpec] = [
    DemoServiceSpec(
        name="Payment Gateway API",
        slug="payment-api",
        description="Processes inbound and outbound credit card & ACH transactions",
        tier=ServiceTier.CRITICAL,
    ),
    DemoServiceSpec(
        name="Authentication Service",
        slug="auth-service",
        description="Provides identity, token generation, and single sign-on",
        tier=ServiceTier.CRITICAL,
    ),
    DemoServiceSpec(
        name="Frontend Web Application",
        slug="frontend-web",
        description="Primary customer web dashboard and user portal",
        tier=ServiceTier.HIGH,
    ),
    DemoServiceSpec(
        name="Notification Service",
        slug="notification-service",
        description="Delivers transactional emails, SMS, and webhook alerts",
        tier=ServiceTier.MEDIUM,
    ),
]


DEMO_USERS: list[DemoUserSpec] = [
    DemoUserSpec(
        email="admin@demo.local",
        password="DemoAdmin123!",
        role=Role.ADMIN,
        full_name="Demo Admin",
    ),
    DemoUserSpec(
        email="engineer@demo.local",
        password="DemoEng123!",
        role=Role.ENGINEER,
        full_name="Demo Engineer",
    ),
    DemoUserSpec(
        email="responder@demo.local",
        password="DemoResp123!",
        role=Role.RESPONDER,
        full_name="Demo Responder",
    ),
    DemoUserSpec(
        email="viewer@demo.local",
        password="DemoView123!",
        role=Role.VIEWER,
        full_name="Demo Viewer",
    ),
]


async def seed_development_data(session: AsyncSession) -> Organization:
    """Idempotently seed Demo Organization and initial users."""
    # 1. Ensure Demo Organization
    stmt = select(Organization).where(Organization.slug == "demo")
    result = await session.execute(stmt)
    org = result.scalar_one_or_none()

    if org is None:
        org = Organization(name="Demo Organization", slug="demo", is_active=True)
        session.add(org)
        await session.flush()
        print(f"[Seed] Created Organization: '{org.name}' ({org.id})")
    else:
        print(f"[Seed] Organization already exists: '{org.name}' ({org.id})")

    # 2. Seed Users
    for spec in DEMO_USERS:
        user_stmt = select(User).where(
            User.organization_id == org.id, User.email == spec.email
        )
        user_result = await session.execute(user_stmt)
        user = user_result.scalar_one_or_none()

        if user is None:
            user = User(
                organization_id=org.id,
                email=spec.email,
                hashed_password=hash_password(spec.password),
                full_name=spec.full_name,
                role=spec.role.value,
                is_active=True,
            )
            session.add(user)
            print(f"[Seed] Created User: {spec.email} [{spec.role.value}]")
        else:
            print(f"[Seed] User already exists: {spec.email}")

    # 3. Seed Services
    for svc_spec in DEMO_SERVICES:
        svc_stmt = select(Service).where(
            Service.organization_id == org.id, Service.slug == svc_spec.slug
        )
        svc_result = await session.execute(svc_stmt)
        svc = svc_result.scalar_one_or_none()

        if svc is None:
            svc = Service(
                organization_id=org.id,
                name=svc_spec.name,
                slug=svc_spec.slug,
                description=svc_spec.description,
                tier=svc_spec.tier.value,
                is_active=True,
            )
            session.add(svc)
            print(f"[Seed] Created Service: {svc_spec.slug} [{svc_spec.tier.value}]")
        else:
            print(f"[Seed] Service already exists: {svc_spec.slug}")

    await session.commit()
    print("[Seed] Seeding completed successfully.")
    return org


async def main() -> None:
    settings = get_settings()
    if settings.ENVIRONMENT == "production":
        print("[Error] Seeding cannot be executed in production environment!")
        return

    engine = create_engine(settings)
    session_factory = create_session_factory(engine)

    async with session_factory() as session:
        await seed_development_data(session)

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
