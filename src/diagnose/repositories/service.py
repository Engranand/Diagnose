"""Repository for Service data access."""

from __future__ import annotations

import uuid
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.models.service import Service


class ServiceRepository:
    """Tenant-scoped repository for services."""

    async def create(self, session: AsyncSession, service: Service) -> Service:
        """Add a new service entity to the session."""
        session.add(service)
        await session.flush()
        return service

    async def get_by_id(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        service_id: uuid.UUID,
    ) -> Service | None:
        """Find a service by ID strictly within an organization."""
        query = select(Service).where(
            Service.organization_id == organization_id,
            Service.id == service_id,
        )
        result = await session.execute(query)
        return result.scalar_one_or_none()

    async def get_by_slug(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        slug: str,
    ) -> Service | None:
        """Find a service by slug within an organization."""
        query = select(Service).where(
            Service.organization_id == organization_id,
            Service.slug == slug,
        )
        result = await session.execute(query)
        return result.scalar_one_or_none()

    async def list_by_organization(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        is_active: bool | None = None,
        tier: str | None = None,
    ) -> Sequence[Service]:
        """List services belonging to an organization, optionally filtered."""
        query = select(Service).where(Service.organization_id == organization_id)
        if is_active is not None:
            query = query.where(Service.is_active == is_active)
        if tier is not None:
            query = query.where(Service.tier == tier)
        query = query.order_by(Service.name.asc())
        result = await session.execute(query)
        return result.scalars().all()
