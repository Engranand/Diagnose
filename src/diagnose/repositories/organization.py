"""Organization repository."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.models.organization import Organization


class OrganizationRepository:
    """Data-access methods for Organization entities."""

    async def get_by_id(
        self, session: AsyncSession, org_id: UUID
    ) -> Organization | None:
        """Fetch an organization by its primary key."""
        stmt = select(Organization).where(Organization.id == org_id)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_slug(
        self, session: AsyncSession, slug: str
    ) -> Organization | None:
        """Fetch an organization by its unique slug."""
        stmt = select(Organization).where(Organization.slug == slug)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    async def create(
        self, session: AsyncSession, organization: Organization
    ) -> Organization:
        """Add and flush a new organization."""
        session.add(organization)
        await session.flush()
        return organization
