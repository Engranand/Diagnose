"""User repository."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.models.user import User


class UserRepository:
    """Data-access methods for User entities with strict tenant boundaries."""

    async def get_by_id(
        self,
        session: AsyncSession,
        user_id: UUID,
        organization_id: UUID | None = None,
    ) -> User | None:
        """Fetch a user by ID, optionally scoped to an organization."""
        stmt = select(User).where(User.id == user_id)
        if organization_id is not None:
            stmt = stmt.where(User.organization_id == organization_id)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_email(
        self,
        session: AsyncSession,
        email: str,
        organization_id: UUID | None = None,
    ) -> User | None:
        """Fetch a user by email, optionally scoped to an organization."""
        stmt = select(User).where(User.email == email)
        if organization_id is not None:
            stmt = stmt.where(User.organization_id == organization_id)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_organization(
        self, session: AsyncSession, organization_id: UUID
    ) -> list[User]:
        """List all users belonging strictly to the specified organization."""
        stmt = (
            select(User)
            .where(User.organization_id == organization_id)
            .order_by(User.created_at.asc())
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())

    async def create(self, session: AsyncSession, user: User) -> User:
        """Add and flush a new user within the session."""
        session.add(user)
        await session.flush()
        return user
