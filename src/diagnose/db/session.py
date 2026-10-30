"""Async SQLAlchemy engine and session factory.

Both are created from application :class:`~diagnose.settings.Settings` so
that the connection pool parameters and database URL are centralised.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from diagnose.settings import Settings


def create_engine(settings: Settings) -> AsyncEngine:
    """Build an :class:`AsyncEngine` from application settings."""
    return create_async_engine(
        settings.DATABASE_URL,
        pool_size=settings.DATABASE_POOL_SIZE,
        max_overflow=settings.DATABASE_MAX_OVERFLOW,
        echo=settings.DATABASE_ECHO,
    )


def create_session_factory(
    engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    """Build a session factory bound to *engine*."""
    return async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
