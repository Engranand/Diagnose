"""Shared FastAPI dependencies (dependency-injection functions).

These are used by route handlers to obtain database sessions, the current
authenticated user, the active organisation context, etc.

In M1 only the database-session dependency is implemented.
Auth and tenant-scoping dependencies will be added in M2.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession


async def get_db(request: Request) -> AsyncGenerator[AsyncSession, None]:
    """Yield a scoped async database session and ensure it is closed."""
    session_factory = request.app.state.db_session_factory
    async with session_factory() as session:
        try:
            yield session
        finally:
            await session.close()
