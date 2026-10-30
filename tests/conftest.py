"""Shared pytest fixtures.

Provides:
- ``test_settings`` — application settings pointed at the test database and
  a dedicated Redis database (db 1).
- ``app`` — a fully-initialised FastAPI application with live DB and Redis
  connections.
- ``client`` — an async HTTPX client wired to the test application (no
  real TCP socket; uses ASGI transport).
"""

from __future__ import annotations

import pytest
import redis.asyncio as aioredis
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine

from diagnose.db.session import create_engine, create_session_factory
from diagnose.main import create_app
from diagnose.settings import Settings


@pytest.fixture()
def test_settings() -> Settings:
    """Settings targeting the test database and a separate Redis DB."""
    return Settings(
        DATABASE_URL=(
            "postgresql+asyncpg://diagnose:diagnose_dev@localhost:5432/diagnose_test"
        ),
        REDIS_URL="redis://localhost:6379/1",
        ENVIRONMENT="testing",
        DEBUG=True,
    )


@pytest.fixture()
async def app(test_settings: Settings):
    """Create the FastAPI app and initialise backing-service connections.

    Connections are torn down after each test to prevent leaking state.
    """
    application = create_app(settings=test_settings)

    # Manually replicate lifespan setup so that the ASGI transport can
    # call the app without a real ASGI server managing the lifespan.
    engine: AsyncEngine = create_engine(test_settings)
    application.state.db_engine = engine
    application.state.db_session_factory = create_session_factory(engine)
    application.state.redis = aioredis.from_url(
        test_settings.REDIS_URL, decode_responses=True
    )

    yield application

    # Teardown
    await application.state.redis.aclose()
    await engine.dispose()


@pytest.fixture()
async def client(app) -> AsyncClient:
    """Async HTTP client bound to the test application."""
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as ac:
        yield ac


@pytest.fixture()
async def db_session(app):
    """Yield an independent async DB session for test setup."""
    session_factory = app.state.db_session_factory
    async with session_factory() as session:
        yield session

