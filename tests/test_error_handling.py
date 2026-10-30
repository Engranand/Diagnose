"""Tests for global error handling middleware."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from fastapi import APIRouter

from diagnose.domain.exceptions import (
    EntityNotFound,
    InvalidStateTransition,
    AuthorizationError,
    ConflictError,
    ValidationError as DomainValidationError,
)
from diagnose.main import create_app
from diagnose.settings import Settings
from diagnose.db.session import create_engine, create_session_factory
import redis.asyncio as aioredis


def _make_app_with_error_routes(settings: Settings):
    """Create an app with routes that raise each domain exception type."""
    app = create_app(settings=settings)

    error_router = APIRouter(prefix="/test-errors")

    @error_router.get("/not-found")
    async def raise_not_found():
        raise EntityNotFound("Widget", "abc-123")

    @error_router.get("/invalid-transition")
    async def raise_invalid_transition():
        raise InvalidStateTransition("Incident", "DETECTED", "RESOLVED")

    @error_router.get("/forbidden")
    async def raise_forbidden():
        raise AuthorizationError()

    @error_router.get("/conflict")
    async def raise_conflict():
        raise ConflictError("Resource already exists")

    @error_router.get("/validation")
    async def raise_validation():
        raise DomainValidationError("Name must not be empty")

    @error_router.get("/unhandled")
    async def raise_unhandled():
        raise RuntimeError("Something unexpected")

    app.include_router(error_router)
    return app


@pytest.fixture()
async def error_client(test_settings: Settings):
    """Client wired to an app with error-raising test routes."""
    from httpx import ASGITransport

    application = _make_app_with_error_routes(test_settings)

    engine = create_engine(test_settings)
    application.state.db_engine = engine
    application.state.db_session_factory = create_session_factory(engine)
    application.state.redis = aioredis.from_url(
        test_settings.REDIS_URL, decode_responses=True
    )

    transport = ASGITransport(app=application)
    async with AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as ac:
        yield ac

    await application.state.redis.aclose()
    await engine.dispose()


@pytest.mark.asyncio
async def test_entity_not_found_returns_404(error_client: AsyncClient) -> None:
    response = await error_client.get("/test-errors/not-found")
    assert response.status_code == 404
    body = response.json()
    assert body["error"]["code"] == "NOT_FOUND"
    assert "Widget" in body["error"]["message"]


@pytest.mark.asyncio
async def test_invalid_transition_returns_409(
    error_client: AsyncClient,
) -> None:
    response = await error_client.get("/test-errors/invalid-transition")
    assert response.status_code == 409
    body = response.json()
    assert body["error"]["code"] == "INVALID_STATE_TRANSITION"


@pytest.mark.asyncio
async def test_authorization_error_returns_403(
    error_client: AsyncClient,
) -> None:
    response = await error_client.get("/test-errors/forbidden")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_conflict_returns_409(error_client: AsyncClient) -> None:
    response = await error_client.get("/test-errors/conflict")
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "CONFLICT"


@pytest.mark.asyncio
async def test_validation_error_returns_422(
    error_client: AsyncClient,
) -> None:
    response = await error_client.get("/test-errors/validation")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_unhandled_exception_returns_500(
    error_client: AsyncClient,
) -> None:
    response = await error_client.get("/test-errors/unhandled")
    assert response.status_code == 500
    body = response.json()
    assert body["error"]["code"] == "INTERNAL_ERROR"
    # Must NOT leak the actual exception message
    assert "Something unexpected" not in body["error"]["message"]
