"""Tests for application startup and structure."""

from __future__ import annotations

import pytest
from fastapi import FastAPI

from diagnose.main import create_app
from diagnose.settings import Settings


def test_create_app_returns_fastapi_instance() -> None:
    """The factory must return a FastAPI app without raising."""
    settings = Settings(
        DATABASE_URL="postgresql+asyncpg://x:x@localhost/x",
        REDIS_URL="redis://localhost:6379/1",
        ENVIRONMENT="testing",
        DEBUG=True,
    )
    application = create_app(settings=settings)
    assert isinstance(application, FastAPI)


def test_app_has_v1_health_route() -> None:
    """The /api/v1/health route must be registered."""
    settings = Settings(
        DATABASE_URL="postgresql+asyncpg://x:x@localhost/x",
        REDIS_URL="redis://localhost:6379/1",
        ENVIRONMENT="testing",
        DEBUG=True,
    )
    application = create_app(settings=settings)

    route_paths = [route.path for route in application.routes]
    assert "/api/v1/health" in route_paths


def test_app_debug_mode_enables_docs() -> None:
    """In debug mode, OpenAPI docs should be accessible."""
    settings = Settings(
        DATABASE_URL="postgresql+asyncpg://x:x@localhost/x",
        REDIS_URL="redis://localhost:6379/1",
        ENVIRONMENT="testing",
        DEBUG=True,
    )
    application = create_app(settings=settings)
    assert application.docs_url == "/api/docs"
    assert application.redoc_url == "/api/redoc"


def test_app_production_mode_disables_docs() -> None:
    """In production mode, OpenAPI docs must not be exposed."""
    settings = Settings(
        DATABASE_URL="postgresql+asyncpg://x:x@localhost/x",
        REDIS_URL="redis://localhost:6379/1",
        ENVIRONMENT="production",
        DEBUG=False,
    )
    application = create_app(settings=settings)
    assert application.docs_url is None
    assert application.redoc_url is None


def test_settings_defaults() -> None:
    """Settings must have sensible defaults for required fields."""
    settings = Settings()
    assert settings.APP_NAME == "Diagnose"
    assert settings.APP_VERSION == "0.1.0"
    assert settings.API_V1_PREFIX == "/api/v1"
    assert settings.DATABASE_POOL_SIZE == 10


def test_correlation_id_middleware_registered() -> None:
    """The CorrelationIdMiddleware must be in the middleware stack."""
    settings = Settings(
        DATABASE_URL="postgresql+asyncpg://x:x@localhost/x",
        REDIS_URL="redis://localhost:6379/1",
        ENVIRONMENT="testing",
        DEBUG=True,
    )
    application = create_app(settings=settings)

    # Walk the middleware stack — the app wraps middleware as layers
    middleware_classes = []
    inner = application.middleware_stack
    while inner is not None:
        middleware_classes.append(type(inner).__name__)
        inner = getattr(inner, "app", None)

    assert "CorrelationIdMiddleware" in middleware_classes
