"""FastAPI application factory.

Use :func:`create_app` to build a configured application instance.
The module-level ``app`` object is a convenience for ``uvicorn diagnose.main:app``.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

import redis.asyncio as aioredis
import structlog
from fastapi import FastAPI

from diagnose.api.v1.router import v1_router
from diagnose.db.session import create_engine, create_session_factory
from diagnose.logging import setup_logging
from diagnose.middleware.correlation_id import CorrelationIdMiddleware
from diagnose.middleware.error_handler import setup_exception_handlers
from diagnose.settings import Settings, get_settings


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Manage startup/shutdown of backing-service connections."""
    settings: Settings = app.state.settings
    log = structlog.get_logger()

    # ── Startup ──────────────────────────────────────────────────────
    engine = create_engine(settings)
    app.state.db_engine = engine
    app.state.db_session_factory = create_session_factory(engine)

    app.state.redis = aioredis.from_url(
        settings.REDIS_URL, decode_responses=True
    )

    log.info(
        "application_started",
        environment=settings.ENVIRONMENT,
        version=settings.APP_VERSION,
    )

    yield

    # ── Shutdown ─────────────────────────────────────────────────────
    await app.state.redis.aclose()
    await engine.dispose()
    log.info("application_stopped")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build and return a fully-configured :class:`FastAPI` application."""
    if settings is None:
        settings = get_settings()

    setup_logging(settings)

    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        lifespan=lifespan,
        docs_url="/api/docs" if settings.DEBUG else None,
        redoc_url="/api/redoc" if settings.DEBUG else None,
        openapi_url="/api/openapi.json" if settings.DEBUG else None,
    )

    app.state.settings = settings

    # ── Middleware (outermost first) ──────────────────────────────────
    app.add_middleware(CorrelationIdMiddleware)

    # ── Exception handlers ───────────────────────────────────────────
    setup_exception_handlers(app)

    # ── Routers ──────────────────────────────────────────────────────
    app.include_router(v1_router, prefix=settings.API_V1_PREFIX)

    return app


# Convenience instance for ``uvicorn diagnose.main:app``
app = create_app()
