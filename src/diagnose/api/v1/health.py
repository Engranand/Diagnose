"""Health-check endpoint.

Returns the application version and connectivity status for each backing
service (PostgreSQL, Redis).  If *any* dependency is unreachable the
overall status is ``unhealthy`` and the HTTP status code is **503** so
that load-balancers can drain traffic.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from pydantic import BaseModel
from sqlalchemy import text
from starlette import status as http_status

import structlog

router = APIRouter(tags=["health"])
logger = structlog.get_logger()


class HealthResponse(BaseModel):
    """Public contract for the health endpoint."""

    status: str
    version: str
    checks: dict[str, str]


@router.get(
    "/health",
    response_model=HealthResponse,
    responses={503: {"model": HealthResponse}},
)
async def health_check(request: Request) -> HealthResponse:
    checks: dict[str, str] = {}
    overall = "healthy"

    # ── PostgreSQL ───────────────────────────────────────────────────
    try:
        async with request.app.state.db_session_factory() as session:
            await session.execute(text("SELECT 1"))
        checks["postgres"] = "healthy"
    except Exception as exc:
        logger.error("health_check_postgres_failed", error=str(exc))
        checks["postgres"] = "unhealthy"
        overall = "unhealthy"

    # ── Redis ────────────────────────────────────────────────────────
    try:
        await request.app.state.redis.ping()
        checks["redis"] = "healthy"
    except Exception as exc:
        logger.error("health_check_redis_failed", error=str(exc))
        checks["redis"] = "unhealthy"
        overall = "unhealthy"

    response = HealthResponse(
        status=overall,
        version=request.app.state.settings.APP_VERSION,
        checks=checks,
    )

    status_code = (
        http_status.HTTP_200_OK
        if overall == "healthy"
        else http_status.HTTP_503_SERVICE_UNAVAILABLE
    )

    from fastapi.responses import JSONResponse

    return JSONResponse(content=response.model_dump(), status_code=status_code)
