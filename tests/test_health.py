"""Tests for the health-check endpoint."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_returns_200_when_services_available(
    client: AsyncClient,
) -> None:
    """GET /api/v1/health returns 200 with all checks healthy."""
    response = await client.get("/api/v1/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert body["version"] == "0.1.0"
    assert body["checks"]["postgres"] == "healthy"
    assert body["checks"]["redis"] == "healthy"


@pytest.mark.asyncio
async def test_health_response_includes_correlation_id(
    client: AsyncClient,
) -> None:
    """Every response must include an X-Request-ID header."""
    response = await client.get("/api/v1/health")
    assert "x-request-id" in response.headers


@pytest.mark.asyncio
async def test_health_echoes_provided_correlation_id(
    client: AsyncClient,
) -> None:
    """If the caller supplies X-Request-ID, the response echoes it back."""
    custom_id = "test-correlation-123"
    response = await client.get(
        "/api/v1/health", headers={"X-Request-ID": custom_id}
    )
    assert response.headers["x-request-id"] == custom_id


@pytest.mark.asyncio
async def test_health_response_envelope(client: AsyncClient) -> None:
    """Verify the exact shape of the health response."""
    response = await client.get("/api/v1/health")
    body = response.json()

    assert set(body.keys()) == {"status", "version", "checks"}
    assert isinstance(body["checks"], dict)
    assert "postgres" in body["checks"]
    assert "redis" in body["checks"]
