"""Correlation-ID middleware.

Propagates an ``X-Request-ID`` header through the request lifecycle:

1. If the incoming request already carries the header, its value is reused.
2. Otherwise a new UUID-4 is generated.
3. The ID is bound into *structlog* context-vars so every log line emitted
   during the request includes ``correlation_id``, ``method``, and ``path``.
4. The response always echoes the header back to the caller.

This is implemented as a raw ASGI middleware (not Starlette's
``BaseHTTPMiddleware``) to avoid known issues with response streaming
and exception propagation.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog
from starlette.types import ASGIApp, Message, Receive, Scope, Send

HEADER_NAME = b"x-request-id"
log = structlog.get_logger()


class CorrelationIdMiddleware:
    """ASGI middleware that manages correlation IDs, binds context variables, and logs request metrics."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        start_time = time.perf_counter()

        # Extract existing header or generate a new one
        headers = dict(scope.get("headers", []))
        raw_value = headers.get(HEADER_NAME, b"")
        correlation_id = raw_value.decode("latin-1") if raw_value else str(
            uuid.uuid4()
        )

        # Store on the scope so downstream code can access it without
        # reaching into structlog context vars.
        scope["state"] = {**scope.get("state", {}), "correlation_id": correlation_id}

        method = scope.get("method", "")
        path = scope.get("path", "")

        # Bind into structlog context for the duration of this request
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            correlation_id=correlation_id,
            method=method,
            path=path,
        )

        status_code: int = 500

        async def send_with_id(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message.get("status", 200)
                response_headers: list[tuple[bytes, bytes]] = list(
                    message.get("headers", [])
                )
                response_headers.append(
                    (HEADER_NAME, correlation_id.encode("latin-1"))
                )
                message["headers"] = response_headers
            await send(message)

        try:
            await self.app(scope, receive, send_with_id)
        finally:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            state = scope.get("state", {})
            org_id = state.get("organization_id")
            user_id = state.get("user_id")

            # Structured logging of request completion (excluding health check to prevent log flooding)
            if path != "/api/v1/health":
                log.info(
                    "http_request_finished",
                    method=method,
                    path=path,
                    status_code=status_code,
                    duration_ms=duration_ms,
                    organization_id=org_id,
                    user_id=user_id,
                    correlation_id=correlation_id,
                )
