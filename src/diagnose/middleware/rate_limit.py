"""Redis-backed rate limiting middleware with fail-safe behavior."""

from __future__ import annotations

import json
import time
from uuid import UUID

import redis.asyncio as aioredis
import structlog
from starlette.types import ASGIApp, Receive, Scope, Send

from diagnose.core.security import decode_access_token

log = structlog.get_logger()

# Endpoints exempt from rate limiting
EXEMPT_PATHS = {
    "/api/v1/health",
    "/api/docs",
    "/api/redoc",
    "/api/openapi.json",
}


class RateLimitMiddleware:
    """ASGI middleware implementing Redis-backed rate limiting with fail-open safety."""

    def __init__(
        self,
        app: ASGIApp,
        rate_limit_per_minute: int = 120,
        window_seconds: int = 60,
        enabled: bool = True,
    ) -> None:
        self.app = app
        self.rate_limit_per_minute = rate_limit_per_minute
        self.window_seconds = window_seconds
        self.enabled = enabled
        self._circuit_breaker_until: float = 0.0

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self.enabled:
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path in EXEMPT_PATHS or path.rstrip("/") in EXEMPT_PATHS:
            await self.app(scope, receive, send)
            return

        if time.time() < self._circuit_breaker_until:
            # Circuit open: fail open safely during Redis downtime
            await self.app(scope, receive, send)
            return

        # Attempt to retrieve Redis client from FastAPI app state
        app_instance = scope.get("app")
        redis_client: aioredis.Redis | None = (
            getattr(app_instance.state, "redis", None)
            if app_instance and hasattr(app_instance, "state")
            else None
        )

        if redis_client is None:
            # If Redis client is not available on app state, fail open safely
            await self.app(scope, receive, send)
            return

        # Derive rate limit key from authoritative JWT or client IP
        identifier = self._extract_identifier(scope)
        rl_key = f"diagnose:rl:{identifier}:{self.window_seconds}"
        correlation_id = scope.get("state", {}).get("correlation_id", "")

        try:
            # Atomic counter with TTL using Redis pipeline
            pipe = redis_client.pipeline()
            pipe.incr(rl_key)
            pipe.ttl(rl_key)
            results = await pipe.execute()
            current_count: int = results[0]
            ttl: int = results[1]

            if current_count == 1 or ttl == -1:
                await redis_client.expire(rl_key, self.window_seconds)
                ttl = self.window_seconds

            if current_count > self.rate_limit_per_minute:
                retry_after = max(1, ttl)
                log.warning(
                    "rate_limit_exceeded",
                    identifier=identifier,
                    count=current_count,
                    limit=self.rate_limit_per_minute,
                    retry_after=retry_after,
                    correlation_id=correlation_id,
                    path=path,
                )
                error_body = json.dumps(
                    {
                        "error": {
                            "code": "RATE_LIMIT_EXCEEDED",
                            "message": "Too many requests. Please try again later.",
                            "details": {
                                "retry_after": retry_after,
                                "limit": self.rate_limit_per_minute,
                            },
                            "correlation_id": correlation_id,
                        }
                    }
                ).encode("utf-8")
                await send(
                    {
                        "type": "http.response.start",
                        "status": 429,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"retry-after", str(retry_after).encode("ascii")),
                            (b"content-length", str(len(error_body)).encode("ascii")),
                        ],
                    }
                )
                await send(
                    {
                        "type": "http.response.body",
                        "body": error_body,
                    }
                )
                return

        except Exception as exc:
            # Policy: Fail-open for operational continuity during Redis degradation
            self._circuit_breaker_until = time.time() + 2.0  # 2-second cooldown to avoid stalling
            log.warning(
                "redis_rate_limit_unavailable_failing_open",
                error=str(exc),
                path=path,
                correlation_id=correlation_id,
            )

        await self.app(scope, receive, send)

    def _extract_identifier(self, scope: Scope) -> str:
        """Extract authoritative tenant identifier from JWT or fallback to client IP."""
        headers = dict(scope.get("headers", []))
        auth_header = headers.get(b"authorization", b"").decode("latin-1")

        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            try:
                payload = decode_access_token(token)
                org_id = payload.get("org_id")
                user_id = payload.get("sub")
                if org_id and user_id:
                    # Enforce per-tenant-user rate limit isolation
                    return f"org:{org_id}:user:{user_id}"
            except Exception:
                # If token is invalid, fall through to IP-based rate limiting
                pass

        # Fallback to client IP
        client = scope.get("client")
        client_ip = client[0] if client else "unknown"
        return f"ip:{client_ip}"
