"""Redis-backed rate limiting middleware with fail-safe behavior.

================================================================================
RATE-LIMITING ARCHITECTURE & POLICY SPECIFICATION
================================================================================

1. SCOPE AND GRANULARITY:
   - Rate limiting is enforced PER-USER for authenticated callers.
   - Key format: `rate_limit:org:{org_id}:user:{user_id}:{window_epoch}`
   - The organization (`org_id`) participates strictly as NAMESPACE ISOLATION to
     prevent key collisions across tenants and guarantee tenant isolation.
   - The limit is NOT aggregated across the entire organization; User A within Org 1
     consuming requests cannot exhaust the quota of User B within Org 1.
   - Tenant A cannot exhaust or affect the rate-limit bucket of Tenant B.
   - For unauthenticated requests (e.g. login), the fallback identifier is:
     `rate_limit:ip:{client_ip}:{window_epoch}`

2. CONFIGURED LIMIT & WINDOW:
   - Default Limit: 120 requests per minute (configured via `RATE_LIMIT_PER_MINUTE`).
   - Default Window: 60 seconds (configured via `RATE_LIMIT_WINDOW_SECONDS`).
   - Window Epoch: `int(current_timestamp // window_seconds)`.

3. EXEMPT PATHS:
   - Health check: `/api/v1/health`
   - OpenAPI documentation: `/api/docs`, `/api/redoc`, `/api/openapi.json`

4. REDIS OUTAGE BEHAVIOR: FAIL-OPEN WITH CIRCUIT BREAKER:
   - If Redis is unavailable, encounters a network timeout, or raises a connection error:
     The middleware catches the exception, logs a structured warning, and engages a 2-second
     in-memory circuit breaker (`_circuit_breaker_until = time.time() + 2.0`).
   - While the circuit breaker is open, requests pass through directly to downstream handlers
     without attempting Redis operations, preventing request latency stalls.
   - Once Redis recovers and the cooldown elapses, rate limiting automatically resumes.

5. AVAILABILITY VS. ABUSE-PROTECTION TRADEOFF:
   - Design Decision: Fail-open prioritizes system availability over strict throttling.
   - Justification: Diagnose is an incident management platform. If a Redis cache outage
     occurs during an ongoing production outage, on-call responders must still be able to
     access services, triage incidents, and ingest alerts without being blocked by a 500 error
     or false-positive rate limit failures.
   - Caveat: Fail-open is NOT universally security-safe against volumetric denial-of-service
     attacks during a Redis outage. It intentionally accepts the temporary risk of unthrottled
     requests during infrastructure failure in order to maintain critical operational availability.
================================================================================
"""

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
    """ASGI middleware implementing Redis-backed rate limiting with fail-open safety.

    Attributes:
        rate_limit_per_minute: Maximum requests allowed in a 60-second window.
        window_seconds: Size of fixed window in seconds (default: 60).
        enabled: Toggle switch for rate limiting.
    """

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

        now = time.time()
        if now < self._circuit_breaker_until:
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
        window_epoch = int(now // self.window_seconds)
        rl_key = f"rate_limit:{identifier}:{window_epoch}"
        correlation_id = scope.get("state", {}).get("correlation_id", "")

        try:
            # Atomic counter with TTL using Redis pipeline
            pipe = redis_client.pipeline()
            pipe.incr(rl_key)
            pipe.expire(rl_key, self.window_seconds * 2)
            results = await pipe.execute()
            current_count: int = results[0]

            window_end = (window_epoch + 1) * self.window_seconds
            retry_after = max(1, int(window_end - now))

            if current_count > self.rate_limit_per_minute:
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
        """Extract authoritative tenant identifier from JWT or fallback to client IP.

        Format:
            - Authenticated: `org:{org_id}:user:{user_id}`
            - Unauthenticated: `ip:{client_ip}`
        """
        headers = dict(scope.get("headers", []))
        auth_header = headers.get(b"authorization", b"").decode("latin-1")

        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            try:
                payload = decode_access_token(token)
                org_id = payload.get("org_id")
                user_id = payload.get("sub")
                if org_id and user_id:
                    # Enforce per-user rate limit scoped by tenant namespace
                    return f"org:{org_id}:user:{user_id}"
            except Exception:
                # If token is invalid, fall through to IP-based rate limiting
                pass

        # Fallback to client IP
        client = scope.get("client")
        client_ip = client[0] if client else "unknown"
        return f"ip:{client_ip}"
