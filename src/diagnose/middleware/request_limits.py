"""Middleware protecting against oversized requests and excessive query strings."""

from __future__ import annotations

import json
from starlette.types import ASGIApp, Message, Receive, Scope, Send

DEFAULT_MAX_BODY_SIZE = 2 * 1024 * 1024  # 2MB
DEFAULT_MAX_QUERY_LENGTH = 2048  # 2048 chars


class RequestLimitsMiddleware:
    """ASGI middleware enforcing request body size and query parameter length limits."""

    def __init__(
        self,
        app: ASGIApp,
        max_body_size: int = DEFAULT_MAX_BODY_SIZE,
        max_query_length: int = DEFAULT_MAX_QUERY_LENGTH,
    ) -> None:
        self.app = app
        self.max_body_size = max_body_size
        self.max_query_length = max_query_length

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        correlation_id = scope.get("state", {}).get("correlation_id", "")

        # 1. Enforce query string length limit
        query_string = scope.get("query_string", b"")
        if len(query_string) > self.max_query_length:
            error_body = json.dumps(
                {
                    "error": {
                        "code": "QUERY_TOO_LONG",
                        "message": (
                            f"Query string length ({len(query_string)}) exceeds "
                            f"maximum allowed limit of {self.max_query_length} characters."
                        ),
                        "correlation_id": correlation_id,
                    }
                }
            ).encode("utf-8")
            await send(
                {
                    "type": "http.response.start",
                    "status": 400,
                    "headers": [
                        (b"content-type", b"application/json"),
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

        # 2. Enforce Content-Length header check
        headers = dict(scope.get("headers", []))
        raw_cl = headers.get(b"content-length")
        if raw_cl:
            try:
                content_length = int(raw_cl.decode("ascii"))
                if content_length > self.max_body_size:
                    max_mb = self.max_body_size // (1024 * 1024)
                    error_body = json.dumps(
                        {
                            "error": {
                                "code": "REQUEST_TOO_LARGE",
                                "message": (
                                    f"Request body size ({content_length} bytes) exceeds "
                                    f"maximum allowed size of {max_mb}MB."
                                ),
                                "correlation_id": correlation_id,
                            }
                        }
                    ).encode("utf-8")
                    await send(
                        {
                            "type": "http.response.start",
                            "status": 413,
                            "headers": [
                                (b"content-type", b"application/json"),
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
            except (ValueError, UnicodeDecodeError):
                pass

        # 3. Guard against streaming/chunked transfer exceeding body limit
        bytes_received = 0

        async def limited_receive() -> Message:
            nonlocal bytes_received
            message = await receive()
            if message["type"] == "http.request":
                body_chunk = message.get("body", b"")
                bytes_received += len(body_chunk)
                if bytes_received > self.max_body_size:
                    max_mb = self.max_body_size // (1024 * 1024)
                    raise OversizedPayloadException(
                        f"Request streaming body exceeded maximum size of {max_mb}MB."
                    )
            return message

        try:
            await self.app(scope, limited_receive, send)
        except OversizedPayloadException as exc:
            error_body = json.dumps(
                {
                    "error": {
                        "code": "REQUEST_TOO_LARGE",
                        "message": str(exc),
                        "correlation_id": correlation_id,
                    }
                }
            ).encode("utf-8")
            await send(
                {
                    "type": "http.response.start",
                    "status": 413,
                    "headers": [
                        (b"content-type", b"application/json"),
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


class OversizedPayloadException(Exception):
    """Raised when streaming body length exceeds limit."""
