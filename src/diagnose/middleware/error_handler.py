"""Global exception → HTTP-response mapping.

Every :class:`~diagnose.domain.exceptions.DomainException` subclass is
mapped to an appropriate HTTP status code and a consistent error envelope::

    {
        "error": {
            "code": "NOT_FOUND",
            "message": "Incident with id '...' not found"
        }
    }

Unhandled exceptions are logged and returned as ``500 INTERNAL_ERROR``
without leaking implementation details.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette import status
from starlette.exceptions import HTTPException as StarletteHTTPException

import structlog

from diagnose.domain.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    DomainException,
    EntityNotFound,
    InvalidStateTransition,
    ValidationError as DomainValidationError,
)

logger = structlog.get_logger()


def _get_correlation_id(request: Request) -> str | None:
    """Extract correlation ID from request state, ASGI scope, or headers."""
    state = getattr(request, "state", None)
    if state and hasattr(state, "correlation_id") and state.correlation_id:
        return state.correlation_id
    scope_state = request.scope.get("state", {})
    if "correlation_id" in scope_state and scope_state["correlation_id"]:
        return scope_state["correlation_id"]
    return request.headers.get("x-request-id")


def _error_response(
    status_code: int,
    code: str,
    message: str,
    details: Any = None,
    correlation_id: str | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    content: dict[str, Any] = {
        "error": {
            "code": code,
            "message": message,
        }
    }
    if details is not None:
        content["error"]["details"] = details
    if correlation_id is not None:
        content["error"]["correlation_id"] = correlation_id

    return JSONResponse(
        status_code=status_code,
        content=content,
        headers=headers,
    )


def setup_exception_handlers(app: FastAPI) -> None:
    """Register exception handlers on the FastAPI application."""

    @app.exception_handler(AuthenticationError)
    async def _authentication_error(
        request: Request, exc: AuthenticationError
    ) -> JSONResponse:
        cid = _get_correlation_id(request)
        return _error_response(
            status.HTTP_401_UNAUTHORIZED, "UNAUTHORIZED", str(exc), correlation_id=cid
        )

    @app.exception_handler(EntityNotFound)
    async def _entity_not_found(
        request: Request, exc: EntityNotFound
    ) -> JSONResponse:
        cid = _get_correlation_id(request)
        return _error_response(
            status.HTTP_404_NOT_FOUND, "NOT_FOUND", str(exc), correlation_id=cid
        )

    @app.exception_handler(InvalidStateTransition)
    async def _invalid_transition(
        request: Request, exc: InvalidStateTransition
    ) -> JSONResponse:
        cid = _get_correlation_id(request)
        return _error_response(
            status.HTTP_409_CONFLICT,
            "INVALID_STATE_TRANSITION",
            str(exc),
            correlation_id=cid,
        )

    @app.exception_handler(AuthorizationError)
    async def _authorization_error(
        request: Request, exc: AuthorizationError
    ) -> JSONResponse:
        cid = _get_correlation_id(request)
        return _error_response(
            status.HTTP_403_FORBIDDEN, "FORBIDDEN", str(exc), correlation_id=cid
        )

    @app.exception_handler(ConflictError)
    async def _conflict_error(
        request: Request, exc: ConflictError
    ) -> JSONResponse:
        cid = _get_correlation_id(request)
        return _error_response(
            status.HTTP_409_CONFLICT, "CONFLICT", str(exc), correlation_id=cid
        )

    @app.exception_handler(DomainValidationError)
    async def _domain_validation(
        request: Request, exc: DomainValidationError
    ) -> JSONResponse:
        cid = _get_correlation_id(request)
        return _error_response(
            422,
            "VALIDATION_ERROR",
            str(exc),
            correlation_id=cid,
        )

    @app.exception_handler(RequestValidationError)
    async def _request_validation(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        cid = _get_correlation_id(request)
        # Formulate human-friendly message from first error if available
        first_err = exc.errors()[0] if exc.errors() else {}
        field = " -> ".join(str(loc) for loc in first_err.get("loc", []))
        msg = f"Validation failed on field '{field}': {first_err.get('msg', 'invalid')}" if field else "Request validation failed."
        return _error_response(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            msg,
            details=jsonable_encoder(exc.errors()),
            correlation_id=cid,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_exception(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        cid = _get_correlation_id(request)
        code_map = {
            400: "BAD_REQUEST",
            401: "UNAUTHORIZED",
            403: "FORBIDDEN",
            404: "NOT_FOUND",
            405: "METHOD_NOT_ALLOWED",
            409: "CONFLICT",
            413: "REQUEST_TOO_LARGE",
            422: "VALIDATION_ERROR",
            429: "RATE_LIMIT_EXCEEDED",
            500: "INTERNAL_ERROR",
        }
        code = code_map.get(exc.status_code, "HTTP_ERROR")
        headers = dict(exc.headers) if exc.headers else None
        return _error_response(
            exc.status_code,
            code,
            str(exc.detail),
            correlation_id=cid,
            headers=headers,
        )

    @app.exception_handler(DomainException)
    async def _domain_exception(
        request: Request, exc: DomainException
    ) -> JSONResponse:
        cid = _get_correlation_id(request)
        return _error_response(
            status.HTTP_400_BAD_REQUEST, "DOMAIN_ERROR", str(exc), correlation_id=cid
        )

    @app.exception_handler(500)
    @app.exception_handler(Exception)
    async def _unhandled(
        request: Request, exc: Exception
    ) -> JSONResponse:
        logger.exception("unhandled_exception", exc_info=exc)
        cid = _get_correlation_id(request)
        return _error_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "An internal error occurred.",
            correlation_id=cid,
        )
