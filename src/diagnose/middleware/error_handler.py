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

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette import status

import structlog

from diagnose.domain.exceptions import (
    AuthorizationError,
    ConflictError,
    DomainException,
    EntityNotFound,
    InvalidStateTransition,
    ValidationError as DomainValidationError,
)

logger = structlog.get_logger()


def _error_response(
    status_code: int, code: str, message: str
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message}},
    )


def setup_exception_handlers(app: FastAPI) -> None:
    """Register exception handlers on the FastAPI application."""

    @app.exception_handler(EntityNotFound)
    async def _entity_not_found(
        _request: Request, exc: EntityNotFound
    ) -> JSONResponse:
        return _error_response(
            status.HTTP_404_NOT_FOUND, "NOT_FOUND", str(exc)
        )

    @app.exception_handler(InvalidStateTransition)
    async def _invalid_transition(
        _request: Request, exc: InvalidStateTransition
    ) -> JSONResponse:
        return _error_response(
            status.HTTP_409_CONFLICT,
            "INVALID_STATE_TRANSITION",
            str(exc),
        )

    @app.exception_handler(AuthorizationError)
    async def _authorization_error(
        _request: Request, exc: AuthorizationError
    ) -> JSONResponse:
        return _error_response(
            status.HTTP_403_FORBIDDEN, "FORBIDDEN", str(exc)
        )

    @app.exception_handler(ConflictError)
    async def _conflict_error(
        _request: Request, exc: ConflictError
    ) -> JSONResponse:
        return _error_response(
            status.HTTP_409_CONFLICT, "CONFLICT", str(exc)
        )

    @app.exception_handler(DomainValidationError)
    async def _domain_validation(
        _request: Request, exc: DomainValidationError
    ) -> JSONResponse:
        return _error_response(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "VALIDATION_ERROR",
            str(exc),
        )

    @app.exception_handler(DomainException)
    async def _domain_exception(
        _request: Request, exc: DomainException
    ) -> JSONResponse:
        return _error_response(
            status.HTTP_400_BAD_REQUEST, "DOMAIN_ERROR", str(exc)
        )

    @app.exception_handler(Exception)
    async def _unhandled(
        _request: Request, exc: Exception
    ) -> JSONResponse:
        logger.exception("unhandled_exception", exc_info=exc)
        return _error_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "An internal error occurred.",
        )
