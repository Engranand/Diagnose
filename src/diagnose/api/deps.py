"""Shared FastAPI dependencies for DB sessions, identity, and RBAC."""

from __future__ import annotations

from collections.abc import AsyncGenerator, Callable
from uuid import UUID

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.core.security import decode_access_token
from diagnose.domain.exceptions import AuthenticationError, AuthorizationError
from diagnose.domain.roles import Permission, has_permission
from diagnose.models.user import User
from diagnose.repositories.user import UserRepository

security_scheme = HTTPBearer(auto_error=False)


async def get_db(request: Request) -> AsyncGenerator[AsyncSession, None]:
    """Yield a scoped async database session and ensure it is closed."""
    session_factory = request.app.state.db_session_factory
    async with session_factory() as session:
        try:
            yield session
        finally:
            await session.close()


def get_correlation_id(request: Request) -> str | None:
    """Extract the current correlation ID set by the correlation ID middleware."""
    state = getattr(request, "state", None)
    return getattr(state, "correlation_id", None) if state else None


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security_scheme),
    session: AsyncSession = Depends(get_db),
) -> User:
    """Authenticate request from Bearer JWT and return active User instance.

    Raises :class:`AuthenticationError` (401) on missing, expired, or invalid tokens.
    """
    if credentials is None or not credentials.credentials:
        raise AuthenticationError("Authentication required.")

    token = credentials.credentials
    payload = decode_access_token(token)

    try:
        user_id = UUID(payload["sub"])
        org_id = UUID(payload["org_id"])
    except (KeyError, ValueError) as exc:
        raise AuthenticationError("Malformed authentication token.") from exc

    repo = UserRepository()
    user = await repo.get_by_id(session, user_id=user_id, organization_id=org_id)
    if user is None or not user.is_active:
        raise AuthenticationError("User is inactive or no longer exists.")

    return user


async def get_current_org_id(
    current_user: User = Depends(get_current_user),
) -> UUID:
    """Return the authoritative organization ID of the authenticated user.

    The client can never override or supply an arbitrary organization ID.
    """
    return current_user.organization_id


def require_permission(
    permission: Permission,
) -> Callable[[User], User]:
    """Dependency factory that enforces domain RBAC permissions.

    Raises :class:`AuthorizationError` (403) if the user lacks the required permission.
    """

    def _dependency(current_user: User = Depends(get_current_user)) -> User:
        if not has_permission(current_user.role, permission):
            raise AuthorizationError(
                f"Action requires permission '{permission.value}'."
            )
        return current_user

    return _dependency
