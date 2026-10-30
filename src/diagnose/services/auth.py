"""Authentication service."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.core.security import create_access_token, verify_password
from diagnose.domain.exceptions import AuthenticationError
from diagnose.repositories.user import UserRepository
from diagnose.schemas.auth import LoginRequest, TokenResponse


class AuthService:
    """Authentication and token generation operations."""

    def __init__(self, user_repository: UserRepository | None = None) -> None:
        self.user_repository = user_repository or UserRepository()

    async def authenticate(
        self, session: AsyncSession, credentials: LoginRequest
    ) -> TokenResponse:
        """Authenticate user by email and password and return a bearer JWT."""
        user = await self.user_repository.get_by_email(
            session, email=credentials.email
        )

        if user is None or not user.is_active:
            # Consistent generic error to avoid user enumeration
            raise AuthenticationError("Invalid email or password.")

        if not verify_password(credentials.password, user.hashed_password):
            raise AuthenticationError("Invalid email or password.")

        token = create_access_token(
            user_id=user.id,
            organization_id=user.organization_id,
            role=user.role,
        )

        return TokenResponse(access_token=token, token_type="bearer")
