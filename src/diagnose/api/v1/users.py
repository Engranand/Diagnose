"""User endpoints."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.api.deps import (
    get_correlation_id,
    get_current_user,
    get_db,
    require_permission,
)
from diagnose.domain.roles import Permission
from diagnose.models.user import User
from diagnose.schemas.user import (
    UserCreateRequest,
    UserMeUpdateRequest,
    UserResponse,
    UserUpdateRequest,
)
from diagnose.services.user import UserService

router = APIRouter(prefix="/users", tags=["users"])


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
)
async def get_me(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """Return the profile of the authenticated caller."""
    return UserResponse.model_validate(current_user)


@router.patch(
    "/me",
    response_model=UserResponse,
    summary="Update current user profile (full_name only)",
)
async def update_me(
    update_data: UserMeUpdateRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
    correlation_id: str | None = Depends(get_correlation_id),
) -> UserResponse:
    """Update profile of the authenticated caller. Role and org cannot be modified."""
    service = UserService()
    user = await service.update_me(
        session=session,
        user_id=current_user.id,
        organization_id=current_user.organization_id,
        update_data=update_data,
        correlation_id=correlation_id,
    )
    return UserResponse.model_validate(user)


@router.get(
    "",
    response_model=list[UserResponse],
    summary="List all users in the organization (ADMIN only)",
)
async def list_users(
    current_user: User = Depends(require_permission(Permission.MANAGE_USERS)),
    session: AsyncSession = Depends(get_db),
) -> list[UserResponse]:
    """List all users within the caller's organization."""
    service = UserService()
    users = await service.list_users(
        session, organization_id=current_user.organization_id
    )
    return [UserResponse.model_validate(u) for u in users]


@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new user in the organization (ADMIN only)",
)
async def create_user(
    create_data: UserCreateRequest,
    current_user: User = Depends(require_permission(Permission.MANAGE_USERS)),
    session: AsyncSession = Depends(get_db),
    correlation_id: str | None = Depends(get_correlation_id),
) -> UserResponse:
    """Create a new user within the caller's organization."""
    service = UserService()
    user = await service.create_user(
        session=session,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        create_data=create_data,
        correlation_id=correlation_id,
    )
    return UserResponse.model_validate(user)


@router.patch(
    "/{user_id}",
    response_model=UserResponse,
    summary="Update or deactivate a user in the organization (ADMIN only)",
)
async def update_user(
    user_id: UUID,
    update_data: UserUpdateRequest,
    current_user: User = Depends(require_permission(Permission.MANAGE_USERS)),
    session: AsyncSession = Depends(get_db),
    correlation_id: str | None = Depends(get_correlation_id),
) -> UserResponse:
    """Update role, active state, or profile of a user in the caller's organization."""
    service = UserService()
    user = await service.update_user(
        session=session,
        user_id=user_id,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        update_data=update_data,
        correlation_id=correlation_id,
    )
    return UserResponse.model_validate(user)
