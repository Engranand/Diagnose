"""Organization endpoints."""

from __future__ import annotations

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
from diagnose.schemas.organization import (
    OrganizationResponse,
    OrganizationUpdateRequest,
)
from diagnose.services.organization import OrganizationService

router = APIRouter(prefix="/organizations", tags=["organizations"])


@router.get(
    "/me",
    response_model=OrganizationResponse,
    summary="Get caller's organization details",
)
async def get_my_organization(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> OrganizationResponse:
    """Return the organization the authenticated user belongs to."""
    service = OrganizationService()
    org = await service.get_by_id(session, current_user.organization_id)
    return OrganizationResponse.model_validate(org)


@router.patch(
    "/me",
    response_model=OrganizationResponse,
    summary="Update organization details (ADMIN only)",
)
async def update_my_organization(
    update_data: OrganizationUpdateRequest,
    current_user: User = Depends(
        require_permission(Permission.MANAGE_ORGANIZATION)
    ),
    session: AsyncSession = Depends(get_db),
    correlation_id: str | None = Depends(get_correlation_id),
) -> OrganizationResponse:
    """Update organization details. Requires ADMIN role."""
    service = OrganizationService()
    org = await service.update_organization(
        session=session,
        org_id=current_user.organization_id,
        actor_user_id=current_user.id,
        update_data=update_data,
        correlation_id=correlation_id,
    )
    return OrganizationResponse.model_validate(org)
