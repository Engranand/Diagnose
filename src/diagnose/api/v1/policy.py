"""API endpoints for Remediation Policies (Milestone 10.2)."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.api.deps import (
    get_correlation_id,
    get_current_org_id,
    get_current_user,
    get_db,
    require_permission,
)
from diagnose.domain.roles import Permission
from diagnose.models.user import User
from diagnose.schemas.pagination import PaginatedResponse, PaginationParams
from diagnose.schemas.policy import (
    PolicyCreateRequest,
    PolicyResponse,
    PolicyUpdateRequest,
)
from diagnose.services.policy import PolicyService

router = APIRouter(prefix="/policies", tags=["policies"])


@router.post(
    "",
    response_model=PolicyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new remediation policy",
)
async def create_policy(
    payload: PolicyCreateRequest,
    current_user: User = Depends(require_permission(Permission.MANAGE_POLICY)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
    correlation_id: str | None = Depends(get_correlation_id),
) -> PolicyResponse:
    """Create a new remediation policy under organization-row serialization lock."""
    service = PolicyService()
    policy = await service.create_policy(
        session=session,
        organization_id=org_id,
        data=payload,
        actor_user_id=current_user.id,
        correlation_id=correlation_id,
    )
    return PolicyResponse.model_validate(policy)


@router.get(
    "",
    response_model=PaginatedResponse[PolicyResponse],
    summary="List remediation policies for the organization",
)
async def list_policies(
    is_active: bool | None = Query(default=None, description="Filter by active status"),
    action_type: str | None = Query(default=None, description="Filter by action type"),
    pagination: PaginationParams = Depends(),
    current_user: User = Depends(require_permission(Permission.VIEW_POLICY)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
) -> PaginatedResponse[PolicyResponse]:
    """Retrieve paginated remediation policies scoped to the caller's organization."""
    service = PolicyService()
    items, total = await service.list_policies(
        session=session,
        organization_id=org_id,
        is_active=is_active,
        action_type=action_type,
        offset=pagination.offset,
        limit=pagination.limit,
    )
    return PaginatedResponse(
        items=[PolicyResponse.model_validate(item) for item in items],
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        pages=pagination.calculate_pages(total),
    )


@router.get(
    "/{policy_id}",
    response_model=PolicyResponse,
    summary="Get remediation policy details",
)
async def get_policy(
    policy_id: UUID,
    current_user: User = Depends(require_permission(Permission.VIEW_POLICY)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
) -> PolicyResponse:
    """Retrieve details for a specific remediation policy. Returns 404 for foreign tenant."""
    service = PolicyService()
    policy = await service.get_policy(
        session=session,
        organization_id=org_id,
        policy_id=policy_id,
    )
    return PolicyResponse.model_validate(policy)


@router.patch(
    "/{policy_id}",
    response_model=PolicyResponse,
    summary="Update or activate/deactivate a remediation policy",
)
async def update_policy(
    policy_id: UUID,
    payload: PolicyUpdateRequest,
    current_user: User = Depends(require_permission(Permission.MANAGE_POLICY)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
    correlation_id: str | None = Depends(get_correlation_id),
) -> PolicyResponse:
    """Update policy fields, priority, or toggle is_active under organization lock."""
    service = PolicyService()
    policy = await service.update_policy(
        session=session,
        organization_id=org_id,
        policy_id=policy_id,
        data=payload,
        actor_user_id=current_user.id,
        correlation_id=correlation_id,
    )
    return PolicyResponse.model_validate(policy)
