"""Service catalog endpoints."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.api.deps import (
    get_correlation_id,
    get_current_org_id,
    get_current_user,
    get_db,
    require_permission,
)
from diagnose.domain.roles import Permission
from diagnose.domain.sorting import SortOrder
from diagnose.models.user import User
from diagnose.schemas.pagination import PaginationParams
from diagnose.schemas.service import ServiceCreate, ServiceRead, ServiceUpdate
from diagnose.services.service import ServiceService

router = APIRouter(prefix="/services", tags=["services"])


@router.post(
    "",
    response_model=ServiceRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new service in the organization catalog",
)
async def create_service(
    data: ServiceCreate,
    request: Request,
    current_user: User = Depends(require_permission(Permission.MANAGE_SERVICES)),
    session: AsyncSession = Depends(get_db),
    correlation_id: str | None = Depends(get_correlation_id),
) -> ServiceRead:
    """Register a new production service in the caller's organization."""
    service = ServiceService()
    ip_address = request.client.host if request.client else None
    created = await service.create_service(
        session=session,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        data=data,
        correlation_id=correlation_id,
        ip_address=ip_address,
    )
    return ServiceRead.model_validate(created)


@router.get(
    "",
    response_model=list[ServiceRead],
    summary="List all services in the organization",
)
async def list_services(
    is_active: bool | None = Query(default=None, description="Filter by active status"),
    tier: str | None = Query(default=None, description="Filter by criticality tier"),
    search: str | None = Query(default=None, max_length=100, description="Search by service name or slug"),
    sort_by: str = Query(default="name", description="Field to sort by (name, created_at, tier)"),
    sort_order: SortOrder = Query(default=SortOrder.ASC, description="Sort direction (asc, desc)"),
    pagination: PaginationParams = Depends(),
    current_user: User = Depends(get_current_user),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
) -> list[ServiceRead]:
    """List services belonging strictly to the authenticated caller's organization."""
    service = ServiceService()
    services = await service.list_services(
        session=session,
        organization_id=org_id,
        is_active=is_active,
        tier=tier,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order.value,
        offset=pagination.offset,
        limit=pagination.limit,
    )
    return [ServiceRead.model_validate(s) for s in services]


@router.get(
    "/{service_id}",
    response_model=ServiceRead,
    summary="Get service by ID",
)
async def get_service(
    service_id: UUID,
    current_user: User = Depends(get_current_user),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
) -> ServiceRead:
    """Retrieve service details. Returns 404 if not found or belongs to another organization."""
    service = ServiceService()
    found = await service.get_service(
        session=session,
        organization_id=org_id,
        service_id=service_id,
    )
    return ServiceRead.model_validate(found)


@router.patch(
    "/{service_id}",
    response_model=ServiceRead,
    summary="Update or deactivate a service",
)
async def update_service(
    service_id: UUID,
    data: ServiceUpdate,
    request: Request,
    current_user: User = Depends(require_permission(Permission.MANAGE_SERVICES)),
    session: AsyncSession = Depends(get_db),
    correlation_id: str | None = Depends(get_correlation_id),
) -> ServiceRead:
    """Update service metadata or soft-deactivate by passing is_active=false."""
    service = ServiceService()
    ip_address = request.client.host if request.client else None
    updated = await service.update_service(
        session=session,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        service_id=service_id,
        data=data,
        correlation_id=correlation_id,
        ip_address=ip_address,
    )
    return ServiceRead.model_validate(updated)
