"""Incident management and lifecycle endpoints."""

from __future__ import annotations

import math
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
from diagnose.domain.exceptions import AuthorizationError
from diagnose.domain.incidents import IncidentSeverity, IncidentStatus
from diagnose.domain.roles import Permission, has_permission
from diagnose.models.user import User
from diagnose.schemas.incident import (
    IncidentAssign,
    IncidentCreate,
    IncidentEventRead,
    IncidentListResponse,
    IncidentRead,
    IncidentTransition,
    IncidentUpdate,
)
from diagnose.services.incident import IncidentService

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.post(
    "",
    response_model=IncidentRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new incident",
)
async def create_incident(
    data: IncidentCreate,
    request: Request,
    current_user: User = Depends(require_permission(Permission.CREATE_INCIDENT)),
    session: AsyncSession = Depends(get_db),
    correlation_id: str | None = Depends(get_correlation_id),
) -> IncidentRead:
    """Declare a new incident in the caller's organization. Initial status is DETECTED."""
    service = IncidentService()
    ip_address = request.client.host if request.client else None
    created = await service.create_incident(
        session=session,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        data=data,
        correlation_id=correlation_id,
        ip_address=ip_address,
    )
    return IncidentRead.model_validate(created)


@router.get(
    "",
    response_model=IncidentListResponse,
    summary="List incidents with filtering and pagination",
)
async def list_incidents(
    status: IncidentStatus | None = Query(default=None, description="Filter by status"),
    severity: IncidentSeverity | None = Query(default=None, description="Filter by severity"),
    service_id: UUID | None = Query(default=None, description="Filter by service ID"),
    assigned_user_id: UUID | None = Query(default=None, description="Filter by assignee"),
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=50, ge=1, le=100, description="Items per page"),
    current_user: User = Depends(require_permission(Permission.VIEW_INCIDENTS)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
) -> IncidentListResponse:
    """List tenant-scoped incidents with optional filters and pagination."""
    service = IncidentService()
    items, total = await service.list_incidents(
        session=session,
        organization_id=org_id,
        status=status,
        severity=severity,
        service_id=service_id,
        assigned_user_id=assigned_user_id,
        page=page,
        page_size=page_size,
    )
    pages = math.ceil(total / page_size) if total > 0 else 1
    return IncidentListResponse(
        items=[IncidentRead.model_validate(item) for item in items],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get(
    "/{incident_id}",
    response_model=IncidentRead,
    summary="Get incident by ID",
)
async def get_incident(
    incident_id: UUID,
    current_user: User = Depends(require_permission(Permission.VIEW_INCIDENTS)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
) -> IncidentRead:
    """Retrieve incident details. Returns 404 if not found or outside tenant."""
    service = IncidentService()
    incident = await service.get_incident(
        session=session,
        organization_id=org_id,
        incident_id=incident_id,
    )
    return IncidentRead.model_validate(incident)


@router.patch(
    "/{incident_id}",
    response_model=IncidentRead,
    summary="Update incident metadata",
)
async def update_incident(
    incident_id: UUID,
    data: IncidentUpdate,
    request: Request,
    current_user: User = Depends(require_permission(Permission.TRANSITION_INCIDENT)),
    session: AsyncSession = Depends(get_db),
    correlation_id: str | None = Depends(get_correlation_id),
) -> IncidentRead:
    """Update incident title, description, or severity. Direct status mutation is prohibited."""
    service = IncidentService()
    ip_address = request.client.host if request.client else None
    updated = await service.update_incident(
        session=session,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        incident_id=incident_id,
        data=data,
        correlation_id=correlation_id,
        ip_address=ip_address,
    )
    return IncidentRead.model_validate(updated)


@router.post(
    "/{incident_id}/transition",
    response_model=IncidentRead,
    summary="Execute lifecycle state transition",
)
async def transition_incident(
    incident_id: UUID,
    data: IncidentTransition,
    request: Request,
    current_user: User = Depends(require_permission(Permission.TRANSITION_INCIDENT)),
    session: AsyncSession = Depends(get_db),
    correlation_id: str | None = Depends(get_correlation_id),
) -> IncidentRead:
    """Transition incident through its deterministic lifecycle state machine.

    Closing an incident explicitly requires close:incident permission.
    """
    if data.target_status == IncidentStatus.CLOSED:
        if not has_permission(current_user.role, Permission.CLOSE_INCIDENT):
            raise AuthorizationError("Action requires permission 'close:incident'.")

    service = IncidentService()
    ip_address = request.client.host if request.client else None
    transitioned = await service.transition_incident(
        session=session,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        incident_id=incident_id,
        data=data,
        correlation_id=correlation_id,
        ip_address=ip_address,
    )
    return IncidentRead.model_validate(transitioned)


@router.post(
    "/{incident_id}/assign",
    response_model=IncidentRead,
    summary="Assign incident to a user",
)
async def assign_incident(
    incident_id: UUID,
    data: IncidentAssign,
    request: Request,
    current_user: User = Depends(require_permission(Permission.ASSIGN_INCIDENT)),
    session: AsyncSession = Depends(get_db),
    correlation_id: str | None = Depends(get_correlation_id),
) -> IncidentRead:
    """Assign or unassign an incident within the organization."""
    service = IncidentService()
    ip_address = request.client.host if request.client else None
    assigned = await service.assign_incident(
        session=session,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        incident_id=incident_id,
        data=data,
        correlation_id=correlation_id,
        ip_address=ip_address,
    )
    return IncidentRead.model_validate(assigned)


@router.get(
    "/{incident_id}/events",
    response_model=list[IncidentEventRead],
    summary="Get incident timeline events",
)
async def list_incident_events(
    incident_id: UUID,
    current_user: User = Depends(require_permission(Permission.VIEW_INCIDENTS)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
) -> list[IncidentEventRead]:
    """Retrieve the immutable append-only timeline events for an incident."""
    service = IncidentService()
    events = await service.list_events(
        session=session,
        organization_id=org_id,
        incident_id=incident_id,
    )
    return [IncidentEventRead.model_validate(e) for e in events]
