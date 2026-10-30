"""Alert ingestion, management, and incident association endpoints."""

from __future__ import annotations

import math
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.api.deps import (
    get_correlation_id,
    get_current_org_id,
    get_current_user,
    get_db,
    require_permission,
)
from diagnose.domain.alerts import AlertSeverity, AlertStatus
from diagnose.domain.roles import Permission
from diagnose.domain.sorting import SortOrder
from diagnose.models.user import User
from diagnose.schemas.pagination import PaginationParams
from diagnose.schemas.alert import (
    AlertCreate,
    AlertIncidentAssociation,
    AlertListResponse,
    AlertRead,
    AlertUpdate,
)
from diagnose.services.alert import AlertService

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.post(
    "",
    response_model=AlertRead,
    summary="Ingest an alert signal (idempotent by fingerprint)",
)
async def ingest_alert(
    data: AlertCreate,
    request: Request,
    response: Response,
    current_user: User = Depends(require_permission(Permission.MANAGE_ALERTS)),
    session: AsyncSession = Depends(get_db),
    correlation_id: str | None = Depends(get_correlation_id),
) -> AlertRead:
    """Ingest or re-fire an alert. Idempotently updates last_seen_at if active fingerprint exists."""
    service = AlertService()
    ip_address = request.client.host if request.client else None
    alert, is_created = await service.ingest_alert(
        session=session,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        data=data,
        correlation_id=correlation_id,
        ip_address=ip_address,
    )
    if is_created:
        response.status_code = status.HTTP_201_CREATED
    else:
        response.status_code = status.HTTP_200_OK
    return AlertRead.model_validate(alert)


@router.get(
    "",
    response_model=AlertListResponse,
    summary="List alerts with filtering and pagination",
)
async def list_alerts(
    status: AlertStatus | None = Query(default=None, description="Filter by status"),
    severity: AlertSeverity | None = Query(default=None, description="Filter by severity"),
    service_id: UUID | None = Query(default=None, description="Filter by service ID"),
    incident_id: UUID | None = Query(default=None, description="Filter by incident ID"),
    source: str | None = Query(default=None, description="Filter by alert source"),
    fingerprint: str | None = Query(default=None, description="Filter by alert fingerprint"),
    created_from: datetime | None = Query(default=None, description="Filter alerts created at or after"),
    created_to: datetime | None = Query(default=None, description="Filter alerts created at or before"),
    search: str | None = Query(default=None, max_length=100, description="Search title, message, and fingerprint"),
    sort_by: str = Query(default="created_at", description="Field to sort by (created_at, last_seen_at, severity, status)"),
    sort_order: SortOrder = Query(default=SortOrder.DESC, description="Sort direction (asc, desc)"),
    pagination: PaginationParams = Depends(),
    current_user: User = Depends(require_permission(Permission.VIEW_ALERTS)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
) -> AlertListResponse:
    """List tenant-scoped alerts with optional filters and pagination."""
    service = AlertService()
    items, total = await service.list_alerts(
        session=session,
        organization_id=org_id,
        status=status,
        severity=severity,
        service_id=service_id,
        incident_id=incident_id,
        source=source,
        fingerprint=fingerprint,
        created_from=created_from,
        created_to=created_to,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order.value,
        offset=pagination.offset,
        limit=pagination.limit,
    )
    pages = pagination.calculate_pages(total)
    return AlertListResponse(
        items=[AlertRead.model_validate(item) for item in items],
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        pages=pages,
    )


@router.get(
    "/{alert_id}",
    response_model=AlertRead,
    summary="Get alert by ID",
)
async def get_alert(
    alert_id: UUID,
    current_user: User = Depends(require_permission(Permission.VIEW_ALERTS)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
) -> AlertRead:
    """Retrieve alert details. Returns 404 if not found or outside tenant."""
    service = AlertService()
    alert = await service.get_alert(
        session=session,
        organization_id=org_id,
        alert_id=alert_id,
    )
    return AlertRead.model_validate(alert)


@router.patch(
    "/{alert_id}",
    response_model=AlertRead,
    summary="Update operational alert metadata",
)
async def update_alert(
    alert_id: UUID,
    data: AlertUpdate,
    request: Request,
    current_user: User = Depends(require_permission(Permission.MANAGE_ALERTS)),
    session: AsyncSession = Depends(get_db),
    correlation_id: str | None = Depends(get_correlation_id),
) -> AlertRead:
    """Update status, severity, title, or payload of an alert."""
    service = AlertService()
    ip_address = request.client.host if request.client else None
    updated = await service.update_alert(
        session=session,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        alert_id=alert_id,
        data=data,
        correlation_id=correlation_id,
        ip_address=ip_address,
    )
    return AlertRead.model_validate(updated)


@router.post(
    "/{alert_id}/incident",
    response_model=AlertRead,
    summary="Associate alert with an incident",
)
async def associate_alert_incident(
    alert_id: UUID,
    data: AlertIncidentAssociation,
    request: Request,
    current_user: User = Depends(require_permission(Permission.ASSOCIATE_ALERT)),
    session: AsyncSession = Depends(get_db),
    correlation_id: str | None = Depends(get_correlation_id),
) -> AlertRead:
    """Associate an alert with an incident in the same organization and service."""
    service = AlertService()
    ip_address = request.client.host if request.client else None
    associated = await service.associate_incident(
        session=session,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        alert_id=alert_id,
        incident_id=data.incident_id,
        correlation_id=correlation_id,
        ip_address=ip_address,
    )
    return AlertRead.model_validate(associated)
