"""Audit log inspection endpoints (ADMIN only)."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.api.deps import (
    get_current_org_id,
    get_current_user,
    get_db,
    require_permission,
)
from diagnose.domain.roles import Permission
from diagnose.domain.sorting import SortOrder
from diagnose.models.user import User
from diagnose.schemas.audit_log import AuditLogListResponse, AuditLogResponse
from diagnose.schemas.pagination import PaginationParams
from diagnose.services.audit import AuditService

router = APIRouter(prefix="/audit-logs", tags=["audit-logs"])


@router.get(
    "",
    response_model=AuditLogListResponse,
    status_code=status.HTTP_200_OK,
    summary="List tenant audit logs with filtering, sorting, and pagination",
)
async def list_audit_logs(
    action: str | None = Query(default=None, description="Filter by audit action"),
    resource_type: str | None = Query(default=None, description="Filter by resource / entity type"),
    actor: uuid.UUID | None = Query(default=None, description="Filter by actor user ID"),
    created_from: datetime | None = Query(default=None, description="Filter logs created at or after"),
    created_to: datetime | None = Query(default=None, description="Filter logs created at or before"),
    sort_by: str = Query(default="created_at", description="Field to sort by (created_at, action)"),
    sort_order: SortOrder = Query(default=SortOrder.DESC, description="Sort direction (asc, desc)"),
    pagination: PaginationParams = Depends(),
    current_user: User = Depends(require_permission(Permission.VIEW_AUDIT_LOGS)),
    org_id: uuid.UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
) -> AuditLogListResponse:
    """List tenant-scoped immutable audit log records. Requires ADMIN role."""
    service = AuditService()
    items, total = await service.list_audit_logs(
        session=session,
        organization_id=org_id,
        action=action,
        entity_type=resource_type,
        actor_user_id=actor,
        created_from=created_from,
        created_to=created_to,
        sort_by=sort_by,
        sort_order=sort_order.value,
        offset=pagination.offset,
        limit=pagination.limit,
    )
    pages = pagination.calculate_pages(total)
    return AuditLogListResponse(
        items=[AuditLogResponse.model_validate(log_entry) for log_entry in items],
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        pages=pages,
    )
