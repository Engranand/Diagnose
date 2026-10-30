"""Evidence artifact collection and retrieval endpoints."""

from __future__ import annotations

import math
from datetime import datetime
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
from diagnose.domain.evidence import EvidenceReliability, EvidenceType
from diagnose.domain.roles import Permission
from diagnose.domain.sorting import SortOrder
from diagnose.models.user import User
from diagnose.schemas.pagination import PaginationParams
from diagnose.schemas.evidence import (
    EvidenceCreate,
    EvidenceListResponse,
    EvidenceRead,
)
from diagnose.services.evidence import EvidenceService

router = APIRouter(tags=["evidence"])


@router.post(
    "/incidents/{incident_id}/evidence",
    response_model=EvidenceRead,
    status_code=status.HTTP_201_CREATED,
    summary="Add an immutable evidence artifact to an incident",
)
async def add_evidence(
    incident_id: UUID,
    data: EvidenceCreate,
    request: Request,
    current_user: User = Depends(require_permission(Permission.ADD_EVIDENCE)),
    session: AsyncSession = Depends(get_db),
    correlation_id: str | None = Depends(get_correlation_id),
) -> EvidenceRead:
    """Attach an immutable evidence artifact to an incident in the caller's tenant."""
    service = EvidenceService()
    ip_address = request.client.host if request.client else None
    evidence = await service.create_evidence(
        session=session,
        organization_id=current_user.organization_id,
        incident_id=incident_id,
        actor_user_id=current_user.id,
        data=data,
        correlation_id=correlation_id,
        ip_address=ip_address,
    )
    return EvidenceRead.model_validate(evidence)


@router.get(
    "/incidents/{incident_id}/evidence",
    response_model=EvidenceListResponse,
    summary="List evidence artifacts for an incident",
)
async def list_incident_evidence(
    incident_id: UUID,
    evidence_type: EvidenceType | None = Query(default=None, description="Filter by evidence category"),
    reliability: EvidenceReliability | None = Query(default=None, description="Filter by reliability rating"),
    observed_from: datetime | None = Query(default=None, description="Filter evidence observed at or after"),
    observed_to: datetime | None = Query(default=None, description="Filter evidence observed at or before"),
    sort_by: str = Query(default="observed_at", description="Field to sort by (observed_at, created_at)"),
    sort_order: SortOrder = Query(default=SortOrder.ASC, description="Sort direction (asc, desc)"),
    pagination: PaginationParams = Depends(),
    current_user: User = Depends(require_permission(Permission.VIEW_EVIDENCE)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
) -> EvidenceListResponse:
    """List chronological immutable evidence items attached to an incident."""
    service = EvidenceService()
    items, total = await service.list_by_incident(
        session=session,
        organization_id=org_id,
        incident_id=incident_id,
        evidence_type=evidence_type,
        reliability=reliability.value if reliability else None,
        observed_from=observed_from,
        observed_to=observed_to,
        sort_by=sort_by,
        sort_order=sort_order.value,
        offset=pagination.offset,
        limit=pagination.limit,
    )
    pages = pagination.calculate_pages(total)
    return EvidenceListResponse(
        items=[EvidenceRead.model_validate(item) for item in items],
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        pages=pages,
    )


@router.get(
    "/evidence/{evidence_id}",
    response_model=EvidenceRead,
    summary="Get evidence artifact by ID",
)
async def get_evidence(
    evidence_id: UUID,
    current_user: User = Depends(require_permission(Permission.VIEW_EVIDENCE)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
) -> EvidenceRead:
    """Retrieve an evidence artifact by ID. Returns 404 if outside tenant."""
    service = EvidenceService()
    evidence = await service.get_evidence(
        session=session,
        organization_id=org_id,
        evidence_id=evidence_id,
    )
    return EvidenceRead.model_validate(evidence)
