"""Evidence artifact collection and retrieval endpoints."""

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
from diagnose.domain.evidence import EvidenceType
from diagnose.domain.roles import Permission
from diagnose.models.user import User
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
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=50, ge=1, le=100, description="Items per page"),
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
        page=page,
        page_size=page_size,
    )
    pages = math.ceil(total / page_size) if total > 0 else 1
    return EvidenceListResponse(
        items=[EvidenceRead.model_validate(item) for item in items],
        total=total,
        page=page,
        page_size=page_size,
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
