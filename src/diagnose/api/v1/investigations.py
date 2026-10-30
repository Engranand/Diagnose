"""API endpoints for Root-Cause Analysis (Milestone 8)."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, status
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
from diagnose.schemas.investigation import (
    EvidenceCorrelationResponse,
    InvestigationDetailResponse,
    InvestigationHypothesisResponse,
    InvestigationRunResponse,
    InvestigationTimelineEventResponse,
)
from diagnose.schemas.pagination import PaginatedResponse, PaginationParams
from diagnose.services.investigation import InvestigationService

router = APIRouter(prefix="/investigations", tags=["investigations"])
incident_investigations_router = APIRouter(prefix="/incidents", tags=["investigations"])


# ── INCIDENT SCOPED INVESTIGATION ENDPOINTS ──────────────────────────────────


@incident_investigations_router.post(
    "/{incident_id}/investigations",
    response_model=InvestigationRunResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new root-cause investigation run for an incident",
)
async def create_investigation(
    incident_id: UUID,
    current_user: User = Depends(require_permission(Permission.CREATE_INVESTIGATION)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
    correlation_id: str | None = Depends(get_correlation_id),
) -> InvestigationRunResponse:
    """Create an investigation run in PENDING status. Guarantees single active run per incident."""
    service = InvestigationService()
    run = await service.create_investigation(
        session=session,
        organization_id=org_id,
        incident_id=incident_id,
        actor_user_id=current_user.id,
        correlation_id=correlation_id,
    )
    return InvestigationRunResponse.model_validate(run)


@incident_investigations_router.get(
    "/{incident_id}/investigations",
    response_model=PaginatedResponse[InvestigationRunResponse],
    summary="List all investigation runs for an incident",
)
async def list_incident_investigations(
    incident_id: UUID,
    pagination: PaginationParams = Depends(),
    current_user: User = Depends(require_permission(Permission.VIEW_INVESTIGATIONS)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
) -> PaginatedResponse[InvestigationRunResponse]:
    """List investigation runs for an incident ordered by run_number DESC."""
    service = InvestigationService()
    items, total = await service.list_investigations_for_incident(
        session=session,
        organization_id=org_id,
        incident_id=incident_id,
        offset=pagination.offset,
        limit=pagination.limit,
    )
    pages = pagination.calculate_pages(total)
    return PaginatedResponse[InvestigationRunResponse](
        items=[InvestigationRunResponse.model_validate(item) for item in items],
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        pages=pages,
    )


# ── RUN-SCOPED INVESTIGATION ENDPOINTS ───────────────────────────────────────


@router.get(
    "/{investigation_id}",
    response_model=InvestigationDetailResponse,
    summary="Get investigation run details by ID",
)
async def get_investigation(
    investigation_id: UUID,
    current_user: User = Depends(require_permission(Permission.VIEW_INVESTIGATIONS)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
) -> InvestigationDetailResponse:
    """Retrieve detailed investigation run with executed steps and evaluated hypotheses."""
    service = InvestigationService()
    run = await service.get_investigation(
        session=session,
        organization_id=org_id,
        investigation_id=investigation_id,
    )
    return InvestigationDetailResponse.model_validate(run)


@router.post(
    "/{investigation_id}/run",
    response_model=InvestigationDetailResponse,
    summary="Execute or re-execute an investigation run",
)
async def run_investigation(
    investigation_id: UUID,
    current_user: User = Depends(require_permission(Permission.EXECUTE_INVESTIGATION)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
    correlation_id: str | None = Depends(get_correlation_id),
) -> InvestigationDetailResponse:
    """Deterministically execute an investigation run. Idempotently returns completed run if already finished."""
    service = InvestigationService()
    run = await service.execute_investigation(
        session=session,
        organization_id=org_id,
        investigation_id=investigation_id,
        actor_user_id=current_user.id,
        correlation_id=correlation_id,
    )
    return InvestigationDetailResponse.model_validate(run)


@router.get(
    "/{investigation_id}/timeline",
    response_model=PaginatedResponse[InvestigationTimelineEventResponse],
    summary="Get chronologically sorted timeline events for an investigation",
)
async def get_investigation_timeline(
    investigation_id: UUID,
    pagination: PaginationParams = Depends(),
    current_user: User = Depends(require_permission(Permission.VIEW_INVESTIGATIONS)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
) -> PaginatedResponse[InvestigationTimelineEventResponse]:
    """Retrieve timeline events ordered by timestamp ASC, source_id ASC."""
    service = InvestigationService()
    items, total = await service.list_timeline(
        session=session,
        organization_id=org_id,
        investigation_id=investigation_id,
        offset=pagination.offset,
        limit=pagination.limit,
    )
    pages = pagination.calculate_pages(total)
    return PaginatedResponse[InvestigationTimelineEventResponse](
        items=[InvestigationTimelineEventResponse.model_validate(item) for item in items],
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        pages=pages,
    )


@router.get(
    "/{investigation_id}/correlations",
    response_model=PaginatedResponse[EvidenceCorrelationResponse],
    summary="Get evidence correlation records for an investigation",
)
async def get_investigation_correlations(
    investigation_id: UUID,
    pagination: PaginationParams = Depends(),
    current_user: User = Depends(require_permission(Permission.VIEW_INVESTIGATIONS)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
) -> PaginatedResponse[EvidenceCorrelationResponse]:
    """Retrieve explainable evidence correlations ordered by score DESC."""
    service = InvestigationService()
    items, total = await service.list_correlations(
        session=session,
        organization_id=org_id,
        investigation_id=investigation_id,
        offset=pagination.offset,
        limit=pagination.limit,
    )
    pages = pagination.calculate_pages(total)
    return PaginatedResponse[EvidenceCorrelationResponse](
        items=[EvidenceCorrelationResponse.model_validate(item) for item in items],
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        pages=pages,
    )


@router.get(
    "/{investigation_id}/hypotheses",
    response_model=list[InvestigationHypothesisResponse],
    summary="Get evaluated, ranked hypotheses with supporting/contradicting evidence",
)
async def get_investigation_hypotheses(
    investigation_id: UUID,
    current_user: User = Depends(require_permission(Permission.VIEW_INVESTIGATIONS)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
) -> list[InvestigationHypothesisResponse]:
    """Retrieve ranked hypotheses ordered by rank ASC."""
    service = InvestigationService()
    hypotheses = await service.list_hypotheses(
        session=session,
        organization_id=org_id,
        investigation_id=investigation_id,
    )
    return [InvestigationHypothesisResponse.model_validate(h) for h in hypotheses]
