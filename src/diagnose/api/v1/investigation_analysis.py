"""API endpoints for LLM-powered incident investigation analysis (Milestone 9)."""

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
from diagnose.schemas.llm import (
    CreateAnalysisRequest,
    InvestigationAnalysisResponse,
)
from diagnose.services.investigation_analysis import InvestigationAnalysisService

router = APIRouter(prefix="/investigations", tags=["investigation-analysis"])


@router.post(
    "/{investigation_id}/analysis",
    response_model=InvestigationAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Create or retrieve idempotent LLM investigation analysis",
)
async def create_investigation_analysis(
    investigation_id: UUID,
    payload: CreateAnalysisRequest | None = None,
    current_user: User = Depends(require_permission(Permission.EXECUTE_INVESTIGATION)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
    correlation_id: str | None = Depends(get_correlation_id),
) -> InvestigationAnalysisResponse:
    """Execute evidence-grounded LLM analysis. Idempotently returns existing completed analysis if input has not changed."""
    service = InvestigationAnalysisService()
    force_refresh = payload.force_refresh if payload else False
    analysis = await service.execute_analysis(
        session=session,
        organization_id=org_id,
        investigation_id=investigation_id,
        force_refresh=force_refresh,
        actor_user_id=current_user.id,
        correlation_id=correlation_id,
    )
    return InvestigationAnalysisResponse.model_validate(analysis)


@router.get(
    "/{investigation_id}/analysis",
    response_model=InvestigationAnalysisResponse,
    summary="Retrieve the latest completed LLM investigation analysis",
)
async def get_latest_investigation_analysis(
    investigation_id: UUID,
    current_user: User = Depends(require_permission(Permission.VIEW_INVESTIGATIONS)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
) -> InvestigationAnalysisResponse:
    """Fetch the latest completed LLM analysis for an investigation."""
    service = InvestigationAnalysisService()
    analysis = await service.get_latest_analysis(
        session=session,
        organization_id=org_id,
        investigation_id=investigation_id,
    )
    return InvestigationAnalysisResponse.model_validate(analysis)


@router.get(
    "/{investigation_id}/analysis/{analysis_id}",
    response_model=InvestigationAnalysisResponse,
    summary="Retrieve a specific LLM investigation analysis by ID",
)
async def get_investigation_analysis_by_id(
    investigation_id: UUID,
    analysis_id: UUID,
    current_user: User = Depends(require_permission(Permission.VIEW_INVESTIGATIONS)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
) -> InvestigationAnalysisResponse:
    """Fetch a specific LLM analysis by its ID, strictly scoped to the tenant."""
    service = InvestigationAnalysisService()
    analysis = await service.get_analysis(
        session=session,
        organization_id=org_id,
        analysis_id=analysis_id,
    )
    return InvestigationAnalysisResponse.model_validate(analysis)


@router.post(
    "/{investigation_id}/analysis/refresh",
    response_model=InvestigationAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Force refresh an LLM investigation analysis",
)
async def refresh_investigation_analysis(
    investigation_id: UUID,
    current_user: User = Depends(require_permission(Permission.EXECUTE_INVESTIGATION)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
    correlation_id: str | None = Depends(get_correlation_id),
) -> InvestigationAnalysisResponse:
    """Force execution of a fresh LLM analysis bypassing cached input hash."""
    service = InvestigationAnalysisService()
    analysis = await service.execute_analysis(
        session=session,
        organization_id=org_id,
        investigation_id=investigation_id,
        force_refresh=True,
        actor_user_id=current_user.id,
        correlation_id=correlation_id,
    )
    return InvestigationAnalysisResponse.model_validate(analysis)
