"""Operational Job inspection and execution endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.api.deps import (
    get_correlation_id,
    get_current_user,
    get_db,
    require_permission,
)
from diagnose.domain.jobs import JobStatus
from diagnose.domain.roles import Permission
from diagnose.models.user import User
from diagnose.schemas.job import JobCreate, JobListResponse, JobRead
from diagnose.services.job import JobService

router = APIRouter(prefix="/jobs", tags=["jobs"])


@router.post(
    "",
    response_model=JobRead,
    status_code=status.HTTP_201_CREATED,
    summary="Trigger an asynchronous background job (ADMIN / ENGINEER)",
)
async def create_job(
    data: JobCreate,
    current_user: Annotated[User, Depends(require_permission(Permission.TRIGGER_JOB))],
    session: Annotated[AsyncSession, Depends(get_db)],
    correlation_id: Annotated[str, Depends(get_correlation_id)],
) -> JobRead:
    """Trigger an asynchronous background job with transactional outbox event creation."""
    service = JobService()
    job, is_created = await service.create_job(
        session=session,
        organization_id=current_user.organization_id,
        data=data,
        actor_user_id=current_user.id,
        correlation_id=correlation_id,
    )
    return JobRead.model_validate(job)


@router.get(
    "",
    response_model=JobListResponse,
    status_code=status.HTTP_200_OK,
    summary="List background jobs for current organization",
)
async def list_jobs(
    current_user: Annotated[User, Depends(require_permission(Permission.VIEW_JOBS))],
    session: Annotated[AsyncSession, Depends(get_db)],
    status: Annotated[JobStatus | None, Query(description="Filter by job status")] = None,
    job_type: Annotated[str | None, Query(description="Filter by job type")] = None,
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page")] = 50,
) -> JobListResponse:
    """List tenant jobs with filtering and pagination."""
    service = JobService()
    items, total = await service.list_jobs(
        session=session,
        organization_id=current_user.organization_id,
        status=status,
        job_type=job_type,
        page=page,
        page_size=page_size,
    )
    return JobListResponse(
        items=[JobRead.model_validate(j) for j in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/{job_id}",
    response_model=JobRead,
    status_code=status.HTTP_200_OK,
    summary="Get background job details by ID",
)
async def get_job(
    job_id: uuid.UUID,
    current_user: Annotated[User, Depends(require_permission(Permission.VIEW_JOBS))],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> JobRead:
    """Fetch details of a background job scoped strictly to caller's tenant."""
    service = JobService()
    job = await service.get_job(
        session=session,
        organization_id=current_user.organization_id,
        job_id=job_id,
    )
    return JobRead.model_validate(job)
