"""Repository for Job data access."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.sorting import validate_date_range, validate_sort_field
from diagnose.models.job import Job

JOB_SORT_FIELDS = {
    "created_at": Job.created_at,
    "updated_at": Job.updated_at,
    "status": Job.status,
}


class JobRepository:
    """Tenant-scoped repository for Job entities."""

    async def create_job(self, session: AsyncSession, job: Job) -> Job:
        """Add a new Job entity to the session."""
        session.add(job)
        await session.flush()
        return job

    async def get_by_id(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        job_id: uuid.UUID,
        for_update: bool = False,
    ) -> Job | None:
        """Retrieve a job by ID strictly scoped to an organization."""
        query = select(Job).where(
            Job.organization_id == organization_id,
            Job.id == job_id,
        )
        if for_update:
            query = query.with_for_update()
        result = await session.execute(query)
        return result.scalar_one_or_none()

    async def get_by_idempotency_key(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        idempotency_key: str,
        for_update: bool = False,
    ) -> Job | None:
        """Retrieve a job by tenant and idempotency key."""
        query = select(Job).where(
            Job.organization_id == organization_id,
            Job.idempotency_key == idempotency_key,
        )
        if for_update:
            query = query.with_for_update()
        result = await session.execute(query)
        return result.scalar_one_or_none()

    async def list_jobs(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        status: str | None = None,
        job_type: str | None = None,
        created_from: datetime | None = None,
        created_to: datetime | None = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[Job], int]:
        """List jobs scoped to an organization with filtering, sorting, and pagination."""
        tz_from, tz_to = validate_date_range(created_from, created_to)

        base_query = select(Job).where(Job.organization_id == organization_id)
        count_query = select(func.count()).select_from(Job).where(Job.organization_id == organization_id)

        if status:
            base_query = base_query.where(Job.status == status)
            count_query = count_query.where(Job.status == status)
        if job_type:
            base_query = base_query.where(Job.job_type == job_type)
            count_query = count_query.where(Job.job_type == job_type)
        if tz_from is not None:
            base_query = base_query.where(Job.created_at >= tz_from)
            count_query = count_query.where(Job.created_at >= tz_from)
        if tz_to is not None:
            base_query = base_query.where(Job.created_at <= tz_to)
            count_query = count_query.where(Job.created_at <= tz_to)

        total = await session.scalar(count_query) or 0

        order_clauses = validate_sort_field(
            sort_by=sort_by,
            allowed_columns=JOB_SORT_FIELDS,
            default_field="created_at",
            sort_order=sort_order,
            tie_breaker_column=Job.id,
        )

        query = base_query.order_by(*order_clauses).offset(offset).limit(limit)
        result = await session.execute(query)
        return result.scalars().all(), total
