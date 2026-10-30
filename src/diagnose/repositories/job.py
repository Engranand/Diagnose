"""Repository for Job data access."""

from __future__ import annotations

import uuid
from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.models.job import Job


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
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[Job], int]:
        """List jobs scoped to an organization with filtering and pagination."""
        base_query = select(Job).where(Job.organization_id == organization_id)
        count_query = select(func.count()).select_from(Job).where(Job.organization_id == organization_id)

        if status:
            base_query = base_query.where(Job.status == status)
            count_query = count_query.where(Job.status == status)
        if job_type:
            base_query = base_query.where(Job.job_type == job_type)
            count_query = count_query.where(Job.job_type == job_type)

        total = await session.scalar(count_query) or 0
        query = base_query.order_by(Job.created_at.desc()).offset(offset).limit(limit)
        result = await session.execute(query)
        return result.scalars().all(), total
