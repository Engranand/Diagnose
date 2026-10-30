"""Repository for JobEffect durable side-effect access and registration."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.models.job_effect import JobEffect


class JobEffectRepository:
    """Tenant-scoped repository for JobEffect entities ensuring at-most-once durable side-effects."""

    async def get_by_effect_key(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        effect_key: str,
        for_update: bool = False,
    ) -> JobEffect | None:
        """Retrieve a job effect by tenant and effect key."""
        query = select(JobEffect).where(
            JobEffect.organization_id == organization_id,
            JobEffect.effect_key == effect_key,
        )
        if for_update:
            query = query.with_for_update()
        result = await session.execute(query)
        return result.scalar_one_or_none()

    async def record_effect(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        job_id: uuid.UUID,
        effect_key: str,
        payload: dict[str, Any] | None = None,
        status: str = "COMMITTED",
    ) -> tuple[JobEffect, bool]:
        """Atomically record or check a durable side-effect for an organization and effect key.

        Returns:
            (effect, was_applied):
            - was_applied is True if this is a newly inserted effect record.
            - was_applied is False if the effect was already recorded (idempotent no-op).
        """
        existing = await self.get_by_effect_key(
            session=session,
            organization_id=organization_id,
            effect_key=effect_key,
            for_update=True,
        )
        if existing is not None:
            return existing, False

        now = datetime.now(timezone.utc)
        effect = JobEffect(
            id=uuid.uuid4(),
            organization_id=organization_id,
            job_id=job_id,
            effect_key=effect_key,
            status=status,
            payload=payload,
            created_at=now,
            completed_at=now if status == "COMMITTED" else None,
        )
        session.add(effect)
        await session.flush()
        return effect, True

    async def list_by_job(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        job_id: uuid.UUID,
    ) -> Sequence[JobEffect]:
        """List all effects recorded for a specific job."""
        query = select(JobEffect).where(
            JobEffect.organization_id == organization_id,
            JobEffect.job_id == job_id,
        )
        result = await session.execute(query)
        return result.scalars().all()
