"""Repository for Transactional Outbox data access."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.outbox import OutboxStatus
from diagnose.models.outbox import OutboxEvent


class OutboxRepository:
    """Repository for OutboxEvent persistence and bounded polling."""

    async def create_event(self, session: AsyncSession, event: OutboxEvent) -> OutboxEvent:
        """Add an outbox event to the session."""
        session.add(event)
        await session.flush()
        return event

    async def get_by_id(
        self,
        session: AsyncSession,
        event_id: uuid.UUID,
        for_update: bool = False,
    ) -> OutboxEvent | None:
        """Retrieve an outbox event by ID."""
        query = select(OutboxEvent).where(OutboxEvent.id == event_id)
        if for_update:
            query = query.with_for_update()
        result = await session.execute(query)
        return result.scalar_one_or_none()

    async def fetch_pending_batch(
        self,
        session: AsyncSession,
        batch_size: int = 50,
        now: datetime | None = None,
        for_update: bool = True,
        skip_locked: bool = True,
    ) -> Sequence[OutboxEvent]:
        """Fetch a bounded batch of pending outbox events ready for dispatch.

        Uses PostgreSQL ``FOR UPDATE SKIP LOCKED`` so that concurrent dispatcher
        processes safely claim disjoint partitions without blocking or duplicate processing.
        """
        current_time = now or datetime.now(timezone.utc)
        query = (
            select(OutboxEvent)
            .where(
                OutboxEvent.status == OutboxStatus.PENDING.value,
                OutboxEvent.available_at <= current_time,
            )
            .order_by(OutboxEvent.available_at.asc(), OutboxEvent.created_at.asc())
            .limit(batch_size)
        )
        if for_update:
            query = query.with_for_update(skip_locked=skip_locked)

        result = await session.execute(query)
        return result.scalars().all()
