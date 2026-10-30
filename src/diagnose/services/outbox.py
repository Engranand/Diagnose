"""Transactional Outbox Service — enqueues events within active DB transactions."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.outbox import OutboxEventType, OutboxStatus
from diagnose.models.outbox import OutboxEvent
from diagnose.repositories.outbox import OutboxRepository


class OutboxService:
    """Service to create outbox events in the same transaction as business mutations."""

    def __init__(self, outbox_repository: OutboxRepository | None = None) -> None:
        self.outbox_repo = outbox_repository or OutboxRepository()

    async def record_event(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        event_type: str | OutboxEventType,
        aggregate_type: str,
        aggregate_id: str | uuid.UUID,
        payload: dict[str, Any] | None = None,
        max_attempts: int = 5,
        available_at: datetime | None = None,
    ) -> OutboxEvent:
        """Create and stage an OutboxEvent in the current transaction.

        CRITICAL: Does NOT call commit. The caller must commit this event
        atomically alongside their business mutation.
        """
        now = datetime.now(timezone.utc)
        type_str = event_type.value if isinstance(event_type, OutboxEventType) else str(event_type)

        event = OutboxEvent(
            organization_id=organization_id,
            event_type=type_str,
            aggregate_type=aggregate_type,
            aggregate_id=str(aggregate_id),
            payload=payload,
            status=OutboxStatus.PENDING.value,
            available_at=available_at or now,
            attempt_count=0,
            max_attempts=max_attempts,
            created_at=now,
        )
        return await self.outbox_repo.create_event(session, event)
