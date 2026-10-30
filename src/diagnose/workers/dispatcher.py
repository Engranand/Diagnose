"""Outbox Dispatcher — polls pending outbox events with SKIP LOCKED and dispatches to Redis."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable

import structlog
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from diagnose.domain.jobs import calculate_backoff_delay
from diagnose.domain.outbox import OutboxStatus
from diagnose.repositories.outbox import OutboxRepository
from diagnose.workers.queue import RedisQueue, RedisUnavailableError

log = structlog.get_logger()

DEFAULT_QUEUE_NAME = "diagnose:jobs:queue"


class OutboxDispatcher:
    """Dispatches durable outbox events from PostgreSQL to Redis queue."""

    def __init__(
        self,
        redis_queue: RedisQueue,
        outbox_repository: OutboxRepository | None = None,
        default_queue_name: str = DEFAULT_QUEUE_NAME,
    ) -> None:
        self.redis_queue = redis_queue
        self.outbox_repo = outbox_repository or OutboxRepository()
        self.default_queue_name = default_queue_name

    async def dispatch_batch(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        batch_size: int = 50,
    ) -> int:
        """Poll and dispatch a bounded batch of pending outbox events.

        Uses SELECT ... FOR UPDATE SKIP LOCKED to prevent duplicate processing
        across multiple concurrent dispatcher instances.
        """
        published_count = 0

        async with session_factory() as session:
            events = await self.outbox_repo.fetch_pending_batch(
                session=session,
                batch_size=batch_size,
                for_update=True,
                skip_locked=True,
            )

            if not events:
                return 0

            now = datetime.now(timezone.utc)

            for event in events:
                queue_name = self.default_queue_name
                payload = event.payload or {}

                try:
                    await self.redis_queue.enqueue(queue_name, payload)
                    event.status = OutboxStatus.PUBLISHED.value
                    event.published_at = datetime.now(timezone.utc)
                    event.last_error = None
                    published_count += 1
                    log.info(
                        "outbox_event_published",
                        event_id=str(event.id),
                        event_type=event.event_type,
                        aggregate_id=event.aggregate_id,
                        organization_id=str(event.organization_id),
                        queue=queue_name,
                    )
                except (RedisUnavailableError, Exception) as exc:
                    event.attempt_count += 1
                    event.last_error = str(exc)
                    if event.attempt_count >= event.max_attempts:
                        event.status = OutboxStatus.DEAD.value
                        log.error(
                            "outbox_event_dead",
                            event_id=str(event.id),
                            attempts=event.attempt_count,
                            max_attempts=event.max_attempts,
                            error=str(exc),
                        )
                    else:
                        event.status = OutboxStatus.PENDING.value
                        delay = calculate_backoff_delay(event.attempt_count)
                        event.available_at = now + timedelta(seconds=delay)
                        log.warning(
                            "outbox_event_dispatch_failed_retry_scheduled",
                            event_id=str(event.id),
                            attempts=event.attempt_count,
                            retry_delay_seconds=delay,
                            error=str(exc),
                        )

            await session.commit()

        return published_count
