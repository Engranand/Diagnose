"""Tests for Outbox Dispatcher, Redis queuing, and failure modes."""

from __future__ import annotations

import asyncio
import uuid
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from diagnose.domain.outbox import OutboxStatus
from diagnose.models.outbox import OutboxEvent
from diagnose.repositories.outbox import OutboxRepository
from diagnose.workers.dispatcher import OutboxDispatcher
from diagnose.workers.queue import RedisQueue
from tests.factories import create_test_organization, create_test_outbox_event
from tests.fake_redis import FakeAsyncRedis


@pytest.mark.asyncio
async def test_dispatcher_publishes_pending_events_and_marks_published(
    app, db_session: AsyncSession
) -> None:
    """Requirement 5, 6: Dispatcher publishes pending outbox events to Redis and marks status = PUBLISHED."""
    session_factory = app.state.db_session_factory
    org = await create_test_organization(db_session)

    fake_redis = FakeAsyncRedis()
    queue = RedisQueue(fake_redis)  # type: ignore[arg-type]
    dispatcher = OutboxDispatcher(redis_queue=queue)

    # Drain any prior pending events from previous tests
    await dispatcher.dispatch_batch(session_factory, batch_size=100)
    await queue.clear("diagnose:jobs:queue")

    event1 = await create_test_outbox_event(db_session, org.id, payload={"task": 1})
    event2 = await create_test_outbox_event(db_session, org.id, payload={"task": 2})

    # Run dispatch
    published_count = await dispatcher.dispatch_batch(session_factory, batch_size=10)
    assert published_count == 2

    # Verify Redis received both tasks
    assert await queue.size("diagnose:jobs:queue") == 2
    msg1 = await queue.dequeue("diagnose:jobs:queue")
    msg2 = await queue.dequeue("diagnose:jobs:queue")
    assert msg1["task"] == 1
    assert msg2["task"] == 2

    # Verify database status is PUBLISHED with published_at timestamp
    async with session_factory() as session:
        outbox_repo = OutboxRepository()
        ev1 = await outbox_repo.get_by_id(session, event1.id)
        ev2 = await outbox_repo.get_by_id(session, event2.id)
        assert ev1.status == OutboxStatus.PUBLISHED.value
        assert ev1.published_at is not None
        assert ev2.status == OutboxStatus.PUBLISHED.value
        assert ev2.published_at is not None


@pytest.mark.asyncio
async def test_redis_failure_preserves_durable_state_and_schedules_backoff(
    app, db_session: AsyncSession
) -> None:
    """Requirement 7: Redis outage preserves durable state, increments attempt_count, and sets backoff."""
    session_factory = app.state.db_session_factory
    org = await create_test_organization(db_session)

    event = await create_test_outbox_event(
        db_session,
        org.id,
        payload={"durable_payload": "critical_data"},
        max_attempts=3,
    )
    initial_available_at = event.available_at

    fake_redis = FakeAsyncRedis()
    fake_redis.simulate_failure = True  # Simulate Redis down!

    queue = RedisQueue(fake_redis)  # type: ignore[arg-type]
    dispatcher = OutboxDispatcher(redis_queue=queue)

    # Dispatch attempt while Redis is down
    published_count = await dispatcher.dispatch_batch(session_factory, batch_size=10)
    assert published_count == 0

    # Verify durable state in PostgreSQL
    async with session_factory() as session:
        outbox_repo = OutboxRepository()
        ev = await outbox_repo.get_by_id(session, event.id)
        assert ev.status == OutboxStatus.PENDING.value
        assert ev.attempt_count == 1
        assert "Simulated Redis connection failure" in ev.last_error
        assert ev.available_at > initial_available_at
        assert ev.payload["durable_payload"] == "critical_data"

    # Restore Redis and verify recovery
    fake_redis.simulate_failure = False
    # Manually reset available_at so it's ready now
    async with session_factory() as session:
        ev = await OutboxRepository().get_by_id(session, event.id)
        ev.available_at = initial_available_at
        await session.commit()

    published_after_restore = await dispatcher.dispatch_batch(session_factory, batch_size=10)
    assert published_after_restore == 1

    async with session_factory() as session:
        ev = await OutboxRepository().get_by_id(session, event.id)
        assert ev.status == OutboxStatus.PUBLISHED.value


@pytest.mark.asyncio
async def test_multiple_concurrent_dispatchers_process_disjoint_batches(
    app, db_session: AsyncSession
) -> None:
    """Requirement 8: Concurrent dispatchers using FOR UPDATE SKIP LOCKED process disjoint partitions without conflict."""
    session_factory = app.state.db_session_factory
    org = await create_test_organization(db_session)

    fake_redis = FakeAsyncRedis()
    queue = RedisQueue(fake_redis)  # type: ignore[arg-type]
    drain_dispatcher = OutboxDispatcher(redis_queue=queue)
    await drain_dispatcher.dispatch_batch(session_factory, batch_size=100)
    await queue.clear("diagnose:jobs:queue")

    # Create 6 pending outbox events
    event_ids = []
    for i in range(6):
        ev = await create_test_outbox_event(db_session, org.id, payload={"seq": i})
        event_ids.append(ev.id)

    dispatcher1 = OutboxDispatcher(redis_queue=queue)
    dispatcher2 = OutboxDispatcher(redis_queue=queue)

    # Run dispatchers concurrently
    c1, c2 = await asyncio.gather(
        dispatcher1.dispatch_batch(session_factory, batch_size=3),
        dispatcher2.dispatch_batch(session_factory, batch_size=3),
    )

    # Exactly 6 events published in total, no duplicate dispatches
    assert c1 + c2 == 6
    assert await queue.size("diagnose:jobs:queue") == 6

    # Verify all 6 events are now PUBLISHED
    async with session_factory() as session:
        q = select(OutboxEvent).where(OutboxEvent.id.in_(event_ids))
        events = (await session.execute(q)).scalars().all()
        assert len(events) == 6
        assert all(e.status == OutboxStatus.PUBLISHED.value for e in events)
