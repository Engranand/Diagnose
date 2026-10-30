"""Redis task queue abstraction — transport only."""

from __future__ import annotations

import json
from typing import Any

import redis.asyncio as aioredis
from redis.exceptions import RedisError


class RedisUnavailableError(Exception):
    """Raised when Redis operations fail due to network or broker unavailability."""


class RedisQueue:
    """Explicit, lightweight task queue abstraction backed by Redis."""

    def __init__(self, redis_client: aioredis.Redis) -> None:
        self.redis = redis_client

    async def enqueue(self, queue_name: str, payload: dict[str, Any]) -> None:
        """Push a serialized task payload to the tail of the Redis queue."""
        try:
            raw_data = json.dumps(payload, separators=(",", ":"))
            await self.redis.rpush(queue_name, raw_data)
        except (RedisError, ConnectionError, OSError) as exc:
            raise RedisUnavailableError(f"Failed to enqueue to Redis queue '{queue_name}': {exc}") from exc

    async def dequeue(self, queue_name: str, timeout: float = 1.0) -> dict[str, Any] | None:
        """Pop a task payload from the head of the Redis queue.

        Returns None if timeout expires without a task.
        """
        try:
            if timeout > 0:
                result = await self.redis.blpop(queue_name, timeout=int(max(1, timeout)))
                if result is None:
                    return None
                _, raw_data = result
            else:
                raw_data = await self.redis.lpop(queue_name)
                if raw_data is None:
                    return None

            if isinstance(raw_data, bytes):
                raw_data = raw_data.decode("utf-8")
            return json.loads(raw_data)
        except (RedisError, ConnectionError, OSError) as exc:
            raise RedisUnavailableError(f"Failed to dequeue from Redis queue '{queue_name}': {exc}") from exc

    async def size(self, queue_name: str) -> int:
        """Return the current length of the queue."""
        try:
            return await self.redis.llen(queue_name)
        except (RedisError, ConnectionError, OSError) as exc:
            raise RedisUnavailableError(f"Failed to query Redis queue size '{queue_name}': {exc}") from exc

    async def clear(self, queue_name: str) -> None:
        """Flush the queue (useful for test resets)."""
        try:
            await self.redis.delete(queue_name)
        except (RedisError, ConnectionError, OSError) as exc:
            raise RedisUnavailableError(f"Failed to clear Redis queue '{queue_name}': {exc}") from exc
