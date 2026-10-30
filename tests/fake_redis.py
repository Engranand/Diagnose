"""In-memory Async Redis test double for deterministic testing of Redis queue & failure modes."""

from __future__ import annotations

from collections import deque
from typing import Any

from redis.exceptions import ConnectionError


class FakeAsyncRedis:
    """Deterministic in-memory async Redis double for unit and integration testing."""

    def __init__(self) -> None:
        self._queues: dict[str, deque[str]] = {}
        self.simulate_failure: bool = False

    async def rpush(self, key: str, *values: str) -> int:
        if self.simulate_failure:
            raise ConnectionError("Simulated Redis connection failure")
        if key not in self._queues:
            self._queues[key] = deque()
        for v in values:
            self._queues[key].append(v)
        return len(self._queues[key])

    async def lpop(self, key: str) -> str | None:
        if self.simulate_failure:
            raise ConnectionError("Simulated Redis connection failure")
        q = self._queues.get(key)
        if q and len(q) > 0:
            return q.popleft()
        return None

    async def blpop(self, key: str, timeout: int = 1) -> tuple[str, str] | None:
        if self.simulate_failure:
            raise ConnectionError("Simulated Redis connection failure")
        item = await self.lpop(key)
        if item is not None:
            return (key, item)
        return None

    async def llen(self, key: str) -> int:
        if self.simulate_failure:
            raise ConnectionError("Simulated Redis connection failure")
        return len(self._queues.get(key, []))

    async def delete(self, *keys: str) -> int:
        if self.simulate_failure:
            raise ConnectionError("Simulated Redis connection failure")
        deleted = 0
        for k in keys:
            if k in self._queues:
                del self._queues[k]
                deleted += 1
        return deleted

    async def ping(self) -> bool:
        if self.simulate_failure:
            raise ConnectionError("Simulated Redis connection failure")
        return True

    async def aclose(self) -> None:
        pass
