"""In-memory Async Redis test double for deterministic testing of Redis queue & failure modes."""

from __future__ import annotations

from collections import deque
from typing import Any

from redis.exceptions import ConnectionError


class FakePipeline:
    """Fake async pipeline for batch operations."""

    def __init__(self, redis: FakeAsyncRedis) -> None:
        self.redis = redis
        self.commands: list[tuple[str, tuple[Any, ...]]] = []

    def incr(self, key: str) -> FakePipeline:
        self.commands.append(("incr", (key,)))
        return self

    def ttl(self, key: str) -> FakePipeline:
        self.commands.append(("ttl", (key,)))
        return self

    def expire(self, key: str, seconds: int) -> FakePipeline:
        self.commands.append(("expire", (key, seconds)))
        return self

    async def execute(self) -> list[Any]:
        results = []
        for cmd, args in self.commands:
            method = getattr(self.redis, cmd)
            res = await method(*args)
            results.append(res)
        return results


class FakeAsyncRedis:
    """Deterministic in-memory async Redis double for unit and integration testing."""

    def __init__(self) -> None:
        self._queues: dict[str, deque[str]] = {}
        self._keys: dict[str, Any] = {}
        self._ttls: dict[str, int] = {}
        self.simulate_failure: bool = False

    def pipeline(self) -> FakePipeline:
        return FakePipeline(self)

    async def incr(self, key: str) -> int:
        if self.simulate_failure:
            raise ConnectionError("Simulated Redis connection failure")
        val = int(self._keys.get(key, 0)) + 1
        self._keys[key] = str(val)
        return val

    async def expire(self, key: str, seconds: int) -> bool:
        if self.simulate_failure:
            raise ConnectionError("Simulated Redis connection failure")
        self._ttls[key] = seconds
        return True

    async def ttl(self, key: str) -> int:
        if self.simulate_failure:
            raise ConnectionError("Simulated Redis connection failure")
        return self._ttls.get(key, -1)

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
