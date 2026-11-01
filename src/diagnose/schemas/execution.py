"""Pydantic schemas for Controlled Remediation Execution (Milestone 10.5)."""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class ActionExecuteRequest(BaseModel):
    """Payload to trigger controlled execution of an approved remediation action."""

    model_config = ConfigDict(extra="forbid")

    parameters: dict[str, Any] | None = Field(
        default=None,
        description="Optional execution parameter overrides",
    )
    executor_type: str = Field(
        default="SIMULATOR",
        description="Executor type to run (must be registered, e.g. SIMULATOR)",
    )
    idempotency_key: str | None = Field(
        default=None,
        description="Optional client idempotency key",
    )
