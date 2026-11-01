"""Pydantic schemas for Remediation Action Dry-Run Executor (Milestone 10.3)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class DryRunRequest(BaseModel):
    """Optional request payload for triggering a dry-run execution."""

    model_config = ConfigDict(extra="forbid")

    idempotency_key: str | None = Field(
        default=None,
        description="Optional client-provided idempotency key",
    )
    parameters: dict[str, Any] | None = Field(
        default=None,
        description="Optional execution parameter overrides",
    )
    executor_type: str = Field(
        default="SIMULATOR",
        description="Executor type (must be SIMULATOR, MANUAL, or SYSTEM)",
    )


class DryRunStepResponse(BaseModel):
    """Execution plan step description."""

    model_config = ConfigDict(from_attributes=True)

    order: int
    name: str
    description: str
    target: str
    action: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    estimated_duration_sec: float
    is_reversible: bool
    rollback_step: str | None = None


class DryRunPlanResponse(BaseModel):
    """Full deterministic execution plan."""

    model_config = ConfigDict(from_attributes=True)

    action_id: UUID
    organization_id: UUID
    action_type: str
    service_id: UUID
    service_name: str
    environment: str
    executor_type: str
    execution_mode: str
    normalized_parameters: dict[str, Any] = Field(default_factory=dict)
    ordered_steps: list[DryRunStepResponse] = Field(default_factory=list)
    expected_effects: list[str] = Field(default_factory=list)
    safety_checks: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    plan_hash: str


class DryRunResponse(BaseModel):
    """Outcome of a dry-run execution."""

    model_config = ConfigDict(from_attributes=True)

    status: str = Field(
        default="DRY_RUN_SUCCESS",
        description="Dry run status: DRY_RUN_SUCCESS or DRY_RUN_FAILED",
    )
    action_id: UUID
    execution_id: UUID
    plan: DryRunPlanResponse | None = None
    simulated_outcome: str
    safety_checks_passed: bool
    expected_effects: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    no_real_execution: bool = Field(
        default=True,
        description="Immutable flag confirming no real infrastructure mutations occurred",
    )
    started_at: datetime
    completed_at: datetime
