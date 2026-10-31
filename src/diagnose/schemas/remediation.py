"""Pydantic schemas for Remediation Actions and Executions (Milestone 10.1)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from diagnose.domain.remediation import ActionStatus, ActionType, ExecutionMode, RiskLevel


class ActionCreateRequest(BaseModel):
    """Payload to propose a new remediation action for an incident."""

    service_id: uuid.UUID
    action_type: ActionType
    risk_level: RiskLevel
    execution_mode: ExecutionMode = ExecutionMode.DRY_RUN
    title: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=5000)
    rationale: str | None = Field(default=None, max_length=5000)
    preconditions: dict[str, Any] | None = None
    expected_outcome: str | None = Field(default=None, max_length=5000)
    rollback_plan: str | None = Field(default=None, max_length=5000)

    model_config = ConfigDict(extra="ignore")

    @field_validator("title")
    @classmethod
    def validate_title(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Action title cannot be empty or whitespace.")
        return trimmed


class ActionRejectRequest(BaseModel):
    """Payload to reject a proposed remediation action."""

    reason: str | None = Field(default=None, max_length=1000)

    model_config = ConfigDict(extra="ignore")


class ActionExecutionResponse(BaseModel):
    """Response payload representing an execution attempt."""

    id: uuid.UUID
    organization_id: uuid.UUID
    action_id: uuid.UUID
    status: str
    execution_mode: ExecutionMode
    started_at: datetime | None
    completed_at: datetime | None
    result: dict[str, Any] | None = None
    error: str | None = None
    executor_type: str
    correlation_id: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RemediationActionResponse(BaseModel):
    """Response payload representing a remediation action."""

    id: uuid.UUID
    organization_id: uuid.UUID
    incident_id: uuid.UUID
    service_id: uuid.UUID
    action_type: ActionType
    risk_level: RiskLevel
    status: ActionStatus
    execution_mode: ExecutionMode
    title: str
    description: str | None = None
    rationale: str | None = None
    preconditions: dict[str, Any] | None = None
    expected_outcome: str | None = None
    rollback_plan: str | None = None
    proposed_by: uuid.UUID | None = None
    approved_by: uuid.UUID | None = None
    version: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RemediationActionDetailResponse(RemediationActionResponse):
    """Detailed response payload including all execution attempts."""

    executions: list[ActionExecutionResponse] = []
