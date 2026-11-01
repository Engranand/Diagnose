"""Pydantic schemas for Remediation Policies and Policy Evaluations (Milestone 10.2)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from diagnose.domain.policy import PolicyDecision
from diagnose.domain.remediation import ActionType, ExecutionMode, RiskLevel
from diagnose.domain.roles import Role

VALID_TIERS = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


class PolicyCreateRequest(BaseModel):
    """Payload to create a new remediation policy."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=5000)
    service_id: uuid.UUID | None = None
    service_tier: str | None = None
    action_type: ActionType | None = None
    risk_level: RiskLevel | None = None
    execution_mode: ExecutionMode | None = None
    environment: str | None = Field(default=None, max_length=50)
    actor_role: Role | None = None
    decision: PolicyDecision
    priority: int = Field(default=100, ge=1, le=1000)
    is_active: bool = True

    model_config = ConfigDict(extra="ignore")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Policy name cannot be empty or whitespace.")
        return trimmed

    @field_validator("service_tier")
    @classmethod
    def validate_service_tier(cls, v: str | None) -> str | None:
        if v is not None and v.upper() not in VALID_TIERS:
            raise ValueError(f"service_tier must be one of {VALID_TIERS}")
        return v.upper() if v else None


class PolicyUpdateRequest(BaseModel):
    """Payload to update an existing remediation policy or toggle its activation status."""

    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=5000)
    service_id: uuid.UUID | None = None
    service_tier: str | None = None
    action_type: ActionType | None = None
    risk_level: RiskLevel | None = None
    execution_mode: ExecutionMode | None = None
    environment: str | None = Field(default=None, max_length=50)
    actor_role: Role | None = None
    decision: PolicyDecision | None = None
    priority: int | None = Field(default=None, ge=1, le=1000)
    is_active: bool | None = None

    model_config = ConfigDict(extra="ignore")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str | None) -> str | None:
        if v is None:
            return None
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Policy name cannot be empty or whitespace.")
        return trimmed

    @field_validator("service_tier")
    @classmethod
    def validate_service_tier(cls, v: str | None) -> str | None:
        if v is not None and v.upper() not in VALID_TIERS:
            raise ValueError(f"service_tier must be one of {VALID_TIERS}")
        return v.upper() if v else None


class PolicyResponse(BaseModel):
    """Response payload representing a remediation policy."""

    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    description: str | None = None
    service_id: uuid.UUID | None = None
    service_tier: str | None = None
    action_type: str | None = None
    risk_level: str | None = None
    execution_mode: str | None = None
    environment: str | None = None
    actor_role: str | None = None
    decision: str
    priority: int
    is_active: bool
    version: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PolicyEvaluationResponse(BaseModel):
    """Response payload representing a policy evaluation outcome."""

    id: uuid.UUID
    organization_id: uuid.UUID
    action_id: uuid.UUID | None = None
    policy_id: uuid.UUID | None = None
    policy_version: int | None = None
    policy_set_version: int
    decision: str
    context_hash: str
    context_snapshot: dict[str, Any]
    winning_policy_snapshot: dict[str, Any] | None = None
    all_matched_policies: list[dict[str, Any]] = []
    reasons: list[str] = []
    evaluated_by: uuid.UUID | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
