"""Pydantic schemas for Action Approvals (Milestone 10.4)."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ActionApproveRequest(BaseModel):
    """Payload for approving a pending remediation action."""

    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(
        default=None,
        max_length=2000,
        description="Optional justification or comment for the human approval",
    )
    dry_run_plan_hash: str | None = Field(
        default=None,
        max_length=64,
        description="Optional expected dry-run plan hash to verify deterministic plan fidelity",
    )


class ActionRejectRequest(BaseModel):
    """Payload for rejecting a pending remediation action."""

    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(
        default=None,
        max_length=2000,
        description="Optional reason or feedback for rejecting the action",
    )


class ActionApprovalResponse(BaseModel):
    """Response schema representing an immutable human approval or rejection record."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    action_id: UUID
    approver_user_id: UUID
    decision: str
    reason: str | None = None
    policy_set_version: int
    policy_evaluation_id: UUID | None = None
    dry_run_plan_hash: str | None = None
    created_at: datetime
    decided_at: datetime
