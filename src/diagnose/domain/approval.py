"""Approval domain model and decisions (Milestone 10.4).

Enforces human-in-the-loop authorization, strict separation of duties,
and cryptographic provenance linking (policy version & dry-run plan hash).
"""

from __future__ import annotations

import uuid
from enum import StrEnum

from diagnose.domain.exceptions import (
    DryRunHashMismatchError,
    InvalidStateTransition,
    SeparationOfDutiesError,
)
from diagnose.domain.remediation import ActionStatus


class ApprovalDecision(StrEnum):
    """Permitted human approval decisions."""

    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


def validate_separation_of_duties(
    proposer_id: uuid.UUID | None,
    approver_id: uuid.UUID | None,
) -> None:
    """Ensure the user approving the action is NOT the user who proposed it.
    
    Strict separation of duties: Even an ADMIN cannot approve their own action.
    """
    if proposer_id is not None and approver_id is not None and proposer_id == approver_id:
        raise SeparationOfDutiesError(
            "Separation of duties violation: action proposer cannot approve their own action."
        )


def validate_approval_state(current_status: str | ActionStatus) -> None:
    """Ensure action is in PENDING_APPROVAL state before human approval."""
    status_str = current_status.value if isinstance(current_status, ActionStatus) else str(current_status)
    if status_str != ActionStatus.PENDING_APPROVAL.value:
        raise InvalidStateTransition(
            entity_type="RemediationAction",
            current_state=status_str,
            target_state=ActionStatus.APPROVED.value,
        )


def validate_rejection_state(current_status: str | ActionStatus) -> None:
    """Ensure action is in PENDING_APPROVAL state before human rejection."""
    status_str = current_status.value if isinstance(current_status, ActionStatus) else str(current_status)
    if status_str != ActionStatus.PENDING_APPROVAL.value:
        raise InvalidStateTransition(
            entity_type="RemediationAction",
            current_state=status_str,
            target_state=ActionStatus.REJECTED.value,
        )


def validate_dry_run_hash(
    actual_plan_hash: str | None,
    expected_plan_hash: str | None,
) -> None:
    """Verify that expected dry-run plan hash matches the actual recorded dry-run plan hash."""
    if expected_plan_hash is not None:
        if actual_plan_hash is None:
            raise DryRunHashMismatchError(
                f"Dry run plan hash mismatch: expected '{expected_plan_hash}', but no dry run plan hash was found."
            )
        if actual_plan_hash != expected_plan_hash:
            raise DryRunHashMismatchError(
                f"Dry run plan hash mismatch: expected '{expected_plan_hash}', found '{actual_plan_hash}'."
            )
