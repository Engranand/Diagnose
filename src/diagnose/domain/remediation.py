"""Domain models, enums, and state machine for Remediation Actions (Milestone 10.1)."""

from __future__ import annotations

from enum import StrEnum

from diagnose.domain.exceptions import InvalidStateTransition


class ActionType(StrEnum):
    """Categorized remediation intervention types."""

    RESTART_SERVICE = "RESTART_SERVICE"
    SCALE_SERVICE = "SCALE_SERVICE"
    ROLLBACK_DEPLOYMENT = "ROLLBACK_DEPLOYMENT"
    UPDATE_CONFIGURATION = "UPDATE_CONFIGURATION"
    RUN_DIAGNOSTIC = "RUN_DIAGNOSTIC"


class RiskLevel(StrEnum):
    """Risk severity associated with proposing and executing a remediation action."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ActionStatus(StrEnum):
    """Lifecycle state machine for a remediation action."""

    PROPOSED = "PROPOSED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTING = "EXECUTING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ExecutionMode(StrEnum):
    """Execution mode of a remediation action or execution attempt."""

    DRY_RUN = "DRY_RUN"
    EXECUTE = "EXECUTE"


class ExecutorType(StrEnum):
    """Actor or subsystem driving execution."""

    MANUAL = "MANUAL"
    SYSTEM = "SYSTEM"
    SIMULATOR = "SIMULATOR"


# ── DETERMINISTIC STATE MACHINE TRANSITIONS ──────────────────────────────────
# PROPOSED -> PENDING_APPROVAL -> APPROVED -> EXECUTING -> SUCCEEDED
# Failure & Cancellation paths:
#   EXECUTING -> FAILED
#   PENDING_APPROVAL -> REJECTED
#   PROPOSED -> CANCELLED
#   PENDING_APPROVAL -> CANCELLED
#   APPROVED -> CANCELLED
VALID_ACTION_TRANSITIONS: dict[ActionStatus, set[ActionStatus]] = {
    ActionStatus.PROPOSED: {ActionStatus.PENDING_APPROVAL, ActionStatus.CANCELLED},
    ActionStatus.PENDING_APPROVAL: {
        ActionStatus.APPROVED,
        ActionStatus.REJECTED,
        ActionStatus.CANCELLED,
    },
    ActionStatus.APPROVED: {ActionStatus.EXECUTING, ActionStatus.CANCELLED},
    ActionStatus.EXECUTING: {ActionStatus.SUCCEEDED, ActionStatus.FAILED},
    ActionStatus.REJECTED: set(),
    ActionStatus.SUCCEEDED: set(),
    ActionStatus.FAILED: set(),
    ActionStatus.CANCELLED: set(),
}


def validate_action_transition(
    current_status: ActionStatus | str,
    target_status: ActionStatus | str,
    auto_approval_provenance: Any | None = None,
) -> None:
    """Validate that transition from current_status to target_status is valid.

    Direct transition from PROPOSED to APPROVED is strictly restricted to cases with
    authoritative, persisted policy auto-approval provenance (decision == 'ALLOW').

    Raises:
        InvalidStateTransition: If transition is not permitted by the state machine.
    """
    curr = current_status if isinstance(current_status, ActionStatus) else ActionStatus(current_status)
    target = target_status if isinstance(target_status, ActionStatus) else ActionStatus(target_status)

    if curr == ActionStatus.PROPOSED and target == ActionStatus.APPROVED:
        if auto_approval_provenance is None:
            raise InvalidStateTransition("RemediationAction", curr.value, target.value)
        decision = getattr(auto_approval_provenance, "decision", None)
        if decision != "ALLOW":
            raise InvalidStateTransition("RemediationAction", curr.value, target.value)
        return

    allowed = VALID_ACTION_TRANSITIONS.get(curr, set())
    if target not in allowed:
        raise InvalidStateTransition("RemediationAction", curr.value, target.value)
