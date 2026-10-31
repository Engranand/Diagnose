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
) -> None:
    """Validate that transition from current_status to target_status is valid.

    Raises:
        InvalidStateTransition: If transition is not permitted by the state machine.
    """
    curr = current_status if isinstance(current_status, ActionStatus) else ActionStatus(current_status)
    target = target_status if isinstance(target_status, ActionStatus) else ActionStatus(target_status)

    allowed = VALID_ACTION_TRANSITIONS.get(curr, set())
    if target not in allowed:
        raise InvalidStateTransition("RemediationAction", curr.value, target.value)
