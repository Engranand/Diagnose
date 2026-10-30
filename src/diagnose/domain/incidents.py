"""Incident domain model, enums, and deterministic lifecycle state machine."""

from __future__ import annotations

from enum import StrEnum

from diagnose.domain.exceptions import InvalidStateTransition, ValidationError


class IncidentSeverity(StrEnum):
    """Incident severity classification."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class IncidentStatus(StrEnum):
    """Explicit lifecycle states for an incident."""

    DETECTED = "DETECTED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    IDENTIFIED = "IDENTIFIED"
    MITIGATING = "MITIGATING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


# Deterministic state machine transition rules:
# Source Status -> Allowed Target Statuses
VALID_TRANSITIONS: dict[IncidentStatus, set[IncidentStatus]] = {
    IncidentStatus.DETECTED: {
        IncidentStatus.ACKNOWLEDGED,
    },
    IncidentStatus.ACKNOWLEDGED: {
        IncidentStatus.INVESTIGATING,
    },
    IncidentStatus.INVESTIGATING: {
        IncidentStatus.IDENTIFIED,
        IncidentStatus.MITIGATING,
    },
    IncidentStatus.IDENTIFIED: {
        IncidentStatus.MITIGATING,
    },
    IncidentStatus.MITIGATING: {
        IncidentStatus.RESOLVED,
    },
    IncidentStatus.RESOLVED: {
        IncidentStatus.CLOSED,
        IncidentStatus.INVESTIGATING,  # Re-opening if issue resurfaces
    },
    IncidentStatus.CLOSED: set(),  # Terminal state: zero allowed transitions
}


def validate_incident_transition(
    current_status: IncidentStatus | str,
    target_status: IncidentStatus | str,
) -> tuple[IncidentStatus, IncidentStatus]:
    """Validate that the state machine allows transition from current to target status.

    Raises:
        ValidationError: If either status is invalid.
        InvalidStateTransition: If the transition is not allowed by domain rules.
    """
    try:
        current = (
            current_status
            if isinstance(current_status, IncidentStatus)
            else IncidentStatus(str(current_status).upper())
        )
    except ValueError:
        raise ValidationError(f"Invalid current incident status '{current_status}'")

    try:
        target = (
            target_status
            if isinstance(target_status, IncidentStatus)
            else IncidentStatus(str(target_status).upper())
        )
    except ValueError:
        raise ValidationError(f"Invalid target incident status '{target_status}'")

    allowed_targets = VALID_TRANSITIONS.get(current, set())
    if target not in allowed_targets:
        raise InvalidStateTransition(
            entity_type="Incident",
            current_state=current.value,
            target_state=target.value,
        )

    return current, target
