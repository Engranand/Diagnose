"""Alert domain models, enums, and validations."""

from __future__ import annotations

from enum import StrEnum


class AlertSeverity(StrEnum):
    """Severity levels for alerts."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


SEVERITY_ORDER: dict[AlertSeverity | str, int] = {
    AlertSeverity.LOW: 1,
    AlertSeverity.MEDIUM: 2,
    AlertSeverity.HIGH: 3,
    AlertSeverity.CRITICAL: 4,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def should_escalate_severity(
    current: AlertSeverity | str, incoming: AlertSeverity | str
) -> bool:
    """Return True if incoming severity has higher priority than current severity.

    Priority ranking: CRITICAL (4) > HIGH (3) > MEDIUM (2) > LOW (1).
    """
    return SEVERITY_ORDER.get(incoming, 0) > SEVERITY_ORDER.get(current, 0)


class AlertStatus(StrEnum):
    """Operational status of an alert.

    - FIRING: Alert is active and ongoing. Ingestion with the same fingerprint
      while FIRING is deduplicated idempotently (HTTP 200).
    - RESOLVED: Alert condition has cleared. Subsequent ingestion with the same
      fingerprint starts a new active alert occurrence (HTTP 201).
    - SUPPRESSED: Alert signal is muted/inactive. Subsequent ingestion with the same
      fingerprint initiates a new FIRING alert occurrence (HTTP 201).
    """

    FIRING = "FIRING"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"
