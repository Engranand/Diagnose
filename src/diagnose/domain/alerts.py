"""Alert domain models, enums, and validations."""

from __future__ import annotations

from enum import StrEnum


class AlertSeverity(StrEnum):
    """Severity levels for alerts."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AlertStatus(StrEnum):
    """Operational status of an alert."""

    FIRING = "FIRING"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"
