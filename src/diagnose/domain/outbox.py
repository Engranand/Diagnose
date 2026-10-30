"""Transactional outbox domain models and status enums."""

from __future__ import annotations

from enum import StrEnum


class OutboxStatus(StrEnum):
    """Lifecycle status of an outbox event."""

    PENDING = "PENDING"
    PUBLISHED = "PUBLISHED"
    FAILED = "FAILED"
    DEAD = "DEAD"


class OutboxEventType(StrEnum):
    """Standard transactional outbox event types."""

    JOB_CREATED = "job.created"
    ALERT_TRIGGERED = "alert.triggered"
    INCIDENT_TRANSITIONED = "incident.transitioned"
