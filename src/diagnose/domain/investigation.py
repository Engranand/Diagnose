"""Domain definitions, enums, and scoring constants for Root-Cause Analysis (M8)."""

from __future__ import annotations

from enum import StrEnum


class InvestigationStatus(StrEnum):
    """Lifecycle status of an investigation run."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class InvestigationStepType(StrEnum):
    """Sequential deterministic steps in an investigation run."""

    EVIDENCE_COLLECTION = "EVIDENCE_COLLECTION"
    TIMELINE_BUILD = "TIMELINE_BUILD"
    CORRELATION = "CORRELATION"
    HYPOTHESIS_GENERATION = "HYPOTHESIS_GENERATION"
    HYPOTHESIS_SCORING = "HYPOTHESIS_SCORING"
    FINALIZATION = "FINALIZATION"


class CorrelationType(StrEnum):
    """Categorization of evidence correlation."""

    TEMPORAL = "TEMPORAL"
    SERVICE = "SERVICE"
    INCIDENT = "INCIDENT"
    ALERT = "ALERT"
    RELIABILITY = "RELIABILITY"


class CorrelationStrength(StrEnum):
    """Explainable strength classification for correlation."""

    WEAK = "WEAK"
    MODERATE = "MODERATE"
    STRONG = "STRONG"


class CauseType(StrEnum):
    """Supported candidate root cause categories derived from evidence."""

    DEPLOYMENT = "DEPLOYMENT"
    CONFIGURATION = "CONFIGURATION"
    SERVICE_FAILURE = "SERVICE_FAILURE"
    DEPENDENCY_FAILURE = "DEPENDENCY_FAILURE"
    ALERT_PATTERN = "ALERT_PATTERN"
    UNKNOWN = "UNKNOWN"


class HypothesisStatus(StrEnum):
    """Evaluation status of a root cause hypothesis."""

    CANDIDATE = "CANDIDATE"
    SUPPORTED = "SUPPORTED"
    WEAKENED = "WEAKENED"
    REJECTED = "REJECTED"
    SELECTED = "SELECTED"


class ConfidenceBand(StrEnum):
    """Deterministic evidence-support confidence bands."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    VERY_HIGH = "VERY_HIGH"


class EvidenceRelationship(StrEnum):
    """Relationship between an evidence item and a hypothesis."""

    SUPPORTING = "SUPPORTING"
    CONTRADICTING = "CONTRADICTING"
    NEUTRAL = "NEUTRAL"


# ── DETERMINISTIC SCORING WEIGHTS & THRESHOLDS ───────────────────────────────

WEIGHT_TEMPORAL: float = 0.25
WEIGHT_SERVICE_MATCH: float = 0.25
WEIGHT_INCIDENT_ATTACHMENT: float = 0.15
WEIGHT_RELIABILITY: float = 0.15
WEIGHT_SUPPORTING_EVIDENCE: float = 0.20
PENALTY_CONTRADICTING: float = 0.25


def calculate_confidence_band(score: float) -> ConfidenceBand:
    """Map a normalized score [0.0, 1.0] to an explainable confidence band.

    Bands:
        0.00 – 0.29 → LOW
        0.30 – 0.59 → MEDIUM
        0.60 – 0.79 → HIGH
        0.80 – 1.00 → VERY_HIGH
    """
    if score >= 0.80:
        return ConfidenceBand.VERY_HIGH
    if score >= 0.60:
        return ConfidenceBand.HIGH
    if score >= 0.30:
        return ConfidenceBand.MEDIUM
    return ConfidenceBand.LOW
