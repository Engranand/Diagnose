"""Deterministic, sanitized InvestigationContext DTO for LLM analysis (Milestone 9)."""

from __future__ import annotations

import hashlib
import json
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from diagnose.domain.llm import PROMPT_VERSION


class SanitizedIncident(BaseModel):
    """Sanitized incident context."""

    model_config = ConfigDict(extra="forbid")

    id: str
    incident_number: int
    title: str
    description: str | None = None
    severity: str
    status: str
    detected_at: str
    acknowledged_at: str | None = None
    resolved_at: str | None = None


class SanitizedService(BaseModel):
    """Sanitized service context."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    slug: str
    tier: str
    description: str | None = None


class SanitizedTimelineEvent(BaseModel):
    """Sanitized chronological timeline event."""

    model_config = ConfigDict(extra="forbid")

    timestamp: str
    source_id: str
    source_type: str
    event_type: str
    summary: str
    reliability: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class SanitizedCorrelation(BaseModel):
    """Sanitized pairwise evidence correlation."""

    model_config = ConfigDict(extra="forbid")

    source_evidence_id: str
    target_evidence_id: str
    correlation_type: str
    strength: str
    score: float
    explanation: str


class SanitizedCandidateCause(BaseModel):
    """Sanitized candidate root cause."""

    model_config = ConfigDict(extra="forbid")

    id: str
    cause_type: str
    title: str
    description: str | None = None
    service_id: str | None = None


class SanitizedHypothesisEvidence(BaseModel):
    """Sanitized evidence link for a hypothesis."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    evidence_type: str
    relationship: str
    contribution: float
    explanation: str


class SanitizedHypothesis(BaseModel):
    """Sanitized evaluated hypothesis."""

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    explanation: str
    confidence: str
    score: float
    rank: int
    status: str
    evidence_links: list[SanitizedHypothesisEvidence] = Field(default_factory=list)


class InvestigationContext(BaseModel):
    """Immutable, bounded, evidence-grounded snapshot consumed by the LLM."""

    model_config = ConfigDict(extra="forbid")

    investigation_id: str
    run_number: int
    completed_at: str | None = None
    incident: SanitizedIncident
    service: SanitizedService | None = None
    timeline: list[SanitizedTimelineEvent] = Field(default_factory=list)
    correlations: list[SanitizedCorrelation] = Field(default_factory=list)
    candidate_causes: list[SanitizedCandidateCause] = Field(default_factory=list)
    hypotheses: list[SanitizedHypothesis] = Field(default_factory=list)
    valid_evidence_ids: list[str] = Field(default_factory=list)
    valid_hypothesis_ids: list[str] = Field(default_factory=list)

    def to_canonical_json(self) -> str:
        """Produce deterministic, sort-keyed JSON serialization."""
        return json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))

    def compute_input_hash(self, model_provider: str, model_name: str, prompt_version: str = PROMPT_VERSION) -> str:
        """Generate deterministic SHA-256 hash of context, prompt version, and model config."""
        hasher = hashlib.sha256()
        hasher.update(self.investigation_id.encode("utf-8"))
        if self.completed_at:
            hasher.update(self.completed_at.encode("utf-8"))
        hasher.update(self.to_canonical_json().encode("utf-8"))
        hasher.update(prompt_version.encode("utf-8"))
        hasher.update(model_provider.encode("utf-8"))
        hasher.update(model_name.encode("utf-8"))
        return hasher.hexdigest()
