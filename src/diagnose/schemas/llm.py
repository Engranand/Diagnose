"""Pydantic schemas for LLM-powered incident investigation (Milestone 9)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from diagnose.domain.investigation import ConfidenceBand
from diagnose.domain.llm import (
    AnalysisStatus,
    MAX_EVIDENCE_REFS,
    MAX_KEY_FINDINGS,
    MAX_NEXT_CHECKS,
    MAX_REASONING_LENGTH,
    MAX_REMEDIATION_SUGGESTIONS,
    MAX_SUMMARY_LENGTH,
)


class HypothesisAssessment(BaseModel):
    """Detailed reasoning and evidence assessment for a specific deterministic hypothesis."""

    model_config = ConfigDict(extra="forbid")

    hypothesis_id: UUID = Field(
        ...,
        description="ID of an existing candidate hypothesis evaluated by M8.",
    )
    assessment: str = Field(
        ...,
        max_length=MAX_REASONING_LENGTH,
        description="Concise evaluation of the hypothesis likelihood based on evidence.",
    )
    reasoning: str = Field(
        ...,
        max_length=MAX_REASONING_LENGTH,
        description="Evidence-grounded rationale explaining why the evidence supports or weakens this hypothesis.",
    )
    evidence_refs: list[str] = Field(
        default_factory=list,
        max_length=MAX_EVIDENCE_REFS,
        description="List of exact M8 evidence IDs supporting or refuting this assessment.",
    )
    confidence_band: ConfidenceBand = Field(
        ...,
        description="Evaluated confidence band corresponding to evidence backing.",
    )


class InvestigationAnalysisOutput(BaseModel):
    """Strict structured output contract produced by the LLM reasoning layer."""

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(
        ...,
        max_length=MAX_SUMMARY_LENGTH,
        description="Executive incident summary synthesized strictly from M8 evidence.",
    )
    primary_hypothesis_id: UUID | None = Field(
        default=None,
        description="Hypothesis ID most supported by available telemetry, or null if evidence is inconclusive.",
    )
    hypothesis_assessments: list[HypothesisAssessment] = Field(
        default_factory=list,
        description="Evaluations of competing candidate hypotheses.",
    )
    key_findings: list[str] = Field(
        default_factory=list,
        max_length=MAX_KEY_FINDINGS,
        description="Key factual observations directly observed in telemetry.",
    )
    supporting_evidence: list[str] = Field(
        default_factory=list,
        max_length=MAX_EVIDENCE_REFS,
        description="Evidence IDs corroborating the primary hypothesis or main failure sequence.",
    )
    contradicting_evidence: list[str] = Field(
        default_factory=list,
        max_length=MAX_EVIDENCE_REFS,
        description="Evidence IDs weakening or contradicting candidate causes.",
    )
    missing_evidence: list[str] = Field(
        default_factory=list,
        description="Gaps in telemetry or unobserved signals required for conclusive diagnosis.",
    )
    next_checks: list[str] = Field(
        default_factory=list,
        max_length=MAX_NEXT_CHECKS,
        description="Recommended targeted queries or verification checks for engineers.",
    )
    remediation_suggestions: list[str] = Field(
        default_factory=list,
        max_length=MAX_REMEDIATION_SUGGESTIONS,
        description="Mitigation actions suggested for human engineering review only.",
    )
    limitations: str = Field(
        ...,
        max_length=MAX_SUMMARY_LENGTH,
        description="Explicit limitations and caveats of this analysis.",
    )
    model_metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Metadata recorded by the LLM provider (e.g. tokens, latency).",
    )


class CreateAnalysisRequest(BaseModel):
    """Payload to trigger an LLM analysis run."""

    model_config = ConfigDict(extra="forbid")

    force_refresh: bool = Field(
        default=False,
        description="If true, bypasses completed input-hash cache and executes fresh LLM analysis.",
    )


class InvestigationAnalysisResponse(BaseModel):
    """API response schema for an investigation analysis."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    investigation_id: UUID
    model_provider: str
    model_name: str
    prompt_version: str
    status: AnalysisStatus
    summary: str | None = None
    structured_output: InvestigationAnalysisOutput | None = None
    input_hash: str
    output_hash: str | None = None
    error: str | None = None
    created_at: datetime
    updated_at: datetime
