"""Pydantic schemas for Root-Cause Analysis (Milestone 8)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from diagnose.domain.investigation import (
    CauseType,
    ConfidenceBand,
    CorrelationStrength,
    CorrelationType,
    EvidenceRelationship,
    HypothesisStatus,
    InvestigationStatus,
    InvestigationStepType,
)


class InvestigationStepResponse(BaseModel):
    """Schema for an individual executed investigation step."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    investigation_run_id: UUID
    step_type: InvestigationStepType
    status: InvestigationStatus
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    metadata: dict[str, Any] | None = Field(default=None, alias="step_metadata")
    created_at: datetime


class InvestigationTimelineEventResponse(BaseModel):
    """Schema for an item in the chronologically ordered investigation timeline."""

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: UUID
    organization_id: UUID
    investigation_run_id: UUID
    timestamp: datetime
    event_type: str
    source_type: str
    source_id: str
    service_id: UUID | None = None
    summary: str
    reliability: str
    metadata: dict[str, Any] | None = Field(default=None, alias="event_metadata")
    created_at: datetime


class EvidenceCorrelationResponse(BaseModel):
    """Schema for a deterministic evidence correlation record."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    investigation_run_id: UUID
    source_evidence_id: str
    target_evidence_id: str
    correlation_type: CorrelationType
    strength: CorrelationStrength
    score: float = Field(ge=0.0, le=1.0)
    explanation: str
    created_at: datetime


class CandidateCauseResponse(BaseModel):
    """Schema for a candidate cause evaluated during investigation."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    investigation_run_id: UUID
    cause_type: CauseType
    title: str
    description: str | None = None
    service_id: UUID | None = None
    score: float = Field(ge=0.0, le=1.0)
    status: str
    created_at: datetime


class HypothesisEvidenceResponse(BaseModel):
    """Schema for an evidence item linked to a hypothesis with deterministic contribution."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    hypothesis_id: UUID
    evidence_type: str
    evidence_id: str
    relationship: EvidenceRelationship
    contribution: float
    explanation: str
    created_at: datetime


class InvestigationHypothesisResponse(BaseModel):
    """Schema for an evaluated, ranked root-cause hypothesis."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    investigation_run_id: UUID
    candidate_cause_id: UUID | None = None
    title: str
    explanation: str
    confidence: ConfidenceBand
    score: float = Field(ge=0.0, le=1.0)
    rank: int = Field(ge=1)
    status: HypothesisStatus
    created_at: datetime
    updated_at: datetime
    evidence_links: list[HypothesisEvidenceResponse] = Field(default_factory=list)


class InvestigationRunResponse(BaseModel):
    """Summary schema for an investigation run."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    incident_id: UUID
    status: InvestigationStatus
    run_number: int
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    created_at: datetime
    updated_at: datetime


class InvestigationDetailResponse(InvestigationRunResponse):
    """Detailed schema for an investigation run including its steps and summary counts."""

    steps: list[InvestigationStepResponse] = Field(default_factory=list)
    hypotheses: list[InvestigationHypothesisResponse] = Field(default_factory=list)
