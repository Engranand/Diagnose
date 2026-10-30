"""SQLAlchemy ORM models for Root-Cause Analysis (Milestone 8)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship as orm_relationship

from diagnose.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from diagnose.models.incident import Incident
    from diagnose.models.organization import Organization
    from diagnose.models.service import Service


class InvestigationRun(Base, TimestampMixin):
    """Execution run of a deterministic root-cause investigation for an incident."""

    __tablename__ = "investigation_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED')",
            name="ck_investigation_runs_status",
        ),
        UniqueConstraint(
            "organization_id",
            "incident_id",
            "run_number",
            name="uq_investigation_runs_org_inc_run_num",
        ),
        Index("ix_investigation_runs_org_incident_id", "organization_id", "incident_id"),
        Index("ix_investigation_runs_org_status", "organization_id", "status"),
        Index("ix_investigation_runs_org_created_at", "organization_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="PENDING",
    )
    run_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    # Relationships
    steps: Mapped[list[InvestigationStep]] = orm_relationship(
        "InvestigationStep",
        back_populates="run",
        cascade="all, delete-orphan",
        order_by="InvestigationStep.created_at.asc()",
    )
    timeline_events: Mapped[list[InvestigationTimelineEvent]] = orm_relationship(
        "InvestigationTimelineEvent",
        back_populates="run",
        cascade="all, delete-orphan",
        order_by="InvestigationTimelineEvent.timestamp.asc()",
    )
    correlations: Mapped[list[EvidenceCorrelation]] = orm_relationship(
        "EvidenceCorrelation",
        back_populates="run",
        cascade="all, delete-orphan",
        order_by="EvidenceCorrelation.created_at.asc()",
    )
    candidate_causes: Mapped[list[CandidateCause]] = orm_relationship(
        "CandidateCause",
        back_populates="run",
        cascade="all, delete-orphan",
        order_by="CandidateCause.score.desc()",
    )
    hypotheses: Mapped[list[InvestigationHypothesis]] = orm_relationship(
        "InvestigationHypothesis",
        back_populates="run",
        cascade="all, delete-orphan",
        order_by="InvestigationHypothesis.rank.asc()",
    )


class InvestigationStep(Base):
    """Deterministic step executed during an investigation run."""

    __tablename__ = "investigation_steps"
    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED')",
            name="ck_investigation_steps_status",
        ),
        CheckConstraint(
            "step_type IN ('EVIDENCE_COLLECTION', 'TIMELINE_BUILD', 'CORRELATION', 'HYPOTHESIS_GENERATION', 'HYPOTHESIS_SCORING', 'FINALIZATION')",
            name="ck_investigation_steps_type",
        ),
        Index("ix_investigation_steps_org_run_id", "organization_id", "investigation_run_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    investigation_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("investigation_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    step_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="PENDING",
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    step_metadata: Mapped[dict[str, Any] | None] = mapped_column(
        "metadata",
        JSON,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    run: Mapped[InvestigationRun] = orm_relationship(
        "InvestigationRun",
        back_populates="steps",
    )


class InvestigationTimelineEvent(Base):
    """Normalized, chronologically sorted event in an investigation timeline."""

    __tablename__ = "investigation_timeline_events"
    __table_args__ = (
        Index("ix_timeline_org_run_timestamp", "organization_id", "investigation_run_id", "timestamp"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    investigation_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("investigation_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    source_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    source_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    service_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("services.id", ondelete="SET NULL"),
        nullable=True,
    )
    summary: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    reliability: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="MEDIUM",
    )
    event_metadata: Mapped[dict[str, Any] | None] = mapped_column(
        "metadata",
        JSON,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    run: Mapped[InvestigationRun] = orm_relationship(
        "InvestigationRun",
        back_populates="timeline_events",
    )


class EvidenceCorrelation(Base):
    """Explainable correlation relationship between evidence items."""

    __tablename__ = "investigation_correlations"
    __table_args__ = (
        CheckConstraint(
            "correlation_type IN ('TEMPORAL', 'SERVICE', 'INCIDENT', 'ALERT', 'RELIABILITY')",
            name="ck_correlations_type",
        ),
        CheckConstraint(
            "strength IN ('WEAK', 'MODERATE', 'STRONG')",
            name="ck_correlations_strength",
        ),
        CheckConstraint(
            "score >= 0.0 AND score <= 1.0",
            name="ck_correlations_score",
        ),
        Index("ix_correlations_org_run_id", "organization_id", "investigation_run_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    investigation_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("investigation_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source_evidence_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    target_evidence_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    correlation_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    strength: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )
    score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    explanation: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    run: Mapped[InvestigationRun] = orm_relationship(
        "InvestigationRun",
        back_populates="correlations",
    )


class CandidateCause(Base):
    """Candidate root cause derived from collected incident evidence."""

    __tablename__ = "investigation_candidate_causes"
    __table_args__ = (
        CheckConstraint(
            "cause_type IN ('DEPLOYMENT', 'CONFIGURATION', 'SERVICE_FAILURE', 'DEPENDENCY_FAILURE', 'ALERT_PATTERN', 'UNKNOWN')",
            name="ck_candidate_causes_type",
        ),
        CheckConstraint(
            "score >= 0.0 AND score <= 1.0",
            name="ck_candidate_causes_score",
        ),
        Index("ix_candidate_causes_org_run_id", "organization_id", "investigation_run_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    investigation_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("investigation_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    cause_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    service_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("services.id", ondelete="SET NULL"),
        nullable=True,
    )
    score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="CANDIDATE",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    run: Mapped[InvestigationRun] = orm_relationship(
        "InvestigationRun",
        back_populates="candidate_causes",
    )
    hypotheses: Mapped[list[InvestigationHypothesis]] = orm_relationship(
        "InvestigationHypothesis",
        back_populates="candidate_cause",
    )


class InvestigationHypothesis(Base, TimestampMixin):
    """Ranked root cause hypothesis evaluated against supporting/contradicting evidence."""

    __tablename__ = "investigation_hypotheses"
    __table_args__ = (
        CheckConstraint(
            "confidence IN ('LOW', 'MEDIUM', 'HIGH', 'VERY_HIGH')",
            name="ck_hypotheses_confidence",
        ),
        CheckConstraint(
            "status IN ('CANDIDATE', 'SUPPORTED', 'WEAKENED', 'REJECTED', 'SELECTED')",
            name="ck_hypotheses_status",
        ),
        CheckConstraint(
            "score >= 0.0 AND score <= 1.0",
            name="ck_hypotheses_score",
        ),
        Index("ix_hypotheses_org_run_id", "organization_id", "investigation_run_id"),
        Index("ix_hypotheses_org_rank", "organization_id", "investigation_run_id", "rank"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    investigation_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("investigation_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    candidate_cause_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("investigation_candidate_causes.id", ondelete="SET NULL"),
        nullable=True,
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    explanation: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    confidence: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )
    score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    rank: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="CANDIDATE",
    )

    # Relationships
    run: Mapped[InvestigationRun] = orm_relationship(
        "InvestigationRun",
        back_populates="hypotheses",
    )
    candidate_cause: Mapped[CandidateCause | None] = orm_relationship(
        "CandidateCause",
        back_populates="hypotheses",
    )
    evidence_links: Mapped[list[HypothesisEvidence]] = orm_relationship(
        "HypothesisEvidence",
        back_populates="hypothesis",
        cascade="all, delete-orphan",
    )


class HypothesisEvidence(Base):
    """Link between a hypothesis and supporting/contradicting evidence with deterministic contribution."""

    __tablename__ = "investigation_hypothesis_evidence"
    __table_args__ = (
        CheckConstraint(
            "relationship IN ('SUPPORTING', 'CONTRADICTING', 'NEUTRAL')",
            name="ck_hypo_evidence_relationship",
        ),
        Index("ix_hypo_evidence_org_run", "organization_id", "investigation_run_id"),
        Index("ix_hypo_evidence_hypothesis_id", "hypothesis_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    investigation_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("investigation_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    hypothesis_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("investigation_hypotheses.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    evidence_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    evidence_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    relationship: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )
    contribution: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    explanation: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    hypothesis: Mapped[InvestigationHypothesis] = orm_relationship(
        "InvestigationHypothesis",
        back_populates="evidence_links",
    )
