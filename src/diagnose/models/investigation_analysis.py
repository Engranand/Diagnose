"""Investigation Analysis ORM model — LLM reasoning and evidence-grounded interpretation (M9)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    JSON,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from diagnose.models.base import Base

if TYPE_CHECKING:
    from diagnose.models.investigation import InvestigationRun
    from diagnose.models.organization import Organization


class InvestigationAnalysis(Base):
    """Persisted LLM-generated incident analysis grounded in M8 deterministic evidence."""

    __tablename__ = "investigation_analyses"
    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED')",
            name="ck_investigation_analyses_status",
        ),
        Index(
            "ix_investigation_analyses_org_investigation",
            "organization_id",
            "investigation_id",
        ),
        Index("ix_investigation_analyses_org_hash", "organization_id", "input_hash"),
        Index("ix_investigation_analyses_org_status", "organization_id", "status"),
        Index("ix_investigation_analyses_org_created_at", "organization_id", "created_at"),
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
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("investigation_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    model_provider: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    model_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    prompt_version: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="PENDING",
    )
    summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    structured_output: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
    )
    input_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    output_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    investigation: Mapped[InvestigationRun] = relationship(
        "InvestigationRun",
        back_populates="analyses",
    )
    organization: Mapped[Organization] = relationship(
        "Organization",
    )
