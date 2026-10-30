"""Evidence ORM model — immutable investigation artifact."""

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
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from diagnose.models.base import Base

if TYPE_CHECKING:
    from diagnose.models.incident import Incident
    from diagnose.models.organization import Organization
    from diagnose.models.user import User


class Evidence(Base):
    """Immutable investigation artifact attached to an incident."""

    __tablename__ = "evidence"
    __table_args__ = (
        CheckConstraint("length(title) > 0", name="ck_evidence_title_not_empty"),
        CheckConstraint("length(source) > 0", name="ck_evidence_source_not_empty"),
        CheckConstraint(
            "reliability IN ('HIGH', 'MEDIUM', 'LOW')",
            name="ck_evidence_valid_reliability",
        ),
        CheckConstraint(
            "evidence_type IN ('LOG', 'METRIC', 'TRACE', 'ALERT', 'DEPLOYMENT', 'CONFIG', 'EVENT', 'DOCUMENT', 'OTHER')",
            name="ck_evidence_valid_type",
        ),
        UniqueConstraint(
            "organization_id",
            "evidence_hash",
            name="uq_evidence_org_hash",
        ),
        Index("ix_evidence_org_incident_id", "organization_id", "incident_id"),
        Index("ix_evidence_org_type", "organization_id", "evidence_type"),
        Index("ix_evidence_org_observed_at", "organization_id", "observed_at"),
        Index("ix_evidence_org_hash", "organization_id", "evidence_hash"),
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
    evidence_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    content: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    structured_data: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
    )
    observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    collected_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    reliability: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="HIGH",
    )
    evidence_metadata: Mapped[dict[str, Any] | None] = mapped_column(
        "metadata",
        JSON,
        nullable=True,
    )
    evidence_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    organization: Mapped[Organization] = relationship(
        "Organization",
        back_populates="evidence_items",
    )
    incident: Mapped[Incident] = relationship(
        "Incident",
        back_populates="evidence_items",
    )
    collected_by_user: Mapped[User | None] = relationship(
        "User",
        back_populates="collected_evidence",
    )
