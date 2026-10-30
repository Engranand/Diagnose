"""Alert ORM model — observation event source."""

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

from diagnose.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from diagnose.models.incident import Incident
    from diagnose.models.organization import Organization
    from diagnose.models.service import Service


class Alert(Base, TimestampMixin):
    """Observation event source entity representing a firing, resolved, or suppressed signal."""

    __tablename__ = "alerts"
    __table_args__ = (
        CheckConstraint("length(title) > 0", name="ck_alerts_title_not_empty"),
        CheckConstraint("length(fingerprint) > 0", name="ck_alerts_fingerprint_not_empty"),
        CheckConstraint(
            "severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')",
            name="ck_alerts_valid_severity",
        ),
        CheckConstraint(
            "status IN ('FIRING', 'RESOLVED', 'SUPPRESSED')",
            name="ck_alerts_valid_status",
        ),
        UniqueConstraint(
            "organization_id",
            "fingerprint",
            name="uq_alerts_org_fingerprint",
        ),
        Index("ix_alerts_org_status", "organization_id", "status"),
        Index("ix_alerts_org_severity", "organization_id", "severity"),
        Index("ix_alerts_org_service_id", "organization_id", "service_id"),
        Index("ix_alerts_org_incident_id", "organization_id", "incident_id"),
        Index("ix_alerts_org_fingerprint", "organization_id", "fingerprint"),
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
    service_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("services.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    fingerprint: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    alert_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    severity: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="MEDIUM",
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="FIRING",
    )
    payload: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    organization: Mapped[Organization] = relationship(
        "Organization",
        back_populates="alerts",
    )
    service: Mapped[Service] = relationship(
        "Service",
        back_populates="alerts",
    )
    incident: Mapped[Incident | None] = relationship(
        "Incident",
        back_populates="alerts",
    )
