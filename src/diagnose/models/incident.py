"""Incident ORM model."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from diagnose.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from diagnose.models.alert import Alert
    from diagnose.models.evidence import Evidence
    from diagnose.models.incident_event import IncidentEvent
    from diagnose.models.organization import Organization
    from diagnose.models.service import Service
    from diagnose.models.user import User


class Incident(Base, TimestampMixin):
    """Production incident owned by a tenant organization and targeting a service."""

    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint("length(title) > 0", name="ck_incidents_title_not_empty"),
        CheckConstraint(
            "severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')",
            name="ck_incidents_valid_severity",
        ),
        CheckConstraint(
            "status IN ('DETECTED', 'ACKNOWLEDGED', 'INVESTIGATING', 'IDENTIFIED', 'MITIGATING', 'RESOLVED', 'CLOSED')",
            name="ck_incidents_valid_status",
        ),
        UniqueConstraint(
            "organization_id",
            "incident_number",
            name="uq_incidents_org_incident_number",
        ),
        Index("ix_incidents_org_status", "organization_id", "status"),
        Index("ix_incidents_org_severity", "organization_id", "severity"),
        Index("ix_incidents_org_service_id", "organization_id", "service_id"),
        Index("ix_incidents_org_created_at", "organization_id", "created_at"),
        Index("ix_incidents_org_assigned_user", "organization_id", "assigned_user_id"),
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
    incident_number: Mapped[int] = mapped_column(
        Integer,
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
    severity: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="MEDIUM",
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="DETECTED",
    )
    assigned_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    version: Mapped[int] = mapped_column(
        Integer,
        default=1,
        nullable=False,
    )

    # Relationships
    organization: Mapped[Organization] = relationship(
        "Organization",
        back_populates="incidents",
    )
    service: Mapped[Service] = relationship(
        "Service",
        back_populates="incidents",
    )
    assigned_user: Mapped[User | None] = relationship(
        "User",
        back_populates="assigned_incidents",
    )
    events: Mapped[list[IncidentEvent]] = relationship(
        "IncidentEvent",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentEvent.created_at.asc()",
    )
    alerts: Mapped[list[Alert]] = relationship(
        "Alert",
        back_populates="incident",
    )
    evidence_items: Mapped[list[Evidence]] = relationship(
        "Evidence",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="Evidence.created_at.asc()",
    )
