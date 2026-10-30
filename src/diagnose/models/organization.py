"""Organization ORM model."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, CheckConstraint, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from diagnose.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from diagnose.models.alert import Alert
    from diagnose.models.audit_log import AuditLog
    from diagnose.models.evidence import Evidence
    from diagnose.models.incident import Incident
    from diagnose.models.incident_event import IncidentEvent
    from diagnose.models.service import Service
    from diagnose.models.user import User


class Organization(Base, TimestampMixin):
    """Tenant organization."""

    __tablename__ = "organizations"
    __table_args__ = (
        CheckConstraint("length(name) > 0", name="ck_organizations_name_not_empty"),
        CheckConstraint("length(slug) > 0", name="ck_organizations_slug_not_empty"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    slug: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        index=True,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    # Relationships
    users: Mapped[list[User]] = relationship(
        "User",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    audit_logs: Mapped[list[AuditLog]] = relationship(
        "AuditLog",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    services: Mapped[list[Service]] = relationship(
        "Service",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    incidents: Mapped[list[Incident]] = relationship(
        "Incident",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    incident_events: Mapped[list[IncidentEvent]] = relationship(
        "IncidentEvent",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    alerts: Mapped[list[Alert]] = relationship(
        "Alert",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    evidence_items: Mapped[list[Evidence]] = relationship(
        "Evidence",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
