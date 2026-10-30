"""IncidentEvent ORM model — immutable timeline history of an incident."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
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
    from diagnose.models.incident import Incident
    from diagnose.models.organization import Organization
    from diagnose.models.user import User


class IncidentEvent(Base):
    """Immutable audit timeline event for an incident."""

    __tablename__ = "incident_events"
    __table_args__ = (
        Index("ix_incident_events_org_id", "organization_id"),
        Index("ix_incident_events_incident_id", "incident_id"),
        Index(
            "ix_incident_events_org_incident_created",
            "organization_id",
            "incident_id",
            "created_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
    )
    event_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    from_status: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )
    to_status: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )
    message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
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
    organization: Mapped[Organization] = relationship(
        "Organization",
        back_populates="incident_events",
    )
    incident: Mapped[Incident] = relationship(
        "Incident",
        back_populates="events",
    )
    actor_user: Mapped[User | None] = relationship(
        "User",
        back_populates="incident_events",
    )
