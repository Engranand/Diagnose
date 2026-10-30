"""User ORM model."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, CheckConstraint, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from diagnose.domain.roles import Role
from diagnose.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from diagnose.models.evidence import Evidence
    from diagnose.models.incident import Incident
    from diagnose.models.incident_event import IncidentEvent
    from diagnose.models.organization import Organization


class User(Base, TimestampMixin):
    """User account scoped to an Organization."""

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "email", name="uq_users_organization_id_email"
        ),
        CheckConstraint(
            f"role IN ('{Role.ADMIN}', '{Role.ENGINEER}', '{Role.RESPONDER}', '{Role.VIEWER}')",
            name="ck_users_valid_role",
        ),
        Index("ix_users_organization_id", "organization_id"),
        Index("ix_users_email", "email"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    email: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    hashed_password: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    full_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    role: Mapped[str] = mapped_column(
        String(32),
        default=Role.VIEWER.value,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    # Relationships
    organization: Mapped[Organization] = relationship(
        "Organization",
        back_populates="users",
    )
    assigned_incidents: Mapped[list[Incident]] = relationship(
        "Incident",
        back_populates="assigned_user",
    )
    incident_events: Mapped[list[IncidentEvent]] = relationship(
        "IncidentEvent",
        back_populates="actor_user",
    )
    collected_evidence: Mapped[list[Evidence]] = relationship(
        "Evidence",
        back_populates="collected_by_user",
    )
