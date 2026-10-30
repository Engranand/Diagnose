"""Service ORM model."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from diagnose.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from diagnose.models.alert import Alert
    from diagnose.models.incident import Incident
    from diagnose.models.organization import Organization


class Service(Base, TimestampMixin):
    """Production service catalog entity belonging to an organization."""

    __tablename__ = "services"
    __table_args__ = (
        CheckConstraint("length(name) > 0", name="ck_services_name_not_empty"),
        CheckConstraint("length(slug) > 0", name="ck_services_slug_not_empty"),
        CheckConstraint(
            "tier IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')",
            name="ck_services_valid_tier",
        ),
        UniqueConstraint("organization_id", "slug", name="uq_services_organization_id_slug"),
        Index("ix_services_org_is_active", "organization_id", "is_active"),
        Index("ix_services_org_tier", "organization_id", "tier"),
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
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    slug: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    tier: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="MEDIUM",
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    # Relationships
    organization: Mapped[Organization] = relationship(
        "Organization",
        back_populates="services",
    )
    incidents: Mapped[list[Incident]] = relationship(
        "Incident",
        back_populates="service",
        cascade="all, delete-orphan",
    )
    alerts: Mapped[list[Alert]] = relationship(
        "Alert",
        back_populates="service",
        cascade="all, delete-orphan",
    )
