"""OutboxEvent ORM model — transactional outbox pattern implementation."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from diagnose.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from diagnose.models.organization import Organization


class OutboxEvent(Base, TimestampMixin):
    """Outbox event record committed in the same transaction as state changes."""

    __tablename__ = "outbox_events"
    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING', 'PUBLISHED', 'FAILED', 'DEAD')",
            name="ck_outbox_valid_status",
        ),
        CheckConstraint(
            "attempt_count >= 0",
            name="ck_outbox_attempt_count_non_negative",
        ),
        CheckConstraint(
            "max_attempts > 0",
            name="ck_outbox_max_attempts_positive",
        ),
        Index("ix_outbox_polling", "status", "available_at"),
        Index("ix_outbox_org_status", "organization_id", "status"),
        Index("ix_outbox_aggregate", "aggregate_type", "aggregate_id"),
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
    event_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    aggregate_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    aggregate_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    payload: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="PENDING",
        server_default="PENDING",
    )
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    attempt_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    max_attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=5,
        server_default="5",
    )
    last_error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    organization: Mapped[Organization] = relationship(
        "Organization",
        back_populates="outbox_events",
    )
