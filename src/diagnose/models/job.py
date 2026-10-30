"""Job ORM model — durable asynchronous execution entity."""

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
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from diagnose.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from diagnose.models.organization import Organization


class Job(Base, TimestampMixin):
    """Durable job record stored in PostgreSQL as the single source of truth."""

    __tablename__ = "jobs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'RETRYING', 'FAILED', 'DEAD')",
            name="ck_jobs_valid_status",
        ),
        CheckConstraint(
            "attempt_count >= 0",
            name="ck_jobs_attempt_count_non_negative",
        ),
        CheckConstraint(
            "max_attempts > 0",
            name="ck_jobs_max_attempts_positive",
        ),
        Index("ix_jobs_org_status", "organization_id", "status"),
        Index("ix_jobs_org_available_at", "organization_id", "available_at"),
        Index("ix_jobs_org_created_at", "organization_id", "created_at"),
        Index("ix_jobs_org_correlation_id", "organization_id", "correlation_id"),
        Index(
            "uq_jobs_org_idempotency_key",
            "organization_id",
            "idempotency_key",
            unique=True,
            postgresql_where=text("idempotency_key IS NOT NULL"),
        ),
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
    job_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="PENDING",
        server_default="PENDING",
    )
    payload: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
    )
    correlation_id: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    idempotency_key: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
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
        default=3,
        server_default="3",
    )
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    organization: Mapped[Organization] = relationship(
        "Organization",
        back_populates="jobs",
    )
