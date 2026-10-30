"""JobEffect ORM model — durable idempotency and side-effect commit tracker."""

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
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from diagnose.models.base import Base

if TYPE_CHECKING:
    from diagnose.models.job import Job
    from diagnose.models.organization import Organization


class JobEffect(Base):
    """Durable record of a side-effect committed by a background job handler.

    Enforces that for a given (organization_id, effect_key), at most one durable
    side-effect can be committed across retries, worker crashes, and redeliveries.
    """

    __tablename__ = "job_effects"
    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING', 'COMMITTED', 'FAILED')",
            name="ck_job_effects_valid_status",
        ),
        UniqueConstraint(
            "organization_id",
            "effect_key",
            name="uq_job_effects_org_effect_key",
        ),
        Index("ix_job_effects_org_job_id", "organization_id", "job_id"),
        Index("ix_job_effects_org_effect_key", "organization_id", "effect_key"),
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
    job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    effect_key: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="COMMITTED",
        server_default="COMMITTED",
    )
    payload: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    organization: Mapped[Organization] = relationship(
        "Organization",
        back_populates="job_effects",
    )
    job: Mapped[Job] = relationship(
        "Job",
        back_populates="effects",
    )
