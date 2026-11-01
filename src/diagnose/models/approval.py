"""SQLAlchemy ORM model for Action Approvals (Milestone 10.4)."""

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
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from diagnose.models.base import Base

if TYPE_CHECKING:
    from diagnose.models.organization import Organization
    from diagnose.models.policy import PolicyEvaluation
    from diagnose.models.remediation import RemediationAction
    from diagnose.models.user import User


class ActionApproval(Base):
    """Immutable human approval or rejection record for a remediation action."""

    __tablename__ = "action_approvals"
    __table_args__ = (
        CheckConstraint(
            "decision IN ('APPROVED', 'REJECTED')",
            name="ck_action_approvals_decision",
        ),
        Index("ix_action_approvals_org_action", "organization_id", "action_id"),
        Index("ix_action_approvals_org_approver", "organization_id", "approver_user_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    action_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("remediation_actions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    approver_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    decision: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )
    reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    policy_set_version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    policy_evaluation_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("policy_evaluations.id", ondelete="SET NULL"),
        nullable=True,
    )
    dry_run_plan_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    organization: Mapped[Organization] = relationship("Organization")
    action: Mapped[RemediationAction] = relationship("RemediationAction", back_populates="approvals")
    approver: Mapped[User] = relationship("User", foreign_keys=[approver_user_id])
    policy_evaluation: Mapped[PolicyEvaluation | None] = relationship("PolicyEvaluation")
