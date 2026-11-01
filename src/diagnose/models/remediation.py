"""SQLAlchemy ORM models for Remediation Actions and Executions (Milestone 10.1)."""

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

from diagnose.models.base import Base

if TYPE_CHECKING:
    from diagnose.models.approval import ActionApproval
    from diagnose.models.incident import Incident
    from diagnose.models.organization import Organization
    from diagnose.models.service import Service
    from diagnose.models.user import User


class RemediationAction(Base):
    """Proposed remediation intervention and its approval lifecycle."""

    __tablename__ = "remediation_actions"
    __table_args__ = (
        CheckConstraint(
            "action_type IN ('RESTART_SERVICE', 'SCALE_SERVICE', 'ROLLBACK_DEPLOYMENT', 'UPDATE_CONFIGURATION', 'RUN_DIAGNOSTIC')",
            name="ck_remediation_actions_action_type",
        ),
        CheckConstraint(
            "risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name="ck_remediation_actions_risk_level",
        ),
        CheckConstraint(
            "status IN ('PROPOSED', 'PENDING_APPROVAL', 'APPROVED', 'REJECTED', 'EXECUTING', 'SUCCEEDED', 'FAILED', 'CANCELLED')",
            name="ck_remediation_actions_status",
        ),
        CheckConstraint(
            "execution_mode IN ('DRY_RUN', 'EXECUTE')",
            name="ck_remediation_actions_execution_mode",
        ),
        CheckConstraint("length(title) > 0", name="ck_remediation_actions_title_not_empty"),
        Index("ix_remediation_actions_org_incident", "organization_id", "incident_id"),
        Index("ix_remediation_actions_org_service", "organization_id", "service_id"),
        Index("ix_remediation_actions_org_status", "organization_id", "status"),
        Index("ix_remediation_actions_org_created_at", "organization_id", "created_at"),
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
    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    service_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("services.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    action_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    risk_level: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="PROPOSED",
    )
    execution_mode: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="DRY_RUN",
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    rationale: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    preconditions: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
    )
    expected_outcome: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    rollback_plan: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    proposed_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    approved_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    executions: Mapped[list[ActionExecution]] = relationship(
        "ActionExecution",
        back_populates="action",
        cascade="all, delete-orphan",
        order_by="ActionExecution.created_at.asc()",
    )
    approvals: Mapped[list[ActionApproval]] = relationship(
        "ActionApproval",
        back_populates="action",
        order_by="ActionApproval.created_at.asc()",
    )
    incident: Mapped[Incident] = relationship("Incident")
    service: Mapped[Service] = relationship("Service")
    proposer: Mapped[User | None] = relationship("User", foreign_keys=[proposed_by])
    approver: Mapped[User | None] = relationship("User", foreign_keys=[approved_by])
    organization: Mapped[Organization] = relationship("Organization")


class ActionExecution(Base):
    """Execution attempt of a proposed remediation action."""

    __tablename__ = "action_executions"
    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING', 'EXECUTING', 'SUCCEEDED', 'FAILED', 'CANCELLED')",
            name="ck_action_executions_status",
        ),
        CheckConstraint(
            "execution_mode IN ('DRY_RUN', 'EXECUTE')",
            name="ck_action_executions_mode",
        ),
        CheckConstraint(
            "executor_type IN ('MANUAL', 'SYSTEM', 'SIMULATOR')",
            name="ck_action_executions_executor_type",
        ),
        Index("ix_action_executions_org_action", "organization_id", "action_id"),
        Index("ix_action_executions_org_created_at", "organization_id", "created_at"),
        Index("ix_action_executions_action_mode", "action_id", "execution_mode"),
        Index("ix_action_executions_plan_hash", "plan_hash"),
        Index(
            "uq_action_executions_single_succeeded",
            "action_id",
            unique=True,
            postgresql_where=text("status = 'SUCCEEDED' AND execution_mode = 'EXECUTE'"),
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
    action_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("remediation_actions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="PENDING",
    )
    execution_mode: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="DRY_RUN",
    )
    plan_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    result: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
    )
    error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    executor_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="SIMULATOR",
    )
    correlation_id: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    action: Mapped[RemediationAction] = relationship(
        "RemediationAction",
        back_populates="executions",
    )
    organization: Mapped[Organization] = relationship("Organization")
