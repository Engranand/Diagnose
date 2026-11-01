"""SQLAlchemy ORM models for Remediation Policies and Policy Evaluations (Milestone 10.2)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
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

from diagnose.models.base import Base

if TYPE_CHECKING:
    from diagnose.models.organization import Organization
    from diagnose.models.remediation import RemediationAction
    from diagnose.models.service import Service
    from diagnose.models.user import User


class RemediationPolicy(Base):
    """Declarative remediation governance policy scoped to an organization."""

    __tablename__ = "remediation_policies"
    __table_args__ = (
        CheckConstraint("length(name) > 0", name="ck_remediation_policies_name"),
        CheckConstraint(
            "service_tier IS NULL OR service_tier IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')",
            name="ck_remediation_policies_tier",
        ),
        CheckConstraint(
            "action_type IS NULL OR action_type IN ('RESTART_SERVICE', 'SCALE_SERVICE', 'ROLLBACK_DEPLOYMENT', 'UPDATE_CONFIGURATION', 'RUN_DIAGNOSTIC')",
            name="ck_remediation_policies_action_type",
        ),
        CheckConstraint(
            "risk_level IS NULL OR risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name="ck_remediation_policies_risk_level",
        ),
        CheckConstraint(
            "execution_mode IS NULL OR execution_mode IN ('DRY_RUN', 'EXECUTE')",
            name="ck_remediation_policies_mode",
        ),
        CheckConstraint(
            "actor_role IS NULL OR actor_role IN ('ADMIN', 'ENGINEER', 'RESPONDER', 'VIEWER')",
            name="ck_remediation_policies_role",
        ),
        CheckConstraint(
            "decision IN ('ALLOW', 'REQUIRE_APPROVAL', 'DENY')",
            name="ck_remediation_policies_decision",
        ),
        CheckConstraint(
            "priority >= 1 AND priority <= 1000",
            name="ck_remediation_policies_priority",
        ),
        Index("ix_remediation_policies_org_active", "organization_id", "is_active"),
        Index("ix_remediation_policies_org_priority", "organization_id", "priority"),
        Index("ix_remediation_policies_org_service", "organization_id", "service_id"),
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
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    service_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("services.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    service_tier: Mapped[str | None] = mapped_column(
        String(16),
        nullable=True,
    )
    action_type: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )
    risk_level: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
    )
    execution_mode: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
    )
    environment: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )
    actor_role: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )
    decision: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    priority: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=100,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
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
    organization: Mapped[Organization] = relationship("Organization")
    service: Mapped[Service | None] = relationship("Service")


class PolicyEvaluation(Base):
    """Audit and execution record of an evaluation decision against active policies."""

    __tablename__ = "policy_evaluations"
    __table_args__ = (
        CheckConstraint(
            "decision IN ('ALLOW', 'REQUIRE_APPROVAL', 'DENY')",
            name="ck_policy_evaluations_decision",
        ),
        Index("ix_policy_evaluations_org_action", "organization_id", "action_id"),
        Index("ix_policy_evaluations_org_created_at", "organization_id", "created_at"),
        Index("ix_policy_evaluations_org_hash", "organization_id", "context_hash"),
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
    action_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("remediation_actions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    policy_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("remediation_policies.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    policy_version: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    policy_set_version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    decision: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    context_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    context_snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
    )
    winning_policy_snapshot: Mapped[dict[str, Any] | None] = mapped_column(
        JSON,
        nullable=True,
    )
    all_matched_policies: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    reasons: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    evaluated_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    organization: Mapped[Organization] = relationship("Organization")
    action: Mapped[RemediationAction | None] = relationship("RemediationAction")
    policy: Mapped[RemediationPolicy | None] = relationship("RemediationPolicy")
    evaluator: Mapped[User | None] = relationship("User")
