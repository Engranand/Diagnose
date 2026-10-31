"""create remediation action and execution tables

Revision ID: 3e527d91f1a4
Revises: c9a4e32101fe
Create Date: 2026-10-31 03:40:00.000000

"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3e527d91f1a4'
down_revision: Union[str, None] = 'c9a4e32101fe'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. remediation_actions ───────────────────────────────────────────────
    op.create_table(
        'remediation_actions',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('organization_id', sa.UUID(), nullable=False),
        sa.Column('incident_id', sa.UUID(), nullable=False),
        sa.Column('service_id', sa.UUID(), nullable=False),
        sa.Column('action_type', sa.String(length=50), nullable=False),
        sa.Column('risk_level', sa.String(length=20), nullable=False),
        sa.Column('status', sa.String(length=32), server_default='PROPOSED', nullable=False),
        sa.Column('execution_mode', sa.String(length=20), server_default='DRY_RUN', nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('rationale', sa.Text(), nullable=True),
        sa.Column('preconditions', sa.JSON(), nullable=True),
        sa.Column('expected_outcome', sa.Text(), nullable=True),
        sa.Column('rollback_plan', sa.Text(), nullable=True),
        sa.Column('proposed_by', sa.UUID(), nullable=True),
        sa.Column('approved_by', sa.UUID(), nullable=True),
        sa.Column('version', sa.Integer(), server_default='1', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "action_type IN ('RESTART_SERVICE', 'SCALE_SERVICE', 'ROLLBACK_DEPLOYMENT', 'UPDATE_CONFIGURATION', 'RUN_DIAGNOSTIC')",
            name='ck_remediation_actions_action_type',
        ),
        sa.CheckConstraint(
            "risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name='ck_remediation_actions_risk_level',
        ),
        sa.CheckConstraint(
            "status IN ('PROPOSED', 'PENDING_APPROVAL', 'APPROVED', 'REJECTED', 'EXECUTING', 'SUCCEEDED', 'FAILED', 'CANCELLED')",
            name='ck_remediation_actions_status',
        ),
        sa.CheckConstraint(
            "execution_mode IN ('DRY_RUN', 'EXECUTE')",
            name='ck_remediation_actions_execution_mode',
        ),
        sa.CheckConstraint('length(title) > 0', name='ck_remediation_actions_title_not_empty'),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['service_id'], ['services.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['proposed_by'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['approved_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_remediation_actions_org_incident',
        'remediation_actions',
        ['organization_id', 'incident_id'],
    )
    op.create_index(
        'ix_remediation_actions_org_service',
        'remediation_actions',
        ['organization_id', 'service_id'],
    )
    op.create_index(
        'ix_remediation_actions_org_status',
        'remediation_actions',
        ['organization_id', 'status'],
    )
    op.create_index(
        'ix_remediation_actions_org_created_at',
        'remediation_actions',
        ['organization_id', 'created_at'],
    )

    # ── 2. action_executions ─────────────────────────────────────────────────
    op.create_table(
        'action_executions',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('organization_id', sa.UUID(), nullable=False),
        sa.Column('action_id', sa.UUID(), nullable=False),
        sa.Column('status', sa.String(length=32), server_default='PENDING', nullable=False),
        sa.Column('execution_mode', sa.String(length=20), server_default='DRY_RUN', nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('result', sa.JSON(), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('executor_type', sa.String(length=50), server_default='SIMULATOR', nullable=False),
        sa.Column('correlation_id', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "status IN ('PENDING', 'EXECUTING', 'SUCCEEDED', 'FAILED', 'CANCELLED')",
            name='ck_action_executions_status',
        ),
        sa.CheckConstraint(
            "execution_mode IN ('DRY_RUN', 'EXECUTE')",
            name='ck_action_executions_mode',
        ),
        sa.CheckConstraint(
            "executor_type IN ('MANUAL', 'SYSTEM', 'SIMULATOR')",
            name='ck_action_executions_executor_type',
        ),
        sa.ForeignKeyConstraint(['action_id'], ['remediation_actions.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_action_executions_org_action',
        'action_executions',
        ['organization_id', 'action_id'],
    )
    op.create_index(
        'ix_action_executions_org_created_at',
        'action_executions',
        ['organization_id', 'created_at'],
    )


def downgrade() -> None:
    op.drop_index('ix_action_executions_org_created_at', table_name='action_executions')
    op.drop_index('ix_action_executions_org_action', table_name='action_executions')
    op.drop_table('action_executions')

    op.drop_index('ix_remediation_actions_org_created_at', table_name='remediation_actions')
    op.drop_index('ix_remediation_actions_org_status', table_name='remediation_actions')
    op.drop_index('ix_remediation_actions_org_service', table_name='remediation_actions')
    op.drop_index('ix_remediation_actions_org_incident', table_name='remediation_actions')
    op.drop_table('remediation_actions')
