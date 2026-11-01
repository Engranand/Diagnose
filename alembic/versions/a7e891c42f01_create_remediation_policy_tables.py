"""create remediation policy and evaluation tables

Revision ID: a7e891c42f01
Revises: 3e527d91f1a4
Create Date: 2026-10-31 14:00:00.000000

"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a7e891c42f01'
down_revision: Union[str, None] = '3e527d91f1a4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. Add policy_set_version to organizations ───────────────────────────
    op.add_column(
        'organizations',
        sa.Column('policy_set_version', sa.Integer(), server_default='1', nullable=False),
    )

    # ── 2. Create remediation_policies ───────────────────────────────────────
    op.create_table(
        'remediation_policies',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('organization_id', sa.UUID(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('service_id', sa.UUID(), nullable=True),
        sa.Column('service_tier', sa.String(length=16), nullable=True),
        sa.Column('action_type', sa.String(length=50), nullable=True),
        sa.Column('risk_level', sa.String(length=20), nullable=True),
        sa.Column('execution_mode', sa.String(length=20), nullable=True),
        sa.Column('environment', sa.String(length=50), nullable=True),
        sa.Column('actor_role', sa.String(length=32), nullable=True),
        sa.Column('decision', sa.String(length=32), nullable=False),
        sa.Column('priority', sa.Integer(), server_default='100', nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('version', sa.Integer(), server_default='1', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint('length(name) > 0', name='ck_remediation_policies_name'),
        sa.CheckConstraint(
            "service_tier IS NULL OR service_tier IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')",
            name='ck_remediation_policies_tier',
        ),
        sa.CheckConstraint(
            "action_type IS NULL OR action_type IN ('RESTART_SERVICE', 'SCALE_SERVICE', 'ROLLBACK_DEPLOYMENT', 'UPDATE_CONFIGURATION', 'RUN_DIAGNOSTIC')",
            name='ck_remediation_policies_action_type',
        ),
        sa.CheckConstraint(
            "risk_level IS NULL OR risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')",
            name='ck_remediation_policies_risk_level',
        ),
        sa.CheckConstraint(
            "execution_mode IS NULL OR execution_mode IN ('DRY_RUN', 'EXECUTE')",
            name='ck_remediation_policies_mode',
        ),
        sa.CheckConstraint(
            "actor_role IS NULL OR actor_role IN ('ADMIN', 'ENGINEER', 'RESPONDER', 'VIEWER')",
            name='ck_remediation_policies_role',
        ),
        sa.CheckConstraint(
            "decision IN ('ALLOW', 'REQUIRE_APPROVAL', 'DENY')",
            name='ck_remediation_policies_decision',
        ),
        sa.CheckConstraint(
            'priority >= 1 AND priority <= 1000',
            name='ck_remediation_policies_priority',
        ),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['service_id'], ['services.id'], ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_remediation_policies_org_active',
        'remediation_policies',
        ['organization_id', 'is_active'],
    )
    op.create_index(
        'ix_remediation_policies_org_priority',
        'remediation_policies',
        ['organization_id', 'priority'],
    )
    op.create_index(
        'ix_remediation_policies_org_service',
        'remediation_policies',
        ['organization_id', 'service_id'],
    )

    # ── 3. Create policy_evaluations ─────────────────────────────────────────
    op.create_table(
        'policy_evaluations',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('organization_id', sa.UUID(), nullable=False),
        sa.Column('action_id', sa.UUID(), nullable=True),
        sa.Column('policy_id', sa.UUID(), nullable=True),
        sa.Column('policy_version', sa.Integer(), nullable=True),
        sa.Column('policy_set_version', sa.Integer(), nullable=False),
        sa.Column('decision', sa.String(length=32), nullable=False),
        sa.Column('context_hash', sa.String(length=64), nullable=False),
        sa.Column('context_snapshot', sa.JSON(), nullable=False),
        sa.Column('winning_policy_snapshot', sa.JSON(), nullable=True),
        sa.Column('all_matched_policies', sa.JSON(), nullable=False),
        sa.Column('reasons', sa.JSON(), nullable=False),
        sa.Column('evaluated_by', sa.UUID(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "decision IN ('ALLOW', 'REQUIRE_APPROVAL', 'DENY')",
            name='ck_policy_evaluations_decision',
        ),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['action_id'], ['remediation_actions.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['policy_id'], ['remediation_policies.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['evaluated_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_policy_evaluations_org_action',
        'policy_evaluations',
        ['organization_id', 'action_id'],
    )
    op.create_index(
        'ix_policy_evaluations_org_created_at',
        'policy_evaluations',
        ['organization_id', 'created_at'],
    )
    op.create_index(
        'ix_policy_evaluations_org_hash',
        'policy_evaluations',
        ['organization_id', 'context_hash'],
    )


def downgrade() -> None:
    op.drop_index('ix_policy_evaluations_org_hash', table_name='policy_evaluations')
    op.drop_index('ix_policy_evaluations_org_created_at', table_name='policy_evaluations')
    op.drop_index('ix_policy_evaluations_org_action', table_name='policy_evaluations')
    op.drop_table('policy_evaluations')

    op.drop_index('ix_remediation_policies_org_service', table_name='remediation_policies')
    op.drop_index('ix_remediation_policies_org_priority', table_name='remediation_policies')
    op.drop_index('ix_remediation_policies_org_active', table_name='remediation_policies')
    op.drop_table('remediation_policies')

    op.drop_column('organizations', 'policy_set_version')
