"""create action approvals table

Revision ID: c1a23e45f678
Revises: b8f9104c8921
Create Date: 2026-10-31 15:47:00.000000

"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c1a23e45f678'
down_revision: Union[str, None] = 'b8f9104c8921'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'action_approvals',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('organization_id', sa.UUID(), nullable=False),
        sa.Column('action_id', sa.UUID(), nullable=False),
        sa.Column('approver_user_id', sa.UUID(), nullable=False),
        sa.Column('decision', sa.String(length=20), nullable=False),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('policy_set_version', sa.Integer(), nullable=False),
        sa.Column('policy_evaluation_id', sa.UUID(), nullable=True),
        sa.Column('dry_run_plan_hash', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('decided_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "decision IN ('APPROVED', 'REJECTED')",
            name='ck_action_approvals_decision',
        ),
        sa.ForeignKeyConstraint(['action_id'], ['remediation_actions.id'], ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['approver_user_id'], ['users.id'], ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['policy_evaluation_id'], ['policy_evaluations.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_action_approvals_org_action',
        'action_approvals',
        ['organization_id', 'action_id'],
    )
    op.create_index(
        'ix_action_approvals_org_approver',
        'action_approvals',
        ['organization_id', 'approver_user_id'],
    )


def downgrade() -> None:
    op.drop_index('ix_action_approvals_org_approver', table_name='action_approvals')
    op.drop_index('ix_action_approvals_org_action', table_name='action_approvals')
    op.drop_table('action_approvals')
