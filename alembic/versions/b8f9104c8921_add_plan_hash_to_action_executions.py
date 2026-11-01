"""add plan_hash to action_executions

Revision ID: b8f9104c8921
Revises: a7e891c42f01
Create Date: 2026-10-31 14:18:00.000000

"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b8f9104c8921'
down_revision: Union[str, None] = 'a7e891c42f01'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'action_executions',
        sa.Column('plan_hash', sa.String(length=64), nullable=True),
    )
    op.create_index(
        'ix_action_executions_plan_hash',
        'action_executions',
        ['plan_hash'],
    )
    op.create_index(
        'ix_action_executions_action_mode',
        'action_executions',
        ['action_id', 'execution_mode'],
    )


def downgrade() -> None:
    op.drop_index('ix_action_executions_action_mode', table_name='action_executions')
    op.drop_index('ix_action_executions_plan_hash', table_name='action_executions')
    op.drop_column('action_executions', 'plan_hash')
