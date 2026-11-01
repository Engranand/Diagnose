"""add single succeeded execution idempotency index

Revision ID: d3e4f5a6b7c8
Revises: c1a23e45f678
Create Date: 2026-10-31 23:45:00.000000

"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd3e4f5a6b7c8'
down_revision: Union[str, None] = 'c1a23e45f678'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(
        'uq_action_executions_single_succeeded',
        'action_executions',
        ['action_id'],
        unique=True,
        postgresql_where=sa.text("status = 'SUCCEEDED' AND execution_mode = 'EXECUTE'"),
    )


def downgrade() -> None:
    op.drop_index(
        'uq_action_executions_single_succeeded',
        table_name='action_executions',
    )
