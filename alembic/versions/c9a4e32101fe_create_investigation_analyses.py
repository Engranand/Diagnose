"""create investigation analyses

Revision ID: c9a4e32101fe
Revises: b8e19c054231
Create Date: 2026-10-31 03:00:00.000000

"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c9a4e32101fe'
down_revision: Union[str, None] = 'b8e19c054231'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'investigation_analyses',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('organization_id', sa.UUID(), nullable=False),
        sa.Column('investigation_id', sa.UUID(), nullable=False),
        sa.Column('model_provider', sa.String(length=50), nullable=False),
        sa.Column('model_name', sa.String(length=100), nullable=False),
        sa.Column('prompt_version', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=32), server_default='PENDING', nullable=False),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('structured_output', sa.JSON(), nullable=True),
        sa.Column('input_hash', sa.String(length=64), nullable=False),
        sa.Column('output_hash', sa.String(length=64), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED')",
            name='ck_investigation_analyses_status',
        ),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigation_runs.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_investigation_analyses_org_investigation',
        'investigation_analyses',
        ['organization_id', 'investigation_id'],
    )
    op.create_index(
        'ix_investigation_analyses_org_hash',
        'investigation_analyses',
        ['organization_id', 'input_hash'],
    )
    op.create_index(
        'ix_investigation_analyses_org_status',
        'investigation_analyses',
        ['organization_id', 'status'],
    )
    op.create_index(
        'ix_investigation_analyses_org_created_at',
        'investigation_analyses',
        ['organization_id', 'created_at'],
    )


def downgrade() -> None:
    op.drop_index('ix_investigation_analyses_org_created_at', table_name='investigation_analyses')
    op.drop_index('ix_investigation_analyses_org_status', table_name='investigation_analyses')
    op.drop_index('ix_investigation_analyses_org_hash', table_name='investigation_analyses')
    op.drop_index('ix_investigation_analyses_org_investigation', table_name='investigation_analyses')
    op.drop_table('investigation_analyses')
