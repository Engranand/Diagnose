"""create_job_effects_table

Revision ID: 07aac42874c8
Revises: 5a28e5e9bff0
Create Date: 2026-10-31 00:19:38.913987

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '07aac42874c8'
down_revision: Union[str, None] = '5a28e5e9bff0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'job_effects',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('organization_id', sa.Uuid(), nullable=False),
        sa.Column('job_id', sa.Uuid(), nullable=False),
        sa.Column('effect_key', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=32), server_default='COMMITTED', nullable=False),
        sa.Column('payload', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('PENDING', 'COMMITTED', 'FAILED')",
            name='ck_job_effects_valid_status',
        ),
        sa.ForeignKeyConstraint(
            ['organization_id'],
            ['organizations.id'],
            name='fk_job_effects_organization_id_organizations',
            ondelete='CASCADE',
        ),
        sa.ForeignKeyConstraint(
            ['job_id'],
            ['jobs.id'],
            name='fk_job_effects_job_id_jobs',
            ondelete='CASCADE',
        ),
        sa.PrimaryKeyConstraint('id', name='pk_job_effects'),
        sa.UniqueConstraint('organization_id', 'effect_key', name='uq_job_effects_org_effect_key'),
    )
    op.create_index('ix_job_effects_organization_id', 'job_effects', ['organization_id'], unique=False)
    op.create_index('ix_job_effects_job_id', 'job_effects', ['job_id'], unique=False)
    op.create_index('ix_job_effects_org_job_id', 'job_effects', ['organization_id', 'job_id'], unique=False)
    op.create_index('ix_job_effects_org_effect_key', 'job_effects', ['organization_id', 'effect_key'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_job_effects_org_effect_key', table_name='job_effects')
    op.drop_index('ix_job_effects_org_job_id', table_name='job_effects')
    op.drop_index('ix_job_effects_job_id', table_name='job_effects')
    op.drop_index('ix_job_effects_organization_id', table_name='job_effects')
    op.drop_table('job_effects')
