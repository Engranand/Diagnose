"""create_services_table

Revision ID: c78b41df0921
Revises: a52ef2f20139
Create Date: 2026-10-30 19:15:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c78b41df0921'
down_revision: Union[str, None] = 'a52ef2f20139'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'services',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('organization_id', sa.Uuid(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('slug', sa.String(length=100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('tier', sa.String(length=16), server_default='MEDIUM', nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.CheckConstraint('length(name) > 0', name=op.f('ck_services_ck_services_name_not_empty')),
        sa.CheckConstraint('length(slug) > 0', name=op.f('ck_services_ck_services_slug_not_empty')),
        sa.CheckConstraint("tier IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')", name=op.f('ck_services_ck_services_valid_tier')),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_services_organization_id_organizations'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_services')),
        sa.UniqueConstraint('organization_id', 'slug', name='uq_services_organization_id_slug')
    )
    op.create_index('ix_services_organization_id', 'services', ['organization_id'], unique=False)
    op.create_index('ix_services_org_is_active', 'services', ['organization_id', 'is_active'], unique=False)
    op.create_index('ix_services_org_tier', 'services', ['organization_id', 'tier'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_services_org_tier', table_name='services')
    op.drop_index('ix_services_org_is_active', table_name='services')
    op.drop_index('ix_services_organization_id', table_name='services')
    op.drop_table('services')
