"""add_performance_indexes

Revision ID: f12558d6b051
Revises: 07aac42874c8
Create Date: 2026-10-31 00:41:21.727999

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f12558d6b051'
down_revision: Union[str, None] = '07aac42874c8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(
        'ix_alerts_org_created_at',
        'alerts',
        ['organization_id', 'created_at'],
        unique=False,
    )
    op.create_index(
        'ix_alerts_org_last_seen_at',
        'alerts',
        ['organization_id', 'last_seen_at'],
        unique=False,
    )
    op.create_index(
        'ix_evidence_org_incident_observed',
        'evidence',
        ['organization_id', 'incident_id', 'observed_at'],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index('ix_evidence_org_incident_observed', table_name='evidence')
    op.drop_index('ix_alerts_org_last_seen_at', table_name='alerts')
    op.drop_index('ix_alerts_org_created_at', table_name='alerts')
