"""partial_unique_index_active_alerts

Revision ID: a44028fcf799
Revises: e42b1093f120
Create Date: 2026-10-30 23:09:36.690791

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a44028fcf799'
down_revision: Union[str, None] = 'e42b1093f120'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Drop unconditional unique constraint on alerts (organization_id, fingerprint)
    op.drop_constraint('uq_alerts_org_fingerprint', 'alerts', type_='unique')

    # 2. Create partial unique index restricting uniqueness to active (FIRING) alerts only
    op.create_index(
        'uq_alerts_org_active_fingerprint',
        'alerts',
        ['organization_id', 'fingerprint'],
        unique=True,
        postgresql_where=sa.text("status = 'FIRING'"),
    )


def downgrade() -> None:
    # 1. Drop partial unique index
    op.drop_index('uq_alerts_org_active_fingerprint', table_name='alerts')

    # 2. Re-create unconditional unique constraint
    op.create_unique_constraint(
        'uq_alerts_org_fingerprint',
        'alerts',
        ['organization_id', 'fingerprint'],
    )
