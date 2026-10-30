"""create_alerts_and_evidence_tables

Revision ID: e42b1093f120
Revises: d91e8432a510
Create Date: 2026-10-30 22:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e42b1093f120'
down_revision: Union[str, None] = 'd91e8432a510'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create alerts table
    op.create_table(
        'alerts',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('organization_id', sa.Uuid(), nullable=False),
        sa.Column('service_id', sa.Uuid(), nullable=False),
        sa.Column('incident_id', sa.Uuid(), nullable=True),
        sa.Column('fingerprint', sa.String(length=255), nullable=False),
        sa.Column('source', sa.String(length=100), nullable=False),
        sa.Column('alert_type', sa.String(length=100), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('message', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(length=16), server_default='MEDIUM', nullable=False),
        sa.Column('status', sa.String(length=32), server_default='FIRING', nullable=False),
        sa.Column('payload', sa.JSON(), nullable=True),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.CheckConstraint('length(title) > 0', name=op.f('ck_alerts_ck_alerts_title_not_empty')),
        sa.CheckConstraint('length(fingerprint) > 0', name=op.f('ck_alerts_ck_alerts_fingerprint_not_empty')),
        sa.CheckConstraint("severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')", name=op.f('ck_alerts_ck_alerts_valid_severity')),
        sa.CheckConstraint("status IN ('FIRING', 'RESOLVED', 'SUPPRESSED')", name=op.f('ck_alerts_ck_alerts_valid_status')),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_alerts_incident_id_incidents'), ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_alerts_organization_id_organizations'), ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['service_id'], ['services.id'], name=op.f('fk_alerts_service_id_services'), ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_alerts')),
        sa.UniqueConstraint('organization_id', 'fingerprint', name='uq_alerts_org_fingerprint')
    )
    op.create_index('ix_alerts_organization_id', 'alerts', ['organization_id'], unique=False)
    op.create_index('ix_alerts_service_id', 'alerts', ['service_id'], unique=False)
    op.create_index('ix_alerts_incident_id', 'alerts', ['incident_id'], unique=False)
    op.create_index('ix_alerts_org_status', 'alerts', ['organization_id', 'status'], unique=False)
    op.create_index('ix_alerts_org_severity', 'alerts', ['organization_id', 'severity'], unique=False)
    op.create_index('ix_alerts_org_service_id', 'alerts', ['organization_id', 'service_id'], unique=False)
    op.create_index('ix_alerts_org_incident_id', 'alerts', ['organization_id', 'incident_id'], unique=False)
    op.create_index('ix_alerts_org_fingerprint', 'alerts', ['organization_id', 'fingerprint'], unique=False)

    # 2. Create evidence table
    op.create_table(
        'evidence',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('organization_id', sa.Uuid(), nullable=False),
        sa.Column('incident_id', sa.Uuid(), nullable=False),
        sa.Column('evidence_type', sa.String(length=32), nullable=False),
        sa.Column('source', sa.String(length=100), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('content', sa.Text(), nullable=True),
        sa.Column('structured_data', sa.JSON(), nullable=True),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('collected_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('collected_by_user_id', sa.Uuid(), nullable=True),
        sa.Column('reliability', sa.String(length=16), server_default='HIGH', nullable=False),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('evidence_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.CheckConstraint('length(title) > 0', name=op.f('ck_evidence_ck_evidence_title_not_empty')),
        sa.CheckConstraint('length(source) > 0', name=op.f('ck_evidence_ck_evidence_source_not_empty')),
        sa.CheckConstraint("reliability IN ('HIGH', 'MEDIUM', 'LOW')", name=op.f('ck_evidence_ck_evidence_valid_reliability')),
        sa.CheckConstraint("evidence_type IN ('LOG', 'METRIC', 'TRACE', 'ALERT', 'DEPLOYMENT', 'CONFIG', 'EVENT', 'DOCUMENT', 'OTHER')", name=op.f('ck_evidence_ck_evidence_valid_type')),
        sa.ForeignKeyConstraint(['collected_by_user_id'], ['users.id'], name=op.f('fk_evidence_collected_by_user_id_users'), ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_evidence_incident_id_incidents'), ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_evidence_organization_id_organizations'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_evidence')),
        sa.UniqueConstraint('organization_id', 'evidence_hash', name='uq_evidence_org_hash')
    )
    op.create_index('ix_evidence_organization_id', 'evidence', ['organization_id'], unique=False)
    op.create_index('ix_evidence_incident_id', 'evidence', ['incident_id'], unique=False)
    op.create_index('ix_evidence_collected_by_user_id', 'evidence', ['collected_by_user_id'], unique=False)
    op.create_index('ix_evidence_org_incident_id', 'evidence', ['organization_id', 'incident_id'], unique=False)
    op.create_index('ix_evidence_org_type', 'evidence', ['organization_id', 'evidence_type'], unique=False)
    op.create_index('ix_evidence_org_observed_at', 'evidence', ['organization_id', 'observed_at'], unique=False)
    op.create_index('ix_evidence_org_hash', 'evidence', ['organization_id', 'evidence_hash'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_evidence_org_hash', table_name='evidence')
    op.drop_index('ix_evidence_org_observed_at', table_name='evidence')
    op.drop_index('ix_evidence_org_type', table_name='evidence')
    op.drop_index('ix_evidence_org_incident_id', table_name='evidence')
    op.drop_index('ix_evidence_collected_by_user_id', table_name='evidence')
    op.drop_index('ix_evidence_incident_id', table_name='evidence')
    op.drop_index('ix_evidence_organization_id', table_name='evidence')
    op.drop_table('evidence')

    op.drop_index('ix_alerts_org_fingerprint', table_name='alerts')
    op.drop_index('ix_alerts_org_incident_id', table_name='alerts')
    op.drop_index('ix_alerts_org_service_id', table_name='alerts')
    op.drop_index('ix_alerts_org_severity', table_name='alerts')
    op.drop_index('ix_alerts_org_status', table_name='alerts')
    op.drop_index('ix_alerts_incident_id', table_name='alerts')
    op.drop_index('ix_alerts_service_id', table_name='alerts')
    op.drop_index('ix_alerts_organization_id', table_name='alerts')
    op.drop_table('alerts')
