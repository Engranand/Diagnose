"""create_incidents_and_events_tables

Revision ID: d91e8432a510
Revises: c78b41df0921
Create Date: 2026-10-30 19:45:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd91e8432a510'
down_revision: Union[str, None] = 'c78b41df0921'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create incidents table
    op.create_table(
        'incidents',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('organization_id', sa.Uuid(), nullable=False),
        sa.Column('service_id', sa.Uuid(), nullable=False),
        sa.Column('incident_number', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(length=16), server_default='MEDIUM', nullable=False),
        sa.Column('status', sa.String(length=32), server_default='DETECTED', nullable=False),
        sa.Column('assigned_user_id', sa.Uuid(), nullable=True),
        sa.Column('detected_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('acknowledged_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('version', sa.Integer(), server_default='1', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.CheckConstraint('length(title) > 0', name=op.f('ck_incidents_ck_incidents_title_not_empty')),
        sa.CheckConstraint("severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')", name=op.f('ck_incidents_ck_incidents_valid_severity')),
        sa.CheckConstraint("status IN ('DETECTED', 'ACKNOWLEDGED', 'INVESTIGATING', 'IDENTIFIED', 'MITIGATING', 'RESOLVED', 'CLOSED')", name=op.f('ck_incidents_ck_incidents_valid_status')),
        sa.ForeignKeyConstraint(['assigned_user_id'], ['users.id'], name=op.f('fk_incidents_assigned_user_id_users'), ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_incidents_organization_id_organizations'), ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['service_id'], ['services.id'], name=op.f('fk_incidents_service_id_services'), ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_incidents')),
        sa.UniqueConstraint('organization_id', 'incident_number', name='uq_incidents_org_incident_number')
    )
    op.create_index('ix_incidents_organization_id', 'incidents', ['organization_id'], unique=False)
    op.create_index('ix_incidents_service_id', 'incidents', ['service_id'], unique=False)
    op.create_index('ix_incidents_assigned_user_id', 'incidents', ['assigned_user_id'], unique=False)
    op.create_index('ix_incidents_org_status', 'incidents', ['organization_id', 'status'], unique=False)
    op.create_index('ix_incidents_org_severity', 'incidents', ['organization_id', 'severity'], unique=False)
    op.create_index('ix_incidents_org_service_id', 'incidents', ['organization_id', 'service_id'], unique=False)
    op.create_index('ix_incidents_org_created_at', 'incidents', ['organization_id', 'created_at'], unique=False)
    op.create_index('ix_incidents_org_assigned_user', 'incidents', ['organization_id', 'assigned_user_id'], unique=False)

    # 2. Create incident_events table
    op.create_table(
        'incident_events',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('organization_id', sa.Uuid(), nullable=False),
        sa.Column('incident_id', sa.Uuid(), nullable=False),
        sa.Column('event_type', sa.String(length=64), nullable=False),
        sa.Column('actor_user_id', sa.Uuid(), nullable=True),
        sa.Column('from_status', sa.String(length=32), nullable=True),
        sa.Column('to_status', sa.String(length=32), nullable=True),
        sa.Column('message', sa.Text(), nullable=True),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['actor_user_id'], ['users.id'], name=op.f('fk_incident_events_actor_user_id_users'), ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_incident_events_incident_id_incidents'), ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_incident_events_organization_id_organizations'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_incident_events'))
    )
    op.create_index('ix_incident_events_organization_id', 'incident_events', ['organization_id'], unique=False)
    op.create_index('ix_incident_events_incident_id', 'incident_events', ['incident_id'], unique=False)
    op.create_index('ix_incident_events_actor_user_id', 'incident_events', ['actor_user_id'], unique=False)
    op.create_index(op.f('ix_incident_events_event_type'), 'incident_events', ['event_type'], unique=False)
    op.create_index('ix_incident_events_org_incident_created', 'incident_events', ['organization_id', 'incident_id', 'created_at'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_incident_events_org_incident_created', table_name='incident_events')
    op.drop_index(op.f('ix_incident_events_event_type'), table_name='incident_events')
    op.drop_index('ix_incident_events_actor_user_id', table_name='incident_events')
    op.drop_index('ix_incident_events_incident_id', table_name='incident_events')
    op.drop_index('ix_incident_events_organization_id', table_name='incident_events')
    op.drop_table('incident_events')

    op.drop_index('ix_incidents_org_assigned_user', table_name='incidents')
    op.drop_index('ix_incidents_org_created_at', table_name='incidents')
    op.drop_index('ix_incidents_org_service_id', table_name='incidents')
    op.drop_index('ix_incidents_org_severity', table_name='incidents')
    op.drop_index('ix_incidents_org_status', table_name='incidents')
    op.drop_index('ix_incidents_assigned_user_id', table_name='incidents')
    op.drop_index('ix_incidents_service_id', table_name='incidents')
    op.drop_index('ix_incidents_organization_id', table_name='incidents')
    op.drop_table('incidents')
