"""create_jobs_and_outbox_tables

Revision ID: 5a28e5e9bff0
Revises: a44028fcf799
Create Date: 2026-10-30 23:46:10.692998

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5a28e5e9bff0'
down_revision: Union[str, None] = 'a44028fcf799'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create jobs table
    op.create_table(
        'jobs',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('organization_id', sa.Uuid(), nullable=False),
        sa.Column('job_type', sa.String(length=100), nullable=False),
        sa.Column('status', sa.String(length=32), server_default='PENDING', nullable=False),
        sa.Column('payload', sa.JSON(), nullable=True),
        sa.Column('correlation_id', sa.String(length=100), nullable=True),
        sa.Column('idempotency_key', sa.String(length=255), nullable=True),
        sa.Column('attempt_count', sa.Integer(), server_default='0', nullable=False),
        sa.Column('max_attempts', sa.Integer(), server_default='3', nullable=False),
        sa.Column('available_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.CheckConstraint(
            "status IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'RETRYING', 'FAILED', 'DEAD')",
            name=op.f('ck_jobs_ck_jobs_valid_status'),
        ),
        sa.CheckConstraint('attempt_count >= 0', name=op.f('ck_jobs_ck_jobs_attempt_count_non_negative')),
        sa.CheckConstraint('max_attempts > 0', name=op.f('ck_jobs_ck_jobs_max_attempts_positive')),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_jobs_organization_id_organizations'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_jobs')),
    )
    op.create_index('ix_jobs_organization_id', 'jobs', ['organization_id'], unique=False)
    op.create_index('ix_jobs_job_type', 'jobs', ['job_type'], unique=False)
    op.create_index('ix_jobs_org_status', 'jobs', ['organization_id', 'status'], unique=False)
    op.create_index('ix_jobs_org_available_at', 'jobs', ['organization_id', 'available_at'], unique=False)
    op.create_index('ix_jobs_org_created_at', 'jobs', ['organization_id', 'created_at'], unique=False)
    op.create_index('ix_jobs_org_correlation_id', 'jobs', ['organization_id', 'correlation_id'], unique=False)
    op.create_index(
        'uq_jobs_org_idempotency_key',
        'jobs',
        ['organization_id', 'idempotency_key'],
        unique=True,
        postgresql_where=sa.text("idempotency_key IS NOT NULL"),
    )

    # 2. Create outbox_events table
    op.create_table(
        'outbox_events',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('organization_id', sa.Uuid(), nullable=False),
        sa.Column('event_type', sa.String(length=100), nullable=False),
        sa.Column('aggregate_type', sa.String(length=100), nullable=False),
        sa.Column('aggregate_id', sa.String(length=100), nullable=False),
        sa.Column('payload', sa.JSON(), nullable=True),
        sa.Column('status', sa.String(length=32), server_default='PENDING', nullable=False),
        sa.Column('available_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('attempt_count', sa.Integer(), server_default='0', nullable=False),
        sa.Column('max_attempts', sa.Integer(), server_default='5', nullable=False),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('published_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.CheckConstraint(
            "status IN ('PENDING', 'PUBLISHED', 'FAILED', 'DEAD')",
            name=op.f('ck_outbox_events_ck_outbox_valid_status'),
        ),
        sa.CheckConstraint('attempt_count >= 0', name=op.f('ck_outbox_events_ck_outbox_attempt_count_non_negative')),
        sa.CheckConstraint('max_attempts > 0', name=op.f('ck_outbox_events_ck_outbox_max_attempts_positive')),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_outbox_events_organization_id_organizations'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_outbox_events')),
    )
    op.create_index('ix_outbox_events_organization_id', 'outbox_events', ['organization_id'], unique=False)
    op.create_index('ix_outbox_events_event_type', 'outbox_events', ['event_type'], unique=False)
    op.create_index('ix_outbox_polling', 'outbox_events', ['status', 'available_at'], unique=False)
    op.create_index('ix_outbox_org_status', 'outbox_events', ['organization_id', 'status'], unique=False)
    op.create_index('ix_outbox_aggregate', 'outbox_events', ['aggregate_type', 'aggregate_id'], unique=False)


def downgrade() -> None:
    # 1. Drop outbox_events table
    op.drop_index('ix_outbox_aggregate', table_name='outbox_events')
    op.drop_index('ix_outbox_org_status', table_name='outbox_events')
    op.drop_index('ix_outbox_polling', table_name='outbox_events')
    op.drop_index('ix_outbox_events_event_type', table_name='outbox_events')
    op.drop_index('ix_outbox_events_organization_id', table_name='outbox_events')
    op.drop_table('outbox_events')

    # 2. Drop jobs table
    op.drop_index('uq_jobs_org_idempotency_key', table_name='jobs')
    op.drop_index('ix_jobs_org_correlation_id', table_name='jobs')
    op.drop_index('ix_jobs_org_created_at', table_name='jobs')
    op.drop_index('ix_jobs_org_available_at', table_name='jobs')
    op.drop_index('ix_jobs_org_status', table_name='jobs')
    op.drop_index('ix_jobs_job_type', table_name='jobs')
    op.drop_index('ix_jobs_organization_id', table_name='jobs')
    op.drop_table('jobs')
