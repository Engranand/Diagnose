"""create investigation tables

Revision ID: b8e19c054231
Revises: f12558d6b051
Create Date: 2026-10-31 02:22:00.000000

"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b8e19c054231'
down_revision: Union[str, None] = 'f12558d6b051'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. investigation_runs ──────────────────────────────────────────────────
    op.create_table(
        'investigation_runs',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('organization_id', sa.UUID(), nullable=False),
        sa.Column('incident_id', sa.UUID(), nullable=False),
        sa.Column('status', sa.String(length=20), server_default='PENDING', nullable=False),
        sa.Column('run_number', sa.Integer(), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED')", name='ck_investigation_runs_status'),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('organization_id', 'incident_id', 'run_number', name='uq_investigation_runs_org_inc_run_num'),
    )
    op.create_index('ix_investigation_runs_org_incident_id', 'investigation_runs', ['organization_id', 'incident_id'])
    op.create_index('ix_investigation_runs_org_status', 'investigation_runs', ['organization_id', 'status'])
    op.create_index('ix_investigation_runs_org_created_at', 'investigation_runs', ['organization_id', 'created_at'])

    # ── 2. investigation_steps ─────────────────────────────────────────────────
    op.create_table(
        'investigation_steps',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('organization_id', sa.UUID(), nullable=False),
        sa.Column('investigation_run_id', sa.UUID(), nullable=False),
        sa.Column('step_type', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=20), server_default='PENDING', nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED')", name='ck_investigation_steps_status'),
        sa.CheckConstraint("step_type IN ('EVIDENCE_COLLECTION', 'TIMELINE_BUILD', 'CORRELATION', 'HYPOTHESIS_GENERATION', 'HYPOTHESIS_SCORING', 'FINALIZATION')", name='ck_investigation_steps_type'),
        sa.ForeignKeyConstraint(['investigation_run_id'], ['investigation_runs.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_investigation_steps_org_run_id', 'investigation_steps', ['organization_id', 'investigation_run_id'])

    # ── 3. investigation_timeline_events ───────────────────────────────────────
    op.create_table(
        'investigation_timeline_events',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('organization_id', sa.UUID(), nullable=False),
        sa.Column('investigation_run_id', sa.UUID(), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('event_type', sa.String(length=50), nullable=False),
        sa.Column('source_type', sa.String(length=50), nullable=False),
        sa.Column('source_id', sa.String(length=100), nullable=False),
        sa.Column('service_id', sa.UUID(), nullable=True),
        sa.Column('summary', sa.Text(), nullable=False),
        sa.Column('reliability', sa.String(length=20), server_default='MEDIUM', nullable=False),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['investigation_run_id'], ['investigation_runs.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['service_id'], ['services.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_timeline_org_run_timestamp', 'investigation_timeline_events', ['organization_id', 'investigation_run_id', 'timestamp'])

    # ── 4. investigation_correlations ──────────────────────────────────────────
    op.create_table(
        'investigation_correlations',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('organization_id', sa.UUID(), nullable=False),
        sa.Column('investigation_run_id', sa.UUID(), nullable=False),
        sa.Column('source_evidence_id', sa.String(length=100), nullable=False),
        sa.Column('target_evidence_id', sa.String(length=100), nullable=False),
        sa.Column('correlation_type', sa.String(length=50), nullable=False),
        sa.Column('strength', sa.String(length=20), nullable=False),
        sa.Column('score', sa.Float(), nullable=False),
        sa.Column('explanation', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("correlation_type IN ('TEMPORAL', 'SERVICE', 'INCIDENT', 'ALERT', 'RELIABILITY')", name='ck_correlations_type'),
        sa.CheckConstraint("strength IN ('WEAK', 'MODERATE', 'STRONG')", name='ck_correlations_strength'),
        sa.CheckConstraint('score >= 0.0 AND score <= 1.0', name='ck_correlations_score'),
        sa.ForeignKeyConstraint(['investigation_run_id'], ['investigation_runs.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_correlations_org_run_id', 'investigation_correlations', ['organization_id', 'investigation_run_id'])

    # ── 5. investigation_candidate_causes ──────────────────────────────────────
    op.create_table(
        'investigation_candidate_causes',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('organization_id', sa.UUID(), nullable=False),
        sa.Column('investigation_run_id', sa.UUID(), nullable=False),
        sa.Column('cause_type', sa.String(length=50), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('service_id', sa.UUID(), nullable=True),
        sa.Column('score', sa.Float(), server_default='0.0', nullable=False),
        sa.Column('status', sa.String(length=50), server_default='CANDIDATE', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("cause_type IN ('DEPLOYMENT', 'CONFIGURATION', 'SERVICE_FAILURE', 'DEPENDENCY_FAILURE', 'ALERT_PATTERN', 'UNKNOWN')", name='ck_candidate_causes_type'),
        sa.CheckConstraint('score >= 0.0 AND score <= 1.0', name='ck_candidate_causes_score'),
        sa.ForeignKeyConstraint(['investigation_run_id'], ['investigation_runs.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['service_id'], ['services.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_candidate_causes_org_run_id', 'investigation_candidate_causes', ['organization_id', 'investigation_run_id'])

    # ── 6. investigation_hypotheses ────────────────────────────────────────────
    op.create_table(
        'investigation_hypotheses',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('organization_id', sa.UUID(), nullable=False),
        sa.Column('investigation_run_id', sa.UUID(), nullable=False),
        sa.Column('candidate_cause_id', sa.UUID(), nullable=True),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('explanation', sa.Text(), nullable=False),
        sa.Column('confidence', sa.String(length=20), nullable=False),
        sa.Column('score', sa.Float(), nullable=False),
        sa.Column('rank', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=20), server_default='CANDIDATE', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("confidence IN ('LOW', 'MEDIUM', 'HIGH', 'VERY_HIGH')", name='ck_hypotheses_confidence'),
        sa.CheckConstraint("status IN ('CANDIDATE', 'SUPPORTED', 'WEAKENED', 'REJECTED', 'SELECTED')", name='ck_hypotheses_status'),
        sa.CheckConstraint('score >= 0.0 AND score <= 1.0', name='ck_hypotheses_score'),
        sa.ForeignKeyConstraint(['candidate_cause_id'], ['investigation_candidate_causes.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['investigation_run_id'], ['investigation_runs.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_hypotheses_org_run_id', 'investigation_hypotheses', ['organization_id', 'investigation_run_id'])
    op.create_index('ix_hypotheses_org_rank', 'investigation_hypotheses', ['organization_id', 'investigation_run_id', 'rank'])

    # ── 7. investigation_hypothesis_evidence ───────────────────────────────────
    op.create_table(
        'investigation_hypothesis_evidence',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('organization_id', sa.UUID(), nullable=False),
        sa.Column('investigation_run_id', sa.UUID(), nullable=False),
        sa.Column('hypothesis_id', sa.UUID(), nullable=False),
        sa.Column('evidence_type', sa.String(length=50), nullable=False),
        sa.Column('evidence_id', sa.String(length=100), nullable=False),
        sa.Column('relationship', sa.String(length=20), nullable=False),
        sa.Column('contribution', sa.Float(), nullable=False),
        sa.Column('explanation', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("relationship IN ('SUPPORTING', 'CONTRADICTING', 'NEUTRAL')", name='ck_hypo_evidence_relationship'),
        sa.ForeignKeyConstraint(['hypothesis_id'], ['investigation_hypotheses.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['investigation_run_id'], ['investigation_runs.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_hypo_evidence_org_run', 'investigation_hypothesis_evidence', ['organization_id', 'investigation_run_id'])
    op.create_index('ix_hypo_evidence_hypothesis_id', 'investigation_hypothesis_evidence', ['hypothesis_id'])


def downgrade() -> None:
    op.drop_table('investigation_hypothesis_evidence')
    op.drop_table('investigation_hypotheses')
    op.drop_table('investigation_candidate_causes')
    op.drop_table('investigation_correlations')
    op.drop_table('investigation_timeline_events')
    op.drop_table('investigation_steps')
    op.drop_table('investigation_runs')
