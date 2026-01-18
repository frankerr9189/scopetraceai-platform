"""add_subscription_trial_to_tenants

Revision ID: b4e7f8a9c0d1
Revises: 815acca3a55
Create Date: 2026-01-18 12:00:00.000000

Adds subscription_status and per-agent trial run counters to tenants for
onboarding gating (Step 1). Existing tenants receive defaults: Trial, 3 runs each.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b4e7f8a9c0d1'
down_revision = '815acca3a55'
branch_labels = None
depends_on = None


def upgrade():
    # Add subscription_status (NOT NULL, default 'Trial')
    # server_default backfills existing rows automatically
    op.add_column(
        'tenants',
        sa.Column(
            'subscription_status',
            sa.String(),
            nullable=False,
            server_default='Trial',
        ),
    )

    # Add per-agent trial run counters (NOT NULL, default 3 each)
    op.add_column(
        'tenants',
        sa.Column(
            'trial_requirements_runs_remaining',
            sa.Integer(),
            nullable=False,
            server_default='3',
        ),
    )
    op.add_column(
        'tenants',
        sa.Column(
            'trial_testplan_runs_remaining',
            sa.Integer(),
            nullable=False,
            server_default='3',
        ),
    )
    op.add_column(
        'tenants',
        sa.Column(
            'trial_writeback_runs_remaining',
            sa.Integer(),
            nullable=False,
            server_default='3',
        ),
    )


def downgrade():
    op.drop_column('tenants', 'trial_writeback_runs_remaining')
    op.drop_column('tenants', 'trial_testplan_runs_remaining')
    op.drop_column('tenants', 'trial_requirements_runs_remaining')
    op.drop_column('tenants', 'subscription_status')
