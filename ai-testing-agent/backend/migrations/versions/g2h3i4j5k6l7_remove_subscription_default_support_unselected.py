"""remove_subscription_default_support_unselected

Revision ID: g2h3i4j5k6l7
Revises: f1a2b3c4d5e6
Create Date: 2026-01-22 14:00:00.000000

Remove default from subscription_status and support "unselected" state.
- Remove server_default from subscription_status (must be explicitly set)
- Update trial counters default to 0 (only set when plan is selected)
- New tenants should be created with subscription_status="unselected"
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision = 'g2h3i4j5k6l7'
down_revision = 'f1a2b3c4d5e6'  # cleanup_tenant_first_onboarding
branch_labels = None
depends_on = None


def upgrade():
    """
    Remove default from subscription_status and update trial counter defaults.
    """
    # Step 1: Update any existing tenants with NULL or default "Trial" to explicit values
    # If subscription_status is NULL or "Trial" and counters are at default, set to "unselected"
    conn = op.get_bind()
    
    # Update tenants that have default "Trial" status and default counters to "unselected"
    # This handles existing tenants that were created with defaults
    conn.execute(text("""
        UPDATE tenants
        SET subscription_status = 'unselected'
        WHERE subscription_status = 'Trial'
          AND trial_requirements_runs_remaining = 3
          AND trial_testplan_runs_remaining = 3
          AND trial_writeback_runs_remaining = 3
    """))
    
    # Step 2: Remove server_default from subscription_status
    # First, ensure no NULL values exist
    null_count = conn.execute(text("""
        SELECT COUNT(*) FROM tenants WHERE subscription_status IS NULL
    """)).scalar()
    
    if null_count > 0:
        # Set NULL values to "unselected"
        conn.execute(text("""
            UPDATE tenants
            SET subscription_status = 'unselected'
            WHERE subscription_status IS NULL
        """))
    
    # Remove the default
    op.alter_column(
        'tenants',
        'subscription_status',
        existing_type=sa.String(),
        nullable=False,
        server_default=None,
        existing_nullable=False
    )
    
    # Step 3: Update trial counter defaults to 0
    op.alter_column(
        'tenants',
        'trial_requirements_runs_remaining',
        existing_type=sa.Integer(),
        nullable=False,
        server_default=text('0'),
        existing_nullable=False
    )
    
    op.alter_column(
        'tenants',
        'trial_testplan_runs_remaining',
        existing_type=sa.Integer(),
        nullable=False,
        server_default=text('0'),
        existing_nullable=False
    )
    
    op.alter_column(
        'tenants',
        'trial_writeback_runs_remaining',
        existing_type=sa.Integer(),
        nullable=False,
        server_default=text('0'),
        existing_nullable=False
    )
    
    print("Removed default from subscription_status and updated trial counter defaults to 0")


def downgrade():
    """
    Restore defaults (not recommended - this would break explicit plan selection).
    """
    # Restore subscription_status default
    op.alter_column(
        'tenants',
        'subscription_status',
        existing_type=sa.String(),
        nullable=False,
        server_default=text("'Trial'"),
        existing_nullable=False
    )
    
    # Restore trial counter defaults
    op.alter_column(
        'tenants',
        'trial_requirements_runs_remaining',
        existing_type=sa.Integer(),
        nullable=False,
        server_default=text('3'),
        existing_nullable=False
    )
    
    op.alter_column(
        'tenants',
        'trial_testplan_runs_remaining',
        existing_type=sa.Integer(),
        nullable=False,
        server_default=text('3'),
        existing_nullable=False
    )
    
    op.alter_column(
        'tenants',
        'trial_writeback_runs_remaining',
        existing_type=sa.Integer(),
        nullable=False,
        server_default=text('3'),
        existing_nullable=False
    )
    
    print("Restored defaults (WARNING: This breaks explicit plan selection)")
