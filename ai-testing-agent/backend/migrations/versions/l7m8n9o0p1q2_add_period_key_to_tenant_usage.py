"""add_period_key_to_tenant_usage

Revision ID: l7m8n9o0p1q2
Revises: k6l7m8n9o0p1
Create Date: 2026-01-20 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = 'l7m8n9o0p1q2'
down_revision = 'k6l7m8n9o0p1'
branch_labels = None
depends_on = None


def upgrade():
    # Add period_key column (nullable initially for backfill)
    op.add_column('tenant_usage', sa.Column('period_key', sa.Text(), nullable=True))
    
    # Backfill period_key for existing rows
    # Format: "YYYY-MM" for calendar months, or "YYYY-MM-DD_YYYY-MM-DD" for Stripe periods
    op.execute("""
        UPDATE tenant_usage
        SET period_key = CASE
            -- If period is calendar month (1st to last day of month)
            -- Check if period_start is the 1st of the month
            -- and period_end is the last day of the same month
            WHEN EXTRACT(DAY FROM period_start) = 1 
                 AND period_end = (DATE_TRUNC('MONTH', period_start) + INTERVAL '1 MONTH - 1 day')::date
            THEN TO_CHAR(period_start, 'YYYY-MM')
            -- Otherwise use full period range (Stripe periods or other)
            ELSE TO_CHAR(period_start, 'YYYY-MM-DD') || '_' || TO_CHAR(period_end, 'YYYY-MM-DD')
        END
    """)
    
    # Make period_key NOT NULL
    op.alter_column('tenant_usage', 'period_key', nullable=False)
    
    # Drop old unique constraint if it exists
    try:
        op.drop_constraint('tenant_usage_tenant_id_period_start_period_end_key', 'tenant_usage', type_='unique')
    except:
        # Constraint might not exist or have different name
        pass
    
    # Add new unique constraint on (tenant_id, period_key)
    op.create_unique_constraint(
        'uq_tenant_usage_tenant_id_period_key',
        'tenant_usage',
        ['tenant_id', 'period_key']
    )
    
    # Add index for faster lookups
    op.create_index(
        'idx_tenant_usage_tenant_id_period_key',
        'tenant_usage',
        ['tenant_id', 'period_key']
    )


def downgrade():
    # Remove index
    op.drop_index('idx_tenant_usage_tenant_id_period_key', table_name='tenant_usage')
    
    # Remove unique constraint
    op.drop_constraint('uq_tenant_usage_tenant_id_period_key', 'tenant_usage', type_='unique')
    
    # Restore old unique constraint (if needed)
    # Note: This might fail if the constraint name was different
    try:
        op.create_unique_constraint(
            'tenant_usage_tenant_id_period_start_period_end_key',
            'tenant_usage',
            ['tenant_id', 'period_start', 'period_end']
        )
    except:
        pass
    
    # Remove period_key column
    op.drop_column('tenant_usage', 'period_key')
