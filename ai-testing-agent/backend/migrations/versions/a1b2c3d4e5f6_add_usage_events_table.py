"""add_usage_events_table

Revision ID: a1b2c3d4e5f6
Revises: 7886edc4b365
Create Date: 2026-01-16 22:50:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = 'a1b2c3d4e5f6'
down_revision = '7886edc4b365'
branch_labels = None
depends_on = None


def upgrade():
    # Create usage_events table
    op.create_table(
        'usage_events',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('agent', sa.String(), nullable=False),
        sa.Column('source', sa.String(), nullable=False),
        sa.Column('jira_ticket_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('input_char_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('success', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('error_code', sa.String(), nullable=True),
        sa.Column('run_id', sa.String(), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['tenant_users.id'], ondelete='SET NULL'),
    )
    
    # Create indexes
    op.create_index('idx_usage_events_tenant_id', 'usage_events', ['tenant_id'])
    op.create_index('idx_usage_events_agent', 'usage_events', ['agent'])
    op.create_index('idx_usage_events_created_at', 'usage_events', ['created_at'])


def downgrade():
    op.drop_index('idx_usage_events_created_at', table_name='usage_events')
    op.drop_index('idx_usage_events_agent', table_name='usage_events')
    op.drop_index('idx_usage_events_tenant_id', table_name='usage_events')
    op.drop_table('usage_events')
