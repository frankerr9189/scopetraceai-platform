"""add_admin_audit_log_table

Revision ID: j5k6l7m8n9o0
Revises: i4j5k6l7m8n9
Create Date: 2026-01-24 12:00:00.000000

Adds admin_audit_log table for ops safety audit trail.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


# revision identifiers, used by Alembic.
revision = 'j5k6l7m8n9o0'
down_revision = 'i4j5k6l7m8n9'  # add_password_reset_tokens_table
branch_labels = None
depends_on = None


def upgrade():
    # Create admin_audit_log table
    op.create_table(
        'admin_audit_log',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('tenant_id', UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', UUID(as_uuid=True), nullable=False),
        sa.Column('action', sa.String(100), nullable=False),  # e.g., 'ops.user.deactivate', 'ops.tenant.suspend'
        sa.Column('target_type', sa.String(50), nullable=True),  # 'user' | 'tenant' | 'usage' | 'run'
        sa.Column('target_id', UUID(as_uuid=True), nullable=True),  # ID of the target entity
        sa.Column('metadata', sa.Text(), nullable=True),  # JSON string for additional context
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['tenant_users.id'], ondelete='SET NULL')
    )
    
    # Create indexes
    op.create_index('idx_admin_audit_tenant_id', 'admin_audit_log', ['tenant_id'])
    op.create_index('idx_admin_audit_user_id', 'admin_audit_log', ['user_id'])
    op.create_index('idx_admin_audit_created_at', 'admin_audit_log', ['created_at'])
    op.create_index('idx_admin_audit_action', 'admin_audit_log', ['action'])


def downgrade():
    op.drop_index('idx_admin_audit_action', table_name='admin_audit_log')
    op.drop_index('idx_admin_audit_created_at', table_name='admin_audit_log')
    op.drop_index('idx_admin_audit_user_id', table_name='admin_audit_log')
    op.drop_index('idx_admin_audit_tenant_id', table_name='admin_audit_log')
    op.drop_table('admin_audit_log')
