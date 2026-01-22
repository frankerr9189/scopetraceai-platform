"""add_user_invite_tokens_table

Revision ID: k6l7m8n9o0p1
Revises: j5k6l7m8n9o0
Create Date: 2026-01-25 12:00:00.000000

Adds user_invite_tokens table for Phase A: Tenant User Management.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


# revision identifiers, used by Alembic.
revision = 'k6l7m8n9o0p1'
down_revision = 'j5k6l7m8n9o0'  # add_admin_audit_log_table
branch_labels = None
depends_on = None


def upgrade():
    # Create user_invite_tokens table
    op.create_table(
        'user_invite_tokens',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('user_id', UUID(as_uuid=True), nullable=False),
        sa.Column('token_hash', sa.Text(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('created_by_user_id', UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['tenant_users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by_user_id'], ['tenant_users.id'], ondelete='SET NULL'),
        sa.UniqueConstraint('token_hash', name='uq_user_invite_tokens_token_hash')
    )
    
    # Create indexes
    op.create_index('idx_user_invite_tokens_user_id', 'user_invite_tokens', ['user_id'])
    op.create_index('idx_user_invite_tokens_expires_at', 'user_invite_tokens', ['expires_at'])
    op.create_index('idx_user_invite_tokens_token_hash', 'user_invite_tokens', ['token_hash'])


def downgrade():
    op.drop_index('idx_user_invite_tokens_token_hash', table_name='user_invite_tokens')
    op.drop_index('idx_user_invite_tokens_expires_at', table_name='user_invite_tokens')
    op.drop_index('idx_user_invite_tokens_user_id', table_name='user_invite_tokens')
    op.drop_table('user_invite_tokens')
