"""add_password_reset_tokens_table

Revision ID: i4j5k6l7m8n9
Revises: h3i4j5k6l7m8
Create Date: 2026-01-23 12:00:00.000000

Adds password_reset_tokens table for Phase 2.1 password reset flow.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


# revision identifiers, used by Alembic.
revision = 'i4j5k6l7m8n9'
down_revision = 'h3i4j5k6l7m8'  # map_subscription_status_to_new_tiers
branch_labels = None
depends_on = None


def upgrade():
    # Create password_reset_tokens table
    op.create_table(
        'password_reset_tokens',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('user_id', UUID(as_uuid=True), nullable=False),
        sa.Column('token_hash', sa.Text(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.ForeignKeyConstraint(['user_id'], ['tenant_users.id'], ondelete='CASCADE'),
        sa.UniqueConstraint('token_hash', name='uq_password_reset_tokens_token_hash')
    )
    
    # Create indexes
    op.create_index('idx_password_reset_user_id', 'password_reset_tokens', ['user_id'])
    op.create_index('idx_password_reset_expires_at', 'password_reset_tokens', ['expires_at'])


def downgrade():
    op.drop_index('idx_password_reset_expires_at', table_name='password_reset_tokens')
    op.drop_index('idx_password_reset_user_id', table_name='password_reset_tokens')
    op.drop_table('password_reset_tokens')
