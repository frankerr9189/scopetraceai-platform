"""add_tenant_integrations_table

Revision ID: 7886edc4b365
Revises: 59fbe7b87a7e
Create Date: 2026-01-16 18:30:45.123456

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = '7886edc4b365'
down_revision = '59fbe7b87a7e'
branch_labels = None
depends_on = None


def upgrade():
    # Create tenant_integrations table
    op.create_table(
        'tenant_integrations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('provider', sa.String(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('jira_base_url', sa.String(), nullable=True),
        sa.Column('jira_user_email', sa.String(), nullable=True),
        sa.Column('credentials_ciphertext', sa.Text(), nullable=False),
        sa.Column('credentials_version', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
    )
    
    # Create indexes
    op.create_index('idx_tenant_integrations_tenant_id', 'tenant_integrations', ['tenant_id'])
    
    # Create unique constraint: one integration per provider per tenant
    op.create_unique_constraint('uq_tenant_integrations_tenant_provider', 'tenant_integrations', ['tenant_id', 'provider'])


def downgrade():
    op.drop_constraint('uq_tenant_integrations_tenant_provider', 'tenant_integrations', type_='unique')
    op.drop_index('idx_tenant_integrations_tenant_id', table_name='tenant_integrations')
    op.drop_table('tenant_integrations')
