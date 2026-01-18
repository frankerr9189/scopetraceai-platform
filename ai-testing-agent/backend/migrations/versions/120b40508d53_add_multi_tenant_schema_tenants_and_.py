"""Add multi-tenant schema (tenants and tenant_users)

Revision ID: 120b40508d53
Revises: 
Create Date: 2026-01-15 22:22:48.352693

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '120b40508d53'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Create tenants table
    op.create_table(
        'tenants',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('slug', sa.String(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_tenants_slug', 'tenants', ['slug'], unique=True)
    
    # Create tenant_users table
    op.create_table(
        'tenant_users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('password_hash', sa.String(), nullable=False),
        sa.Column('role', sa.String(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('first_name', sa.String(), nullable=True),
        sa.Column('last_name', sa.String(), nullable=True),
        sa.Column('address_1', sa.String(), nullable=True),
        sa.Column('address_2', sa.String(), nullable=True),
        sa.Column('city', sa.String(), nullable=True),
        sa.Column('state', sa.String(), nullable=True),
        sa.Column('zip', sa.String(), nullable=True),
        sa.Column('phone', sa.String(), nullable=True),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
    )
    op.create_index('idx_tenant_users_tenant_id', 'tenant_users', ['tenant_id'])
    op.create_index('idx_tenant_users_email', 'tenant_users', ['email'])
    op.create_unique_constraint('uq_tenant_users_tenant_email', 'tenant_users', ['tenant_id', 'email'])


def downgrade():
    op.drop_constraint('uq_tenant_users_tenant_email', 'tenant_users', type_='unique')
    op.drop_index('idx_tenant_users_email', table_name='tenant_users')
    op.drop_index('idx_tenant_users_tenant_id', table_name='tenant_users')
    op.drop_table('tenant_users')
    op.drop_index('ix_tenants_slug', table_name='tenants')
    op.drop_table('tenants')
