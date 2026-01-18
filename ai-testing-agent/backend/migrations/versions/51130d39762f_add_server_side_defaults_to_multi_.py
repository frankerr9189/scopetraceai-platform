"""Add server-side defaults to multi-tenant schema

Revision ID: 51130d39762f
Revises: 120b40508d53
Create Date: 2026-01-15 22:42:11.229910

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '51130d39762f'
down_revision = '120b40508d53'
branch_labels = None
depends_on = None


def upgrade():
    # Add server-side defaults to tenants table
    # Note: Using ALTER COLUMN SET DEFAULT for existing columns (forward-only, no drops)
    op.alter_column('tenants', 'is_active',
                    existing_type=sa.Boolean(),
                    server_default='true',
                    existing_nullable=False)
    
    op.alter_column('tenants', 'created_at',
                    existing_type=postgresql.TIMESTAMP(timezone=True),
                    server_default=sa.text('now()'),
                    existing_nullable=False)
    
    op.alter_column('tenants', 'updated_at',
                    existing_type=postgresql.TIMESTAMP(timezone=True),
                    server_default=sa.text('now()'),
                    existing_nullable=False)
    
    # Add server-side defaults to tenant_users table
    op.alter_column('tenant_users', 'is_active',
                    existing_type=sa.Boolean(),
                    server_default='true',
                    existing_nullable=False)
    
    op.alter_column('tenant_users', 'role',
                    existing_type=sa.String(),
                    server_default='member',
                    existing_nullable=False)
    
    op.alter_column('tenant_users', 'created_at',
                    existing_type=postgresql.TIMESTAMP(timezone=True),
                    server_default=sa.text('now()'),
                    existing_nullable=False)
    
    op.alter_column('tenant_users', 'updated_at',
                    existing_type=postgresql.TIMESTAMP(timezone=True),
                    server_default=sa.text('now()'),
                    existing_nullable=False)


def downgrade():
    # Remove server-side defaults (reverse the changes)
    op.alter_column('tenant_users', 'updated_at',
                    existing_type=postgresql.TIMESTAMP(timezone=True),
                    server_default=None,
                    existing_nullable=False)
    
    op.alter_column('tenant_users', 'created_at',
                    existing_type=postgresql.TIMESTAMP(timezone=True),
                    server_default=None,
                    existing_nullable=False)
    
    op.alter_column('tenant_users', 'role',
                    existing_type=sa.String(),
                    server_default=None,
                    existing_nullable=False)
    
    op.alter_column('tenant_users', 'is_active',
                    existing_type=sa.Boolean(),
                    server_default=None,
                    existing_nullable=False)
    
    op.alter_column('tenants', 'updated_at',
                    existing_type=postgresql.TIMESTAMP(timezone=True),
                    server_default=None,
                    existing_nullable=False)
    
    op.alter_column('tenants', 'created_at',
                    existing_type=postgresql.TIMESTAMP(timezone=True),
                    server_default=None,
                    existing_nullable=False)
    
    op.alter_column('tenants', 'is_active',
                    existing_type=sa.Boolean(),
                    server_default=None,
                    existing_nullable=False)
