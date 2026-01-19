"""make_tenant_id_nullable_for_onboarding

Revision ID: d7e8f9a0b1c2
Revises: c5d6e7f8a9b0
Create Date: 2026-01-20 12:00:00.000000

Makes tenant_id nullable in tenant_users to support onboarding flow where
users sign up first, then create company/workspace.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = 'd7e8f9a0b1c2'
down_revision = 'c5d6e7f8a9b0'  # Latest migration: normalize_role_to_user
branch_labels = None
depends_on = None


def upgrade():
    # Make tenant_id nullable in tenant_users
    # This allows users to be created before tenant/company is created
    op.alter_column(
        'tenant_users',
        'tenant_id',
        existing_type=postgresql.UUID(as_uuid=True),
        nullable=True,
        existing_nullable=False
    )
    
    # Note: Foreign key constraint remains, but now allows NULL
    # Users with NULL tenant_id are in "onboarding incomplete" state


def downgrade():
    # Before making tenant_id NOT NULL, we must ensure no NULL values exist
    # In practice, this migration should only be run if all users have tenants
    op.alter_column(
        'tenant_users',
        'tenant_id',
        existing_type=postgresql.UUID(as_uuid=True),
        nullable=False,
        existing_nullable=True
    )
