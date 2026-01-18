"""normalize_role_to_user

Revision ID: c5d6e7f8a9b0
Revises: b4e7f8a9c0d1
Create Date: 2026-01-20 10:00:00.000000

Normalize role default from 'member' to 'user' and update existing data.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c5d6e7f8a9b0'
down_revision = 'b4e7f8a9c0d1'
branch_labels = None
depends_on = None


def upgrade():
    # Step 1: Normalize existing 'member' roles to 'user'
    op.execute("UPDATE tenant_users SET role='user' WHERE role='member'")
    
    # Step 2: Change the server_default from 'member' to 'user'
    # First, drop the existing default
    op.alter_column('tenant_users', 'role',
                    existing_type=sa.String(),
                    server_default=None)
    
    # Then add the new default
    op.alter_column('tenant_users', 'role',
                    existing_type=sa.String(),
                    nullable=False,
                    server_default='user')


def downgrade():
    # Revert server_default back to 'member'
    op.alter_column('tenant_users', 'role',
                    existing_type=sa.String(),
                    server_default=None)
    
    op.alter_column('tenant_users', 'role',
                    existing_type=sa.String(),
                    nullable=False,
                    server_default='member')
    
    # Note: We don't revert the data normalization (member -> user)
    # as we can't distinguish which rows were originally 'member' vs 'user'
