"""cleanup_tenant_first_onboarding

Revision ID: f1a2b3c4d5e6
Revises: e8f9a0b1c2d3
Create Date: 2026-01-22 12:00:00.000000

Cleanup migration for tenant-first onboarding:
1. Delete orphaned tenant_users rows (tenant_id IS NULL)
2. Remove global UNIQUE(email) constraint
3. Restore per-tenant UNIQUE(tenant_id, email) constraint
4. Enforce tenant_id NOT NULL

This migration fixes forward from user-first onboarding experiments.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = 'f1a2b3c4d5e6'
down_revision = 'e8f9a0b1c2d3'  # add_unique_email_to_tenant_users
branch_labels = None
depends_on = None


def upgrade():
    """
    Clean up user-first onboarding artifacts and restore tenant-first schema.
    """
    conn = op.get_bind()
    
    # Step 1: Delete orphaned tenant_users rows (tenant_id IS NULL)
    # These are invalid in tenant-first model
    orphan_count = conn.execute(text("""
        SELECT COUNT(*) FROM tenant_users WHERE tenant_id IS NULL
    """)).scalar()
    
    if orphan_count > 0:
        print(f"Found {orphan_count} orphaned tenant_users row(s) with tenant_id IS NULL. Deleting...")
        conn.execute(text("""
            DELETE FROM tenant_users WHERE tenant_id IS NULL
        """))
        conn.commit()
        print(f"Deleted {orphan_count} orphaned row(s).")
    else:
        print("No orphaned tenant_users rows found.")
    
    # Step 2: Remove global UNIQUE(email) constraint if it exists
    try:
        op.drop_constraint('uq_tenant_users_email_global', 'tenant_users', type_='unique')
        print("Removed global UNIQUE(email) constraint.")
    except Exception as e:
        print(f"Note: Global UNIQUE(email) constraint may not exist: {e}")
    
    # Step 3: Restore per-tenant UNIQUE(tenant_id, email) constraint
    # Check if it already exists first
    try:
        op.create_unique_constraint(
            'uq_tenant_users_tenant_email',
            'tenant_users',
            ['tenant_id', 'email']
        )
        print("Restored per-tenant UNIQUE(tenant_id, email) constraint.")
    except Exception as e:
        print(f"Note: Per-tenant unique constraint may already exist: {e}")
    
    # Step 4: Enforce tenant_id NOT NULL
    # First verify no NULL values remain (should be 0 after Step 1)
    null_count = conn.execute(text("""
        SELECT COUNT(*) FROM tenant_users WHERE tenant_id IS NULL
    """)).scalar()
    
    if null_count > 0:
        raise ValueError(
            f"Cannot enforce NOT NULL: {null_count} tenant_users rows still have tenant_id IS NULL. "
            "Please clean up these rows manually before running this migration."
        )
    
    op.alter_column(
        'tenant_users',
        'tenant_id',
        existing_type=postgresql.UUID(as_uuid=True),
        nullable=False,
        existing_nullable=True
    )
    print("Enforced tenant_id NOT NULL constraint.")


def downgrade():
    """
    Revert to user-first onboarding schema (NOT RECOMMENDED).
    This downgrade is provided for completeness but should not be used in production.
    """
    # Make tenant_id nullable again
    op.alter_column(
        'tenant_users',
        'tenant_id',
        existing_type=postgresql.UUID(as_uuid=True),
        nullable=True,
        existing_nullable=False
    )
    print("Made tenant_id nullable again (user-first onboarding).")
    
    # Remove per-tenant unique constraint
    try:
        op.drop_constraint('uq_tenant_users_tenant_email', 'tenant_users', type_='unique')
        print("Removed per-tenant UNIQUE(tenant_id, email) constraint.")
    except Exception as e:
        print(f"Note: Constraint may not exist: {e}")
    
    # Restore global UNIQUE(email) constraint
    try:
        op.create_unique_constraint(
            'uq_tenant_users_email_global',
            'tenant_users',
            ['email']
        )
        print("Restored global UNIQUE(email) constraint.")
    except Exception as e:
        print(f"Warning: Could not restore global constraint (duplicates may exist): {e}")
