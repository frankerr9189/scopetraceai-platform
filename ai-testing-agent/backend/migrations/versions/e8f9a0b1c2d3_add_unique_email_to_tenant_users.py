"""add_unique_email_to_tenant_users

Revision ID: e8f9a0b1c2d3
Revises: d7e8f9a0b1c2
Create Date: 2026-01-21 12:00:00.000000

Adds UNIQUE constraint on tenant_users.email to ensure each app user
(email address) can only have ONE row in tenant_users table.

This prevents duplicate user rows (e.g., one NULL tenant_id + one non-NULL tenant_id)
and enforces data integrity at the database level.

Before adding the constraint, this migration:
1. Detects duplicate emails
2. Cleans them up deterministically:
   - Prefer row with tenant_id NOT NULL (onboarding complete)
   - If multiple have tenant_id NOT NULL, keep most recent (largest created_at, then id)
   - Otherwise keep row with largest id
3. Deletes duplicate rows
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = 'e8f9a0b1c2d3'
down_revision = 'd7e8f9a0b1c2'  # make_tenant_id_nullable_for_onboarding
branch_labels = None
depends_on = None


def upgrade():
    """
    Add UNIQUE constraint on tenant_users.email after cleaning up duplicates.
    """
    conn = op.get_bind()
    
    # Step 1: Check for duplicate emails
    duplicate_check = conn.execute(text("""
        SELECT email, COUNT(*) as count
        FROM tenant_users
        GROUP BY email
        HAVING COUNT(*) > 1
    """))
    
    duplicates = duplicate_check.fetchall()
    
    if duplicates:
        print(f"Found {len(duplicates)} email(s) with duplicate rows. Cleaning up...")
        
        # Step 2: For each duplicate email, determine which row to keep
        for (email, count) in duplicates:
            print(f"  Processing email: {email} ({count} rows)")
            
            # Get all rows for this email, ordered by preference:
            # 1. tenant_id NOT NULL (onboarding complete)
            # 2. created_at DESC (most recent)
            # 3. id DESC (fallback)
            rows = conn.execute(text("""
                SELECT id, tenant_id, created_at
                FROM tenant_users
                WHERE email = :email
                ORDER BY 
                    CASE WHEN tenant_id IS NOT NULL THEN 0 ELSE 1 END,
                    created_at DESC NULLS LAST,
                    id DESC
            """), {"email": email}).fetchall()
            
            if not rows:
                continue
            
            # Keep the first row (best candidate)
            keep_id = rows[0][0]
            print(f"    Keeping row with id: {keep_id}")
            
            # Delete all other rows
            delete_ids = [row[0] for row in rows[1:]]
            if delete_ids:
                print(f"    Deleting {len(delete_ids)} duplicate row(s)")
                # Delete rows one by one to avoid SQL injection
                for delete_id in delete_ids:
                    conn.execute(text("""
                        DELETE FROM tenant_users
                        WHERE id = :id
                    """), {"id": delete_id})
        
        # Commit the cleanup
        conn.commit()
        print("Duplicate cleanup complete.")
    else:
        print("No duplicate emails found. Proceeding with constraint addition.")
    
    # Step 3: Drop the old composite unique constraint (tenant_id, email)
    # This is replaced by global email uniqueness
    try:
        op.drop_constraint('uq_tenant_users_tenant_email', 'tenant_users', type_='unique')
        print("Dropped old composite unique constraint (tenant_id, email)")
    except Exception as e:
        # Constraint might not exist in some environments
        print(f"Note: Could not drop old constraint (may not exist): {e}")
    
    # Step 4: Add UNIQUE constraint on email (global)
    # This ensures each app user (email) can only have ONE row in tenant_users
    op.create_unique_constraint(
        'uq_tenant_users_email_global',
        'tenant_users',
        ['email']
    )
    
    print("Added UNIQUE constraint on tenant_users.email (global)")


def downgrade():
    """
    Remove UNIQUE constraint on tenant_users.email and restore composite constraint.
    """
    # Drop global email constraint
    op.drop_constraint('uq_tenant_users_email_global', 'tenant_users', type_='unique')
    print("Removed UNIQUE constraint on tenant_users.email")
    
    # Restore composite unique constraint (tenant_id, email)
    # Note: This may fail if duplicate emails exist across tenants
    try:
        op.create_unique_constraint(
            'uq_tenant_users_tenant_email',
            'tenant_users',
            ['tenant_id', 'email']
        )
        print("Restored composite unique constraint (tenant_id, email)")
    except Exception as e:
        print(f"Warning: Could not restore composite constraint (duplicates may exist): {e}")
