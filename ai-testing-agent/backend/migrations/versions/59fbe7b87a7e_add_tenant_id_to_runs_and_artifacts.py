"""add_tenant_id_to_runs_and_artifacts

Revision ID: 59fbe7b87a7e
Revises: 51130d39762f
Create Date: 2026-01-16 17:09:30.371016

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision = '59fbe7b87a7e'
down_revision = '51130d39762f'
branch_labels = None
depends_on = None


def upgrade():
    # Step 1: Add tenant_id columns as nullable
    op.add_column('runs', sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column('artifacts', sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=True))
    
    # Step 2: Backfill existing rows with demo tenant
    # Look up tenant by slug 'kerr-ai-studio', or use first tenant if not found
    connection = op.get_bind()
    
    # Find demo tenant
    result = connection.execute(text("""
        SELECT id FROM tenants 
        WHERE slug = 'kerr-ai-studio' 
        LIMIT 1
    """))
    demo_tenant_row = result.fetchone()
    
    if not demo_tenant_row:
        # Fallback to first tenant
        result = connection.execute(text("""
            SELECT id FROM tenants 
            ORDER BY created_at ASC 
            LIMIT 1
        """))
        demo_tenant_row = result.fetchone()
    
    if demo_tenant_row:
        demo_tenant_id = demo_tenant_row[0]
        
        # Backfill runs
        connection.execute(text("""
            UPDATE runs 
            SET tenant_id = :tenant_id 
            WHERE tenant_id IS NULL
        """), {"tenant_id": demo_tenant_id})
        
        # Backfill artifacts (via run relationship)
        connection.execute(text("""
            UPDATE artifacts 
            SET tenant_id = (
                SELECT tenant_id FROM runs 
                WHERE runs.run_id = artifacts.run_id 
                LIMIT 1
            )
            WHERE tenant_id IS NULL
        """))
    else:
        # Check if there are existing runs/artifacts that need backfilling
        runs_count = connection.execute(text("SELECT COUNT(*) FROM runs")).scalar()
        artifacts_count = connection.execute(text("SELECT COUNT(*) FROM artifacts")).scalar()
        
        if runs_count > 0 or artifacts_count > 0:
            # If there are existing rows but no tenant, we can't backfill
            raise Exception(
                "Migration failed: Existing runs/artifacts found but no tenant exists. "
                "Please create a tenant first (e.g., run seed_superuser.py) before running this migration."
            )
        # If no rows exist, migration can proceed (new install)
    
    # Step 3: Add foreign key constraints
    op.create_foreign_key(
        'fk_runs_tenant_id',
        'runs', 'tenants',
        ['tenant_id'], ['id'],
        ondelete='CASCADE'
    )
    op.create_foreign_key(
        'fk_artifacts_tenant_id',
        'artifacts', 'tenants',
        ['tenant_id'], ['id'],
        ondelete='CASCADE'
    )
    
    # Step 4: Set NOT NULL (after backfill)
    op.alter_column('runs', 'tenant_id',
                    existing_type=postgresql.UUID(as_uuid=True),
                    nullable=False)
    op.alter_column('artifacts', 'tenant_id',
                    existing_type=postgresql.UUID(as_uuid=True),
                    nullable=False)
    
    # Step 5: Add indexes for performance
    op.create_index('idx_runs_tenant_id', 'runs', ['tenant_id'])
    op.create_index('idx_artifacts_tenant_id', 'artifacts', ['tenant_id'])


def downgrade():
    # Remove indexes
    op.drop_index('idx_artifacts_tenant_id', table_name='artifacts')
    op.drop_index('idx_runs_tenant_id', table_name='runs')
    
    # Remove foreign key constraints
    op.drop_constraint('fk_artifacts_tenant_id', 'artifacts', type_='foreignkey')
    op.drop_constraint('fk_runs_tenant_id', 'runs', type_='foreignkey')
    
    # Remove columns
    op.drop_column('artifacts', 'tenant_id')
    op.drop_column('runs', 'tenant_id')
