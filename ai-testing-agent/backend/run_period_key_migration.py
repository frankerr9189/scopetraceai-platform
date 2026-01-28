#!/usr/bin/env python3
"""
Script to run the period_key migration directly.
This handles the case where earlier migrations might be in an inconsistent state.
"""
import os
import sys
from sqlalchemy import text, inspect
from sqlalchemy.exc import ProgrammingError

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

from app import app
from db import engine

def check_column_exists(engine, table_name, column_name):
    """Check if a column exists in a table."""
    inspector = inspect(engine)
    columns = [col['name'] for col in inspector.get_columns(table_name)]
    return column_name in columns

def check_table_exists(engine, table_name):
    """Check if a table exists."""
    inspector = inspect(engine)
    return table_name in inspector.get_table_names()

def run_period_key_migration():
    """Run the period_key migration directly."""
    with app.app_context():
        db_engine = engine
        
        print("=" * 60)
        print("Running period_key migration for tenant_usage table")
        print("=" * 60)
        print()
        
        # Check if tenant_usage table exists
        if not check_table_exists(db_engine, 'tenant_usage'):
            print("❌ ERROR: tenant_usage table does not exist!")
            print("   Please ensure the database schema is set up correctly.")
            return False
        
        # Check if period_key already exists
        if check_column_exists(db_engine, 'tenant_usage', 'period_key'):
            print("✓ period_key column already exists. Migration may have already been applied.")
            print("  Verifying constraint and index...")
            
            # Check if constraint exists
            with db_engine.connect() as conn:
                result = conn.execute(text("""
                    SELECT constraint_name 
                    FROM information_schema.table_constraints 
                    WHERE table_name = 'tenant_usage' 
                    AND constraint_name = 'uq_tenant_usage_tenant_id_period_key'
                """))
                if result.first():
                    print("✓ Unique constraint already exists.")
                else:
                    print("⚠ Unique constraint missing. Creating...")
                    try:
                        conn.execute(text("""
                            ALTER TABLE tenant_usage
                            ADD CONSTRAINT uq_tenant_usage_tenant_id_period_key
                            UNIQUE (tenant_id, period_key)
                        """))
                        conn.commit()
                        print("✓ Unique constraint created.")
                    except Exception as e:
                        print(f"⚠ Could not create constraint: {e}")
                
                # Check if index exists
                result = conn.execute(text("""
                    SELECT indexname 
                    FROM pg_indexes 
                    WHERE tablename = 'tenant_usage' 
                    AND indexname = 'idx_tenant_usage_tenant_id_period_key'
                """))
                if result.first():
                    print("✓ Index already exists.")
                else:
                    print("⚠ Index missing. Creating...")
                    try:
                        conn.execute(text("""
                            CREATE INDEX idx_tenant_usage_tenant_id_period_key
                            ON tenant_usage (tenant_id, period_key)
                        """))
                        conn.commit()
                        print("✓ Index created.")
                    except Exception as e:
                        print(f"⚠ Could not create index: {e}")
            
            return True
        
        print("Step 1: Adding period_key column (nullable)...")
        with db_engine.begin() as conn:
            try:
                conn.execute(text("""
                    ALTER TABLE tenant_usage
                    ADD COLUMN period_key TEXT
                """))
                print("✓ Column added.")
            except Exception as e:
                if "already exists" in str(e).lower() or "duplicate" in str(e).lower():
                    print("⚠ Column already exists (continuing...)")
                else:
                    print(f"❌ Error adding column: {e}")
                    return False
        
        print("\nStep 2: Backfilling period_key for existing rows...")
        with db_engine.begin() as conn:
            try:
                result = conn.execute(text("""
                    UPDATE tenant_usage
                    SET period_key = CASE
                        -- If period is calendar month (1st to last day of month)
                        -- Check if period_start is the 1st of the month
                        -- and period_end is the last day of the same month
                        WHEN EXTRACT(DAY FROM period_start) = 1 
                             AND period_end = (DATE_TRUNC('MONTH', period_start) + INTERVAL '1 MONTH - 1 day')::date
                        THEN TO_CHAR(period_start, 'YYYY-MM')
                        -- Otherwise use full period range (Stripe periods or other)
                        ELSE TO_CHAR(period_start, 'YYYY-MM-DD') || '_' || TO_CHAR(period_end, 'YYYY-MM-DD')
                    END
                    WHERE period_key IS NULL
                """))
                rows_updated = result.rowcount
                print(f"✓ Backfilled {rows_updated} row(s).")
            except Exception as e:
                print(f"❌ Error backfilling: {e}")
                return False
        
        print("\nStep 3: Making period_key NOT NULL...")
        with db_engine.begin() as conn:
            try:
                conn.execute(text("""
                    ALTER TABLE tenant_usage
                    ALTER COLUMN period_key SET NOT NULL
                """))
                print("✓ Column set to NOT NULL.")
            except Exception as e:
                print(f"❌ Error setting NOT NULL: {e}")
                return False
        
        print("\nStep 4: Dropping old unique constraint (if exists)...")
        with db_engine.begin() as conn:
            try:
                # Try to find and drop the old constraint
                result = conn.execute(text("""
                    SELECT constraint_name 
                    FROM information_schema.table_constraints 
                    WHERE table_name = 'tenant_usage' 
                    AND constraint_type = 'UNIQUE'
                    AND constraint_name LIKE '%period_start%period_end%'
                """))
                constraints = [row[0] for row in result]
                for constraint_name in constraints:
                    try:
                        conn.execute(text(f"""
                            ALTER TABLE tenant_usage
                            DROP CONSTRAINT IF EXISTS {constraint_name}
                        """))
                        print(f"✓ Dropped constraint: {constraint_name}")
                    except Exception as e:
                        print(f"⚠ Could not drop constraint {constraint_name}: {e}")
            except Exception as e:
                print(f"⚠ Error checking/dropping old constraints: {e}")
        
        print("\nStep 5: Creating new unique constraint...")
        with db_engine.begin() as conn:
            try:
                conn.execute(text("""
                    ALTER TABLE tenant_usage
                    ADD CONSTRAINT uq_tenant_usage_tenant_id_period_key
                    UNIQUE (tenant_id, period_key)
                """))
                print("✓ Unique constraint created.")
            except Exception as e:
                if "already exists" in str(e).lower():
                    print("⚠ Constraint already exists (continuing...)")
                else:
                    print(f"❌ Error creating constraint: {e}")
                    return False
        
        print("\nStep 6: Creating index...")
        with db_engine.begin() as conn:
            try:
                conn.execute(text("""
                    CREATE INDEX idx_tenant_usage_tenant_id_period_key
                    ON tenant_usage (tenant_id, period_key)
                """))
                print("✓ Index created.")
            except Exception as e:
                if "already exists" in str(e).lower():
                    print("⚠ Index already exists (continuing...)")
                else:
                    print(f"❌ Error creating index: {e}")
                    return False
        
        print("\n" + "=" * 60)
        print("✓ Migration completed successfully!")
        print("=" * 60)
        return True

if __name__ == "__main__":
    try:
        success = run_period_key_migration()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
