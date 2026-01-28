#!/usr/bin/env python3
"""
Check if period_key migration has been applied to the database.

This script checks if the tenant_usage table has the period_key column
and the required constraints/indexes.
"""
import os
import sys
from sqlalchemy import text, inspect
from sqlalchemy.orm import Session

# Add backend to path
backend_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from db import get_db, engine

def check_period_key_migration():
    """Check if period_key migration has been applied."""
    print("Checking period_key migration status...")
    print("=" * 60)
    
    db = next(get_db())
    try:
        # Check if period_key column exists
        inspector = inspect(engine)
        columns = [col['name'] for col in inspector.get_columns('tenant_usage')]
        
        has_period_key = 'period_key' in columns
        print(f"✓ period_key column exists: {has_period_key}")
        
        if not has_period_key:
            print("\n❌ MIGRATION NEEDED: period_key column is missing!")
            print("   Run the migration: l7m8n9o0p1q2_add_period_key_to_tenant_usage")
            return False
        
        # Check for unique constraint
        constraints = inspector.get_unique_constraints('tenant_usage')
        has_unique_constraint = any(
            'period_key' in constraint['column_names'] 
            for constraint in constraints
        )
        print(f"✓ Unique constraint on (tenant_id, period_key): {has_unique_constraint}")
        
        # Check for index
        indexes = inspector.get_indexes('tenant_usage')
        has_index = any(
            'period_key' in index['column_names']
            for index in indexes
        )
        print(f"✓ Index on (tenant_id, period_key): {has_index}")
        
        # Check if any rows have period_key set
        result = db.execute(text("""
            SELECT COUNT(*) as total, 
                   COUNT(period_key) as with_period_key
            FROM tenant_usage
        """)).first()
        
        if result:
            total = result.total
            with_key = result.with_period_key
            print(f"\nData status:")
            print(f"  Total rows: {total}")
            print(f"  Rows with period_key: {with_key}")
            if total > 0 and with_key < total:
                print(f"  ⚠️  {total - with_key} rows missing period_key (backfill needed)")
        
        print("\n" + "=" * 60)
        if has_period_key and has_unique_constraint and has_index:
            print("✅ Migration appears to be complete!")
            return True
        else:
            print("⚠️  Migration partially applied - some components missing")
            return False
            
    except Exception as e:
        print(f"\n❌ Error checking migration: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        db.close()

if __name__ == "__main__":
    success = check_period_key_migration()
    sys.exit(0 if success else 1)
