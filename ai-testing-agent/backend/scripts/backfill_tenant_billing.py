#!/usr/bin/env python3
"""
Backfill script to create tenant_billing rows for existing tenants.

This script creates tenant_billing rows for all tenants that don't have one.
It should be run once after migrating to tenant_billing as the source of truth.

Usage:
    cd ai-testing-agent/backend
    source venv/bin/activate
    python3 scripts/backfill_tenant_billing.py
"""
import os
import sys
from dotenv import load_dotenv

# Add parent directory to path to import backend modules
script_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.dirname(script_dir)
sys.path.insert(0, backend_dir)

from db import SessionLocal
from models import Tenant
from sqlalchemy import text

# Load environment variables
try:
    load_dotenv()
except (PermissionError, OSError):
    pass


def backfill_tenant_billing():
    """
    Create tenant_billing rows for all tenants that don't have one.
    """
    db = SessionLocal()
    try:
        # Find all tenants without tenant_billing rows
        tenants_without_billing = db.execute(
            text("""
                SELECT t.id, t.name, t.slug
                FROM tenants t
                LEFT JOIN tenant_billing tb ON t.id = tb.tenant_id
                WHERE tb.tenant_id IS NULL
            """)
        ).fetchall()
        
        if not tenants_without_billing:
            print("✓ All tenants already have tenant_billing rows")
            return
        
        print(f"Found {len(tenants_without_billing)} tenants without tenant_billing rows")
        print("Creating tenant_billing rows...")
        
        from services.entitlements_centralized import create_tenant_billing_row
        
        created_count = 0
        error_count = 0
        
        for tenant_row in tenants_without_billing:
            tenant_id = str(tenant_row[0])
            tenant_name = tenant_row[1]
            tenant_slug = tenant_row[2]
            
            try:
                # Create tenant_billing row with default values
                # Default: status="incomplete" (mapped from "unselected"), plan_tier="free"
                create_tenant_billing_row(db, tenant_id, "unselected", "free")
                created_count += 1
                print(f"  ✓ Created tenant_billing for tenant: {tenant_name} ({tenant_slug})")
            except Exception as e:
                error_count += 1
                print(f"  ✗ Failed to create tenant_billing for tenant {tenant_name} ({tenant_slug}): {e}")
        
        print(f"\n✓ Backfill complete: {created_count} created, {error_count} errors")
        
    except Exception as e:
        print(f"✗ Error during backfill: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    print("Starting tenant_billing backfill...")
    backfill_tenant_billing()
    print("Done!")
