#!/usr/bin/env python3
"""
Check tenant_users table for any invalid or NULL created_at dates.
"""
import os
import sys
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

# Load environment variables
try:
    env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
    load_dotenv(env_path, override=True)
    load_dotenv(override=False)
except (PermissionError, OSError):
    pass

# Get database URL
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    print("ERROR: DATABASE_URL environment variable is required.")
    sys.exit(1)

# Normalize URL for SQLAlchemy (use psycopg3)
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

print("Checking tenant_users table for date issues...\n")

engine = create_engine(DATABASE_URL)
try:
    with engine.connect() as conn:
        # Check created_at column definition
        result = conn.execute(text("""
            SELECT 
                column_name,
                data_type,
                is_nullable,
                column_default
            FROM information_schema.columns 
            WHERE table_name = 'tenant_users' 
            AND column_name = 'created_at'
        """))
        row = result.fetchone()
        if row:
            print(f"Column: {row[0]}")
            print(f"Type: {row[1]}")
            print(f"Nullable: {row[2]}")
            print(f"Default: {row[3] or '(none)'}\n")
        
        # Check for NULL created_at values
        null_check = conn.execute(text("SELECT COUNT(*) FROM tenant_users WHERE created_at IS NULL"))
        null_count = null_check.fetchone()[0]
        if null_count > 0:
            print(f"⚠️  Found {null_count} records with NULL created_at")
            # Show them
            null_records = conn.execute(text("SELECT id, email, created_at FROM tenant_users WHERE created_at IS NULL LIMIT 10"))
            for record in null_records:
                print(f"  - {record[1]} (id: {record[0]})")
        else:
            print("✓ No NULL created_at values found")
        
        # Check for invalid dates (dates that are too old or in the future)
        print("\nChecking for potentially invalid dates...")
        invalid_check = conn.execute(text("""
            SELECT COUNT(*) FROM tenant_users 
            WHERE created_at < '2000-01-01'::timestamp 
            OR created_at > '2100-01-01'::timestamp
        """))
        invalid_count = invalid_check.fetchone()[0]
        if invalid_count > 0:
            print(f"⚠️  Found {invalid_count} records with dates outside reasonable range")
        else:
            print("✓ All dates are within reasonable range")
        
        # Show sample records with their created_at values
        print("\nSample records (most recent first):")
        samples = conn.execute(text("""
            SELECT id, email, created_at, is_active 
            FROM tenant_users 
            ORDER BY created_at DESC NULLS LAST 
            LIMIT 10
        """))
        for sample in samples:
            created_str = str(sample[2]) if sample[2] else "NULL"
            print(f"  Email: {sample[1]}")
            print(f"    ID: {sample[0]}")
            print(f"    Created: {created_str}")
            print(f"    Active: {sample[3]}")
            print()
            
except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
finally:
    engine.dispose()
