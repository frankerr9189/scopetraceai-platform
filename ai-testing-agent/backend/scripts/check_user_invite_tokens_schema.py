#!/usr/bin/env python3
"""
Check the schema of user_invite_tokens table to see if created_at has proper defaults.
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

print("Checking user_invite_tokens table schema...\n")

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
            WHERE table_name = 'user_invite_tokens' 
            AND column_name = 'created_at'
        """))
        row = result.fetchone()
        if row:
            print(f"Column: {row[0]}")
            print(f"Type: {row[1]}")
            print(f"Nullable: {row[2]}")
            print(f"Default: {row[3] or '(none)'}")
            
            if not row[3]:
                print("\n⚠️  WARNING: created_at has no server_default!")
                print("   This means records inserted without explicit created_at will be NULL.")
        else:
            print("ERROR: created_at column not found")
        
        # Check for any NULL created_at values
        print("\nChecking for NULL created_at values...")
        null_check = conn.execute(text("SELECT COUNT(*) FROM user_invite_tokens WHERE created_at IS NULL"))
        null_count = null_check.fetchone()[0]
        if null_count > 0:
            print(f"⚠️  Found {null_count} records with NULL created_at")
        else:
            print("✓ No NULL created_at values found")
            
        # Show sample records
        print("\nSample records:")
        samples = conn.execute(text("SELECT id, created_at, expires_at FROM user_invite_tokens ORDER BY created_at DESC NULLS LAST LIMIT 5"))
        for sample in samples:
            print(f"  ID: {sample[0]}, created_at: {sample[1]}, expires_at: {sample[2]}")
            
except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
finally:
    engine.dispose()
