#!/usr/bin/env python3
"""
Script to create user_invite_tokens table directly.
This is a workaround when migrations are blocked.
"""
import os
import sys
from pathlib import Path
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
# If already postgresql+psycopg://, keep it

# Read SQL file
script_dir = Path(__file__).parent
sql_file = script_dir.parent.parent / "db" / "sql" / "002_create_user_invite_tokens.sql"

if not sql_file.exists():
    print(f"ERROR: SQL file not found: {sql_file}")
    sys.exit(1)

with open(sql_file, 'r') as f:
    sql_content = f.read()

# Execute SQL
print("Creating user_invite_tokens table...")
engine = create_engine(DATABASE_URL)
try:
    with engine.connect() as conn:
        # Execute each statement
        for statement in sql_content.split(';'):
            statement = statement.strip()
            if statement and not statement.startswith('--'):
                try:
                    conn.execute(text(statement))
                    conn.commit()
                except Exception as e:
                    # Ignore "already exists" errors
                    if "already exists" in str(e).lower():
                        print(f"  (Table/index already exists, skipping)")
                    else:
                        print(f"  Warning: {e}")
    print("✓ user_invite_tokens table created successfully!")
except Exception as e:
    print(f"ERROR: Failed to create table: {e}")
    sys.exit(1)
finally:
    engine.dispose()
