#!/usr/bin/env python3
"""
Fix user_invite_tokens table: change id from bigint to UUID.
This fixes the schema mismatch between the table and the model.
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

print("Fixing user_invite_tokens table schema...")
print("Changing id column from bigint to UUID...")

engine = create_engine(DATABASE_URL)
try:
    with engine.connect() as conn:
        # Check current id type
        result = conn.execute(text("""
            SELECT data_type 
            FROM information_schema.columns 
            WHERE table_name = 'user_invite_tokens' 
            AND column_name = 'id'
        """))
        row = result.fetchone()
        if row:
            current_type = row[0]
            print(f"  Current id type: {current_type}")
            
            if current_type == 'uuid':
                print("  ✓ Table already has UUID id - no changes needed!")
            elif current_type == 'bigint':
                print("  Converting from bigint to UUID...")
                
                # Step 1: Drop the sequence if it exists
                conn.execute(text("DROP SEQUENCE IF EXISTS user_invite_tokens_id_seq CASCADE"))
                conn.commit()
                
                # Step 2: Drop existing primary key constraint
                conn.execute(text("ALTER TABLE user_invite_tokens DROP CONSTRAINT IF EXISTS user_invite_tokens_pkey"))
                conn.commit()
                
                # Step 3: Change column type to UUID
                # First, if there's data, we need to handle it
                count_result = conn.execute(text("SELECT COUNT(*) FROM user_invite_tokens"))
                row_count = count_result.fetchone()[0]
                
                if row_count > 0:
                    print(f"  Warning: Table has {row_count} rows. Converting existing data...")
                    # For existing rows, we'll generate new UUIDs
                    # Create a temporary UUID column
                    conn.execute(text("ALTER TABLE user_invite_tokens ADD COLUMN id_new UUID"))
                    conn.commit()
                    
                    # Generate UUIDs for existing rows
                    conn.execute(text("UPDATE user_invite_tokens SET id_new = gen_random_uuid()"))
                    conn.commit()
                    
                    # Drop old id column
                    conn.execute(text("ALTER TABLE user_invite_tokens DROP COLUMN id"))
                    conn.commit()
                    
                    # Rename new column
                    conn.execute(text("ALTER TABLE user_invite_tokens RENAME COLUMN id_new TO id"))
                    conn.commit()
                else:
                    # No data, just change the type
                    conn.execute(text("ALTER TABLE user_invite_tokens ALTER COLUMN id TYPE UUID USING gen_random_uuid()"))
                    conn.commit()
                
                # Step 4: Set default
                conn.execute(text("ALTER TABLE user_invite_tokens ALTER COLUMN id SET DEFAULT gen_random_uuid()"))
                conn.commit()
                
                # Step 5: Add primary key constraint back
                conn.execute(text("ALTER TABLE user_invite_tokens ADD PRIMARY KEY (id)"))
                conn.commit()
                
                print("  ✓ Successfully converted id column to UUID!")
            else:
                print(f"  ERROR: Unexpected id type: {current_type}")
                print("  Please check the table schema manually.")
                sys.exit(1)
        else:
            print("  ERROR: Could not find id column in user_invite_tokens table")
            sys.exit(1)
            
except Exception as e:
    print(f"ERROR: Failed to fix table: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
finally:
    engine.dispose()

print("✓ Table schema fix complete!")
