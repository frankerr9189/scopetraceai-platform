#!/usr/bin/env python3
"""
Safe local development database reset script.

This script fully resets the database schema and reapplies Alembic migrations.
It is ONLY allowed to run in development environments against localhost databases.

SAFETY CONSTRAINTS:
- Requires ENVIRONMENT=development
- Requires DATABASE_URL host to be localhost or 127.0.0.1
- Refuses to run against remote databases (e.g., Supabase)

Usage:
    cd ai-testing-agent/backend
    source venv/bin/activate
    python3 scripts/reset_local_db.py
"""
import os
import sys
from urllib.parse import urlparse
from sqlalchemy import create_engine, text
from alembic.config import Config
from alembic import command
from dotenv import load_dotenv

# Load environment variables
try:
    load_dotenv()
except (PermissionError, OSError):
    pass


def parse_database_url(url: str) -> dict:
    """
    Parse DATABASE_URL and extract components.
    
    Returns:
        dict with keys: scheme, host, port, database, username, password
    """
    # Handle postgresql+psycopg:// format by removing the +psycopg part for parsing
    parse_url = url.replace("postgresql+psycopg://", "postgresql://", 1)
    
    parsed = urlparse(parse_url)
    
    return {
        'scheme': parsed.scheme,
        'host': parsed.hostname,
        'port': parsed.port or 5432,
        'database': parsed.path.lstrip('/').split('?')[0],  # Remove query params
        'username': parsed.username,
        'password': parsed.password,
    }


def validate_safety_constraints():
    """
    Validate that all safety constraints are met.
    
    Raises:
        SystemExit: If any safety constraint is violated
    """
    # Check ENVIRONMENT=development
    environment = os.getenv("ENVIRONMENT", "").lower()
    if environment != "development":
        print("ERROR: This script can only run in development environment.")
        print(f"Current ENVIRONMENT: {environment or '(not set)'}")
        print("Set ENVIRONMENT=development to proceed.")
        sys.exit(1)
    
    # Check DATABASE_URL is set
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        print("ERROR: DATABASE_URL environment variable is required.")
        sys.exit(1)
    
    # Parse and validate host
    try:
        db_info = parse_database_url(database_url)
        host = db_info['host']
    except Exception as e:
        print(f"ERROR: Failed to parse DATABASE_URL: {e}")
        sys.exit(1)
    
    # Check host is localhost or 127.0.0.1
    allowed_hosts = ['localhost', '127.0.0.1', '::1']
    if host not in allowed_hosts:
        print("ERROR: This script can only run against localhost databases.")
        print(f"Detected host: {host}")
        print("Allowed hosts: localhost, 127.0.0.1, ::1")
        print("This script will NOT run against remote databases (e.g., Supabase).")
        sys.exit(1)
    
    print(f"✓ Safety checks passed:")
    print(f"  - ENVIRONMENT: {environment}")
    print(f"  - Database host: {host}")
    print(f"  - Database: {db_info['database']}")


def reset_database_schema(database_url: str):
    """
    Drop and recreate the public schema.
    
    Args:
        database_url: PostgreSQL connection string
    """
    print("\nResetting database schema...")
    
    # Normalize URL for SQLAlchemy (handle postgresql+psycopg://)
    sqlalchemy_url = database_url
    if database_url.startswith("postgresql+psycopg://"):
        # Keep the +psycopg for SQLAlchemy
        pass
    elif database_url.startswith("postgres://"):
        sqlalchemy_url = database_url.replace("postgres://", "postgresql://", 1)
    
    # Create engine
    engine = create_engine(sqlalchemy_url, isolation_level="AUTOCOMMIT")
    
    try:
        with engine.connect() as conn:
            print("  - Dropping public schema...")
            conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            
            print("  - Creating public schema...")
            conn.execute(text("CREATE SCHEMA public"))
            
            print("  - Granting permissions...")
            conn.execute(text("GRANT ALL ON SCHEMA public TO postgres"))
            conn.execute(text("GRANT ALL ON SCHEMA public TO public"))
        
        print("✓ Schema reset complete")
    except Exception as e:
        print(f"ERROR: Failed to reset schema: {e}")
        sys.exit(1)
    finally:
        engine.dispose()


def run_alembic_upgrade(database_url: str):
    """
    Run Alembic migrations to upgrade database to head.
    
    Args:
        database_url: PostgreSQL connection string
    """
    print("\nRunning Alembic migrations...")
    
    # Get the migrations directory path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir = os.path.dirname(script_dir)
    migrations_dir = os.path.join(backend_dir, "migrations")
    
    if not os.path.exists(migrations_dir):
        print(f"ERROR: Migrations directory not found: {migrations_dir}")
        sys.exit(1)
    
    # Normalize URL for Alembic (remove +psycopg dialect)
    alembic_url = database_url
    if alembic_url.startswith("postgresql+psycopg://"):
        alembic_url = alembic_url.replace("postgresql+psycopg://", "postgresql://", 1)
    elif alembic_url.startswith("postgres://"):
        alembic_url = alembic_url.replace("postgres://", "postgresql://", 1)
    
    # Configure Alembic
    alembic_cfg = Config(os.path.join(migrations_dir, "alembic.ini"))
    alembic_cfg.set_main_option("script_location", migrations_dir)
    alembic_cfg.set_main_option("sqlalchemy.url", alembic_url)
    
    try:
        # Run upgrade to head
        command.upgrade(alembic_cfg, "head")
        print("✓ Migrations applied successfully")
    except Exception as e:
        print(f"ERROR: Failed to run migrations: {e}")
        sys.exit(1)


def main():
    """Main entry point for the reset script."""
    print("=" * 60)
    print("Local Development Database Reset Script")
    print("=" * 60)
    print()
    
    # Validate safety constraints
    validate_safety_constraints()
    
    # Get DATABASE_URL
    database_url = os.getenv("DATABASE_URL")
    
    # Confirm with user
    print("\n⚠️  WARNING: This will DROP ALL DATA in the database!")
    print("This action cannot be undone.")
    response = input("\nType 'RESET' to confirm: ")
    
    if response != "RESET":
        print("Reset cancelled.")
        sys.exit(0)
    
    # Reset schema
    reset_database_schema(database_url)
    
    # Run migrations
    run_alembic_upgrade(database_url)
    
    print("\n" + "=" * 60)
    print("✓ Database reset complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
