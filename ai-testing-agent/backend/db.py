"""
SQLAlchemy database setup and session management.
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from dotenv import load_dotenv

# Load environment variables
# Load from current directory explicitly to ensure it's found
try:
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    load_dotenv(env_path, override=True)
    # Also try loading from current working directory as fallback
    load_dotenv(override=False)
except (PermissionError, OSError):
    pass

# Get database URL from environment - REQUIRED for Postgres
DATABASE_URL = os.getenv("DATABASE_URL")

# Validate DATABASE_URL is present
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL environment variable is required. "
        "Please set DATABASE_URL to a PostgreSQL connection string."
    )

# Validate DATABASE_URL is a PostgreSQL URL
if not (DATABASE_URL.startswith("postgresql://") or 
        DATABASE_URL.startswith("postgres://") or 
        DATABASE_URL.startswith("postgresql+psycopg://")):
    raise RuntimeError(
        f"DATABASE_URL must be a PostgreSQL connection string (postgresql:// or postgres://). "
        f"Got: {DATABASE_URL[:50]}..."
    )

# Normalize PostgreSQL URL format for robust handling
# 1. Convert postgres:// to postgresql:// (Supabase and some providers use postgres://)
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# 2. Handle postgresql+psycopg:// format (SQLAlchemy dialect format)
#    SQLAlchemy can use postgresql+psycopg://, but direct psycopg.connect() cannot
#    We keep the SQLAlchemy format for the engine, and create a psycopg-compatible DSN
SQLALCHEMY_DATABASE_URL = DATABASE_URL
PSYCOPG_DSN = DATABASE_URL

if DATABASE_URL.startswith("postgresql+psycopg://"):
    # SQLAlchemy URL: keep the +psycopg dialect specifier
    SQLALCHEMY_DATABASE_URL = DATABASE_URL
    # psycopg DSN: remove the +psycopg part for direct psycopg connections
    PSYCOPG_DSN = DATABASE_URL.replace("postgresql+psycopg://", "postgresql://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    # For standard postgresql:// URLs, we need to use postgresql+psycopg:// for SQLAlchemy
    # to ensure it uses psycopg3 (psycopg) instead of defaulting to psycopg2
    # SQLAlchemy URL: add +psycopg dialect specifier to use psycopg3
    SQLALCHEMY_DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)
    # psycopg DSN: keep standard postgresql:// for direct psycopg connections
    PSYCOPG_DSN = DATABASE_URL

# Create engine using SQLAlchemy-compatible URL (may include +psycopg)
# PostgreSQL only - no SQLite fallback
engine = create_engine(SQLALCHEMY_DATABASE_URL, echo=False)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()

# Expose engine and Base for Flask-Migrate
# Flask-Migrate will use these to manage migrations
# PSYCOPG_DSN is available for any direct psycopg connections (without +psycopg dialect)
__all__ = ['engine', 'Base', 'SessionLocal', 'get_db', 'init_db', 'DATABASE_URL', 'SQLALCHEMY_DATABASE_URL', 'PSYCOPG_DSN']


def get_db() -> Session:
    """
    Generator function to get database session.
    
    Usage in Flask routes:
        db = next(get_db())
        try:
            # use db
        finally:
            db.close()
    
    Yields:
        Session: SQLAlchemy database session
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """
    Initialize database connection and optionally create tables.
    
    NOTE: Alembic migrations are now the single source of truth for schema creation.
    This function will only create tables if DB_CREATE_ALL=true is explicitly set.
    For production and normal operation, use 'flask db upgrade' to apply migrations.
    
    PostgreSQL only - no SQLite fallback.
    """
    # Import models to ensure they're registered with Base
    from models import Run, Artifact, Tenant, TenantUser  # noqa: F401
    
    # Alembic migrations now own schema creation - only create tables if explicitly enabled
    # This is gated behind DB_CREATE_ALL=true for local development convenience only
    if os.getenv("DB_CREATE_ALL", "").lower() == "true":
        Base.metadata.create_all(bind=engine)
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(
            "DB_CREATE_ALL=true: Tables created via create_all(). "
            "This should only be used for local development. "
            "Use 'flask db upgrade' for production schema management."
        )


