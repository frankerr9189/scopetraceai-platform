"""
SQLAlchemy database setup and session management.
"""
import os
import logging
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Load .env BEFORE any use of DB_SCHEMA or DATABASE_URL so connection-time and
# request-time reads see the correct values (avoids import-order freeze).
_env_path_loaded = os.path.join(os.path.dirname(__file__), '.env')
try:
    load_dotenv(_env_path_loaded, override=True)
    load_dotenv(override=False)
except (PermissionError, OSError) as e:
    logger.warning("db.py: could not load .env from %s: %s", _env_path_loaded, e)


def get_db_schema() -> str:
    """
    Read DB_SCHEMA from environment at connection/request time (avoids import-order freeze).
    This is the single source of truth for schema; connect/begin listeners call it at runtime
    so webhook and API requests use the same schema (test vs public) as the process env.
    """
    # Try exact key first; some .env parsers allow "DB_SCHEMA " with trailing space
    v = os.getenv("DB_SCHEMA") or os.environ.get("DB_SCHEMA ") or "public"
    v = (v or "public").strip().lower()
    return v if v in ("public", "test") else "public"


# Log resolved schema at import (for verification; runtime uses get_db_schema() above)
logger.warning("db.py: DB_SCHEMA (get_db_schema)=%r", get_db_schema())


def get_db_schema_debug() -> dict:
    """Return diagnostic dict for health/debug: raw env and resolved schema."""
    raw = os.getenv("DB_SCHEMA")
    raw_alt = os.environ.get("DB_SCHEMA ")
    keys_with_db_schema = [k for k in os.environ if "DB_SCHEMA" in k.upper()]
    resolved = get_db_schema()
    return {
        "get_db_schema": resolved,
        "os_getenv_DB_SCHEMA": raw,
        "os_environ_DB_SCHEMA_space": raw_alt,
        "env_keys_containing_DB_SCHEMA": keys_with_db_schema,
    }

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
# Connection pool configuration to prevent pool exhaustion:
# - pool_size: Number of connections to maintain in the pool (default 5)
# - max_overflow: Additional connections beyond pool_size (default 10)
# - pool_pre_ping: Test connections before using (handles stale connections)
# - pool_recycle: Recycle connections after 3600 seconds (1 hour) to prevent stale connections
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    echo=False,
    pool_size=5,  # Base pool size
    max_overflow=10,  # Additional connections beyond pool_size
    pool_pre_ping=True,  # Test connections before using (handles stale connections)
    pool_recycle=3600,  # Recycle connections after 1 hour
    connect_args={
        "connect_timeout": 10,  # Connection timeout in seconds
    }
)


@event.listens_for(engine, "connect")
def _set_search_path_connect(dbapi_connection, connection_record):
    """Set search_path on every new connection (pool-safe)."""
    cursor = dbapi_connection.cursor()
    try:
        schema = get_db_schema()
        if schema == "test":
            cursor.execute("SET search_path TO test, public")
        else:
            cursor.execute("SET search_path TO public")
    finally:
        cursor.close()


# Run SET search_path at the start of every transaction (required for transaction pooler;
# harmless for direct/session mode).
@event.listens_for(engine, "begin")
def _set_search_path_begin(conn):
    """Set search_path at start of each transaction so it works with Supabase transaction pooler."""
    schema = get_db_schema()
    if schema == "test":
        conn.execute(text("SET search_path TO test, public"))
    else:
        conn.execute(text("SET search_path TO public"))


# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def verify_db_schema_sentinel():
    """
    When DB_SCHEMA=test, verify test.env_sentinel so TEST env fails fast if misconfigured.
    When DB_SCHEMA=public, skip. Raises RuntimeError if test schema sentinel check fails.
    """
    if get_db_schema() != "test":
        return
    db = SessionLocal()
    try:
        r = db.execute(text("SELECT env FROM test.env_sentinel WHERE id = 1")).fetchone()
        if not r or (r[0] or "").strip().lower() != "test":
            raise RuntimeError(
                "DB_SCHEMA=test but test.env_sentinel check failed: "
                "expected env='test' from test.env_sentinel where id=1. "
                "Ensure the test schema and env_sentinel table exist and are populated."
            )
        logger.info("DB schema sentinel verified: test.env_sentinel.env = test")
    finally:
        db.close()

# Base class for models
Base = declarative_base()

# Expose engine and Base for Flask-Migrate
# Flask-Migrate will use these to manage migrations
# PSYCOPG_DSN is available for any direct psycopg connections (without +psycopg dialect)
__all__ = ['engine', 'Base', 'SessionLocal', 'get_db', 'init_db', 'DATABASE_URL', 'SQLALCHEMY_DATABASE_URL', 'PSYCOPG_DSN', 'get_db_schema', 'get_db_schema_debug', 'verify_db_schema_sentinel']


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


