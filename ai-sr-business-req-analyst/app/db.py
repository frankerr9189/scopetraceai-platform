"""
SQLAlchemy database setup and session management for BA Agent.
"""
import os
import logging
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, Session

logger = logging.getLogger(__name__)


def get_db_schema() -> str:
    """Read DB_SCHEMA from environment at runtime (avoids import-order issues with .env loading)."""
    v = os.getenv("DB_SCHEMA") or os.environ.get("DB_SCHEMA ") or "public"
    v = (v or "public").strip().lower()
    return v if v in ("public", "test") else "public"


# Expose for health/debug; code should use get_db_schema() so schema is read after .env is loaded
DB_SCHEMA = get_db_schema()

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

# Normalize PostgreSQL URL format
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

SQLALCHEMY_DATABASE_URL = DATABASE_URL
if DATABASE_URL.startswith("postgresql+psycopg://"):
    SQLALCHEMY_DATABASE_URL = DATABASE_URL
elif DATABASE_URL.startswith("postgresql://"):
    SQLALCHEMY_DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

# Create engine with connection pooling
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    echo=False,
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,
    pool_recycle=3600,
    connect_args={
        "connect_timeout": 10,
    }
)


@event.listens_for(engine, "connect")
def _set_search_path_connect(dbapi_connection, connection_record):
    """Set search_path on every new connection (pool-safe)."""
    schema = get_db_schema()
    cursor = dbapi_connection.cursor()
    try:
        if schema == "test":
            cursor.execute("SET search_path TO test, public")
        else:
            cursor.execute("SET search_path TO public")
    finally:
        cursor.close()


@event.listens_for(engine, "begin")
def _set_search_path_begin(conn):
    """Set search_path at start of each transaction (works with Supabase transaction pooler)."""
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


def get_db() -> Session:
    """
    Generator function to get database session.
    
    Usage:
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
