"""
SQLAlchemy database setup and session management for BA Agent.
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

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

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


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
