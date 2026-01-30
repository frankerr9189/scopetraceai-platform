"""
FastAPI entry point for AI Senior Business Requirement Analyst.
"""
import os
import logging
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# CRITICAL: Load environment variables BEFORE importing any db/session/models
# ============================================================================
# Module-level guard to prevent multiple executions
_env_loaded = False

if not _env_loaded:
    # CRITICAL: Load testing agent backend .env FIRST (contains DATABASE_URL and JWT_SECRET)
    # This must happen BEFORE any imports that use db/session
    # We ONLY use DATABASE_URL from the testing agent's .env, not from local .env
    current_file = os.path.abspath(__file__)
    # Go up: app/main.py -> app -> ai-sr-business-req-analyst -> appscopetraceai -> ai-testing-agent/backend
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
    backend_path = os.path.join(project_root, "ai-testing-agent", "backend")
    testing_env = os.path.join(backend_path, ".env")
    
    if os.path.exists(testing_env):
        load_dotenv(testing_env, override=True)
        logger.info("Loaded DATABASE_URL and JWT_SECRET from testing agent backend .env")
    else:
        logger.error(f"Testing agent .env not found at {testing_env} - DATABASE_URL and JWT_SECRET will not be available!")
    
    # Load local .env file AFTER (for other BA agent-specific config like OPENAI_API_KEY, DB_SCHEMA)
    # Use absolute path so it loads regardless of cwd (e.g. when running from ai-sr-business-req-analyst)
    _ba_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env_path = os.path.join(_ba_root, '.env')
    try:
        # Save DATABASE_URL, JWT_SECRET, and INTERNAL_SERVICE_KEY before loading local .env
        saved_db_url = os.getenv("DATABASE_URL")
        saved_jwt_secret = os.getenv("JWT_SECRET")
        saved_internal_service_key = os.getenv("INTERNAL_SERVICE_KEY")
        
        # Load local .env (may override other vars, but we'll restore DATABASE_URL, JWT_SECRET, and INTERNAL_SERVICE_KEY)
        load_dotenv(env_path, override=True)
        
        # Restore DATABASE_URL, JWT_SECRET, and INTERNAL_SERVICE_KEY from testing agent (they must come from testing agent only)
        if saved_db_url:
            os.environ["DATABASE_URL"] = saved_db_url
        if saved_jwt_secret:
            os.environ["JWT_SECRET"] = saved_jwt_secret
        if saved_internal_service_key:
            os.environ["INTERNAL_SERVICE_KEY"] = saved_internal_service_key
        
        # Prefer DB_SCHEMA from local .env (so local runs can use test schema)
        _local_schema = os.getenv("DB_SCHEMA", "").strip().lower()
        if _local_schema in ("public", "test"):
            os.environ["DB_SCHEMA"] = _local_schema
            
        logger.info("Loaded local .env (DATABASE_URL and JWT_SECRET preserved from testing agent)")
    except (PermissionError, OSError):
        # If .env file can't be read due to permissions, continue without it
        logger.warning("Could not load local .env file")
        pass
    
    # Log DB_SCHEMA and DATABASE_URL type (no secrets)
    logger.info("DB_SCHEMA=%s (from env after loading .env)", os.getenv("DB_SCHEMA", "(unset)") or "public")
    db_url = os.getenv("DATABASE_URL", "")
    if db_url:
        if db_url.startswith("postgresql://") or db_url.startswith("postgres://"):
            logger.info("DATABASE_URL: postgresql (PostgreSQL)")
        elif db_url.startswith("sqlite://"):
            logger.info("DATABASE_URL: sqlite (SQLite)")
        else:
            logger.info("DATABASE_URL: unknown type")
    else:
        logger.warning("DATABASE_URL: not set")
    
    _env_loaded = True

# Now safe to import modules that may use db/session
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from app.api import analyze, overrides, scope_status
from app.db import verify_db_schema_sentinel, get_db_schema


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: when DB_SCHEMA=test, verify test.env_sentinel (fail fast)."""
    if os.getenv("DB_SCHEMA", "").strip().lower() == "test":
        try:
            verify_db_schema_sentinel()
        except Exception as e:
            logger.error("DB schema sentinel check failed at startup: %s", e)
            raise
    yield
    # shutdown: nothing to do
    pass


app = FastAPI(
    title="AI Senior Business Requirement Analyst",
    description="An AI agent that acts as a Senior Business Requirement Analyst",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS configuration with explicit allowlist
# Base allowed origins for local development
ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://localhost:5137",
    "http://localhost:3000",  # Marketing site (Next.js) local development
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5137",
    "http://127.0.0.1:3000",  # Marketing site alternative localhost
    # Production frontend domains
    "https://app.scopetraceai.com",
    "https://scopetraceai-platform.vercel.app",
    "https://scopetraceai-platform.onrender.com",  # Render deployment
    # Marketing site domains
    "https://scopetraceai.com",
    "https://www.scopetraceai.com",
]

# Add additional production domains from environment variable if set
# Supports comma-separated list of origins (e.g., "https://staging.example.com,https://dev.example.com")
production_origins = os.getenv("CORS_ALLOWED_ORIGINS", "").strip()
if production_origins:
    # Split by comma and add to allowed origins
    for origin in production_origins.split(","):
        origin = origin.strip()
        if origin and origin not in ALLOWED_ORIGINS:
            ALLOWED_ORIGINS.append(origin)

# Add CORS middleware - must be added before exception handlers
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Global exception handler to ensure CORS headers are included in error responses.
    """
    from fastapi import HTTPException
    
    # Get origin from request, validate against allowed origins
    origin = request.headers.get("Origin", "")
    allowed_origin = origin if origin in ALLOWED_ORIGINS else ALLOWED_ORIGINS[0] if ALLOWED_ORIGINS else "http://localhost:5173"
    
    if isinstance(exc, HTTPException):
        # For HTTPExceptions, include CORS headers
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers={
                "Access-Control-Allow-Origin": allowed_origin,
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Methods": "*",
                "Access-Control-Allow-Headers": "*",
            }
        )
    else:
        # For other exceptions, return 500 with CORS headers
        return JSONResponse(
            status_code=500,
            content={"detail": f"Internal server error: {str(exc)}"},
            headers={
                "Access-Control-Allow-Origin": allowed_origin,
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Methods": "*",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Validation exception handler with CORS headers.
    """
    # Get origin from request, validate against allowed origins
    origin = request.headers.get("Origin", "")
    allowed_origin = origin if origin in ALLOWED_ORIGINS else ALLOWED_ORIGINS[0] if ALLOWED_ORIGINS else "http://localhost:5173"
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors(), "body": exc.body},
        headers={
            "Access-Control-Allow-Origin": allowed_origin,
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "*",
            "Access-Control-Allow-Headers": "*",
        }
    )

# Include routers
app.include_router(analyze.router, prefix="/api/v1", tags=["Analysis"])
app.include_router(overrides.router, prefix="/api/v1", tags=["Overrides"])
app.include_router(scope_status.router, prefix="/api/v1", tags=["Scope Status"])


@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "AI Senior Business Requirement Analyst API"}


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/health/db")
async def health_db():
    """DB health: current_schema and search_path (for test env debugging)."""
    from app.db import engine
    from sqlalchemy import text
    with engine.connect() as conn:
        row = conn.execute(text("SELECT current_schema(), current_setting('search_path')")).fetchone()
    return {
        "status": "healthy",
        "DB_SCHEMA_env": get_db_schema(),
        "current_schema": row[0] if row else None,
        "search_path": row[1] if row else None,
    }

