"""
FastAPI entry point for Jira Write-Back Agent.
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
    project_root = os.path.dirname(os.path.dirname(current_file))
    backend_path = os.path.join(project_root, "ai-testing-agent", "backend")
    testing_env = os.path.join(backend_path, ".env")
    
    if os.path.exists(testing_env):
        load_dotenv(testing_env, override=True)
        logger.info("Loaded DATABASE_URL and JWT_SECRET from testing agent backend .env")
    else:
        logger.error(f"Testing agent .env not found at {testing_env} - DATABASE_URL and JWT_SECRET will not be available!")
    
    # Load local .env file AFTER (for other jira-writeback-agent-specific config)
    # But DATABASE_URL and JWT_SECRET are already set from testing agent's .env above
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    try:
        # Save DATABASE_URL and JWT_SECRET before loading local .env
        saved_db_url = os.getenv("DATABASE_URL")
        saved_jwt_secret = os.getenv("JWT_SECRET")
        
        # Load local .env (may override other vars, but we'll restore DATABASE_URL and JWT_SECRET)
        load_dotenv(env_path, override=True)
        
        # Restore DATABASE_URL and JWT_SECRET from testing agent (they must come from testing agent only)
        if saved_db_url:
            os.environ["DATABASE_URL"] = saved_db_url
        if saved_jwt_secret:
            os.environ["JWT_SECRET"] = saved_jwt_secret
            
        logger.info("Loaded local .env (DATABASE_URL and JWT_SECRET preserved from testing agent)")
    except (PermissionError, OSError):
        # If .env file can't be read due to permissions, continue without it
        logger.warning("Could not load local .env file")
        pass
    
    # Log DATABASE_URL type (no secrets, just type)
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
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.rewrite import router as rewrite_router

app = FastAPI(
    title="Jira Write-Back Agent",
    description="Deterministic Jira write-back operations for approved, scope-locked outputs",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5137", "http://localhost:3000", "http://127.0.0.1:5173", "http://127.0.0.1:5137"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Include routers
app.include_router(rewrite_router)


@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "Jira Write-Back Agent API"}


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001, reload=True)
