"""
Internal service authentication middleware for Jira Writeback Agent.

TRUST BOUNDARY: This agent is a trusted internal executor. It does NOT enforce
subscription, plan tiers, seat caps, or trial counters. All policy enforcement
happens in the Flask app (policy authority) before requests reach this agent.

This middleware ONLY validates:
- X-Internal-Service-Key header matches INTERNAL_SERVICE_KEY env var

JWT tokens are optional and used only for logging/audit (not enforcement).
"""
import os
import logging
from fastapi import Request, HTTPException, Header
from typing import Optional

logger = logging.getLogger(__name__)

# Don't read INTERNAL_SERVICE_KEY at module import time - read it at runtime
# This ensures .env files are loaded first (by main.py) before this module is used
def get_internal_service_key() -> str:
    """Get INTERNAL_SERVICE_KEY from environment (read at runtime, not import time)."""
    return os.getenv("INTERNAL_SERVICE_KEY", "")


async def verify_internal_service_key(
    request: Request
) -> None:
    """
    Verify that request includes valid internal service key.
    
    This is the ONLY authentication enforcement in the agent.
    All policy (subscription, plan tiers, trials) is enforced by Flask app.
    
    Args:
        request: FastAPI request object
        
    Raises:
        HTTPException(401): If key is missing or invalid
    """
    # Read INTERNAL_SERVICE_KEY at runtime (not at module import time)
    internal_service_key = get_internal_service_key()
    
    if not internal_service_key:
        logger.error("INTERNAL_SERVICE_KEY not configured - rejecting request")
        raise HTTPException(
            status_code=401,
            detail="Internal service authentication not configured"
        )
    
    # Extract header value directly from request headers
    header_value = request.headers.get("X-Internal-Service-Key")
    
    if not header_value:
        logger.warning("Request missing X-Internal-Service-Key header")
        raise HTTPException(
            status_code=401,
            detail="X-Internal-Service-Key header required"
        )
    
    # Ensure header_value is a string and strip whitespace
    header_value_str = str(header_value).strip()
    
    if header_value_str != internal_service_key:
        logger.warning(f"Invalid X-Internal-Service-Key provided. Expected length: {len(internal_service_key)}, Received length: {len(header_value_str)}")
        logger.warning(f"Expected: [{internal_service_key[:20]}...], Received: [{header_value_str[:20]}...]")
        raise HTTPException(
            status_code=401,
            detail="Invalid internal service key"
        )
    
    # Extract tenant/user context for logging (optional, not for enforcement)
    tenant_id = request.headers.get("X-Tenant-ID")
    user_id = request.headers.get("X-User-ID")
    agent_name = request.headers.get("X-Agent-Name")
    
    logger.info(f"Internal service key validated (tenant={tenant_id}, user={user_id}, agent={agent_name})")


def extract_tenant_context_for_logging(request: Request) -> tuple[Optional[str], Optional[str]]:
    """
    Extract tenant_id and user_id from headers for logging/audit purposes only.
    This does NOT enforce access - it's informational only.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Tuple of (tenant_id, user_id) - both may be None
    """
    tenant_id = request.headers.get("X-Tenant-ID")
    user_id = request.headers.get("X-User-ID")
    return tenant_id, user_id
