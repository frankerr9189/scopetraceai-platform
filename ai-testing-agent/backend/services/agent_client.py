"""
HTTP client wrapper for calling agent services with internal authentication.

TRUST BOUNDARY: Flask app is the policy authority. Agent services are trusted
internal executors that only validate the internal service key.

This module handles:
- Injecting X-Internal-Service-Key header
- Injecting tenant context (tenant_id, user_id, agent name)
- Error handling and retries
- Request/response logging
"""
import os
import logging
import requests
from typing import Dict, Any, Optional
from flask import g

logger = logging.getLogger(__name__)

# Agent service base URLs (from environment or defaults)
BA_AGENT_BASE_URL = os.getenv("BA_AGENT_BASE_URL", "http://localhost:8000")
JIRA_WRITEBACK_AGENT_BASE_URL = os.getenv("JIRA_WRITEBACK_AGENT_BASE_URL", "http://localhost:8001")

# Internal service key for agent authentication
INTERNAL_SERVICE_KEY = os.getenv("INTERNAL_SERVICE_KEY", "")
if not INTERNAL_SERVICE_KEY:
    logger.warning("INTERNAL_SERVICE_KEY not set - agent calls will fail authentication")


def get_internal_headers(tenant_id: Optional[str] = None, user_id: Optional[str] = None, agent: Optional[str] = None, actor: Optional[str] = None) -> Dict[str, str]:
    """
    Build headers for internal agent service calls.
    
    Includes:
    - X-Internal-Service-Key: Required by agents for authentication
    - X-Tenant-ID: Tenant context (for logging/audit)
    - X-User-ID: User context (for logging/audit)
    - X-Agent-Name: Agent identifier (for logging/audit)
    - X-Actor: Display name for run attribution (created_by in runs table)
    
    Args:
        tenant_id: Tenant UUID string (from flask.g if not provided)
        user_id: User UUID string (from flask.g if not provided)
        agent: Agent name (e.g., 'requirements_ba', 'jira_writeback')
        actor: Display name for "Created By" (from client X-Actor or derived)
        
    Returns:
        Dictionary of headers
    """
    headers = {
        "Content-Type": "application/json",
        "X-Internal-Service-Key": INTERNAL_SERVICE_KEY
    }
    
    # Extract from flask.g if available
    if not tenant_id and hasattr(g, 'tenant_id'):
        tenant_id = str(g.tenant_id)
    if not user_id and hasattr(g, 'user_id'):
        user_id = str(g.user_id)
    
    if tenant_id:
        headers["X-Tenant-ID"] = tenant_id
    if user_id:
        headers["X-User-ID"] = user_id
    if agent:
        headers["X-Agent-Name"] = agent
    if actor:
        headers["X-Actor"] = actor
    
    return headers


def call_ba_agent(endpoint: str, payload: Dict[str, Any], tenant_id: Optional[str] = None, user_id: Optional[str] = None, actor: Optional[str] = None) -> Dict[str, Any]:
    """
    Call BA Requirements Agent service.
    
    Args:
        endpoint: API endpoint (e.g., '/api/v1/analyze')
        payload: Request payload
        tenant_id: Tenant UUID (optional, uses flask.g if not provided)
        user_id: User UUID (optional, uses flask.g if not provided)
        actor: Display name for run attribution (forwarded as X-Actor to BA agent)
        
    Returns:
        Response JSON as dictionary
        
    Raises:
        requests.RequestException: If HTTP request fails
        ValueError: If response indicates error
    """
    url = f"{BA_AGENT_BASE_URL}{endpoint}"
    headers = get_internal_headers(tenant_id=tenant_id, user_id=user_id, agent="requirements_ba", actor=actor)
    
    logger.info(f"Calling BA agent: {endpoint} (tenant={tenant_id})")
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=300)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        # Try to extract error details from response body
        error_detail = str(e)
        try:
            if e.response is not None:
                error_body = e.response.json()
                if isinstance(error_body, dict) and "detail" in error_body:
                    error_detail = error_body["detail"]
                elif isinstance(error_body, dict) and "error" in error_body:
                    error_detail = error_body["error"]
                else:
                    error_detail = str(error_body)
        except (ValueError, AttributeError):
            # If response body is not JSON, use text or default message
            try:
                if e.response is not None:
                    error_detail = e.response.text[:500]  # Limit length
            except:
                pass
        
        logger.error(f"BA agent HTTP error: {endpoint} - Status {e.response.status_code if e.response else 'unknown'}: {error_detail}")
        # Create a more informative exception
        raise requests.exceptions.HTTPError(
            f"500 Server Error: Internal Server Error for url: {url}. BA Agent returned: {error_detail}",
            response=e.response
        ) from e
    except requests.exceptions.RequestException as e:
        logger.error(f"BA agent call failed: {endpoint} - {str(e)}")
        raise


def call_jira_writeback_agent(endpoint: str, payload: Dict[str, Any], tenant_id: Optional[str] = None, user_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Call Jira Writeback Agent service.
    
    Args:
        endpoint: API endpoint (e.g., '/api/v1/jira/rewrite/execute')
        payload: Request payload
        tenant_id: Tenant UUID (optional, uses flask.g if not provided)
        user_id: User UUID (optional, uses flask.g if not provided)
        
    Returns:
        Response JSON as dictionary
        
    Raises:
        requests.RequestException: If HTTP request fails
        ValueError: If response indicates error
    """
    url = f"{JIRA_WRITEBACK_AGENT_BASE_URL}{endpoint}"
    headers = get_internal_headers(tenant_id=tenant_id, user_id=user_id, agent="jira_writeback")
    
    logger.info(f"Calling Jira writeback agent: {endpoint} (tenant={tenant_id})")
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=300)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        # Try to extract error details from response body
        error_detail = str(e)
        error_type = None
        try:
            if e.response is not None:
                error_body = e.response.json()
                if isinstance(error_body, dict):
                    # Extract detailed error information if available
                    if "error_detail" in error_body:
                        error_detail = error_body["error_detail"]
                    elif "detail" in error_body:
                        error_detail = error_body["detail"]
                    elif "error" in error_body:
                        error_detail = error_body["error"]
                    elif "message" in error_body:
                        error_detail = error_body["message"]
                    
                    if "error_type" in error_body:
                        error_type = error_body["error_type"]
        except (ValueError, AttributeError):
            # If response body is not JSON, use text or default message
            try:
                if e.response is not None:
                    error_detail = e.response.text[:500]  # Limit length
            except:
                pass
        
        status_code = e.response.status_code if e.response else 'unknown'
        logger.error(f"Jira writeback agent HTTP error: {endpoint} - Status {status_code}: {error_detail}")
        
        # Create a more informative exception with error details
        error_msg = f"{status_code} Server Error: Service Unavailable for url: {url}"
        if error_type:
            error_msg += f". Error type: {error_type}"
        if error_detail and error_detail != str(e):
            error_msg += f". {error_detail}"
        else:
            error_msg += f". Jira Writeback Agent returned: {error_detail}"
        
        raise requests.exceptions.HTTPError(
            error_msg,
            response=e.response
        ) from e
    except requests.exceptions.RequestException as e:
        logger.error(f"Jira writeback agent call failed: {endpoint} - {str(e)}")
        raise
