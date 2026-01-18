"""
Tenant isolation utilities and guardrails.

This module provides helper functions to ensure tenant isolation is enforced
across all database queries and operations.
"""
from flask import g, has_request_context
from typing import Optional
import uuid as uuid_module


def require_tenant_context() -> str:
    """
    Require that tenant_id exists in Flask request context (from JWT).
    
    This is a guardrail to prevent accidental access to tenant-scoped operations
    without proper authentication.
    
    Returns:
        str: Tenant ID (UUID string)
        
    Raises:
        RuntimeError: If not in Flask request context
        ValueError: If tenant_id not found in request context
    """
    if not has_request_context():
        raise RuntimeError(
            "require_tenant_context() must be called within a Flask request context. "
            "Ensure the request has passed through JWT authentication middleware."
        )
    
    if not hasattr(g, 'tenant_id') or not g.tenant_id:
        raise ValueError(
            "tenant_id not found in request context. "
            "Ensure JWT authentication is enabled and the token contains a tenant_id claim."
        )
    
    return str(g.tenant_id)


def get_tenant_id() -> Optional[str]:
    """
    Get tenant_id from Flask request context if available.
    
    This is a safe getter that returns None if tenant context is not available,
    rather than raising an exception.
    
    Returns:
        str: Tenant ID (UUID string) if available, None otherwise
    """
    if not has_request_context():
        return None
    
    if not hasattr(g, 'tenant_id') or not g.tenant_id:
        return None
    
    return str(g.tenant_id)


def ensure_tenant_scoped_query(query, model_class, tenant_id: Optional[str] = None):
    """
    Ensure a database query is tenant-scoped.
    
    This is a helper to add tenant_id filtering to queries if not already present.
    It's a guardrail to prevent accidental cross-tenant queries.
    
    Args:
        query: SQLAlchemy query object
        model_class: Model class (must have tenant_id attribute)
        tenant_id: Optional tenant_id to use (defaults to g.tenant_id)
        
    Returns:
        SQLAlchemy query with tenant_id filter applied
        
    Raises:
        ValueError: If tenant_id cannot be determined
    """
    if tenant_id is None:
        tenant_id = require_tenant_context()
    
    # Convert to UUID if needed
    if isinstance(tenant_id, str):
        tenant_id = uuid_module.UUID(tenant_id)
    
    # Add tenant_id filter
    return query.filter(model_class.tenant_id == tenant_id)
