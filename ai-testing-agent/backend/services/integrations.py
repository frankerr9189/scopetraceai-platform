"""
Service functions for retrieving tenant integration credentials.
"""
import logging
from typing import Dict, Optional
from sqlalchemy.orm import Session
from flask import g
from models import TenantIntegration
from utils.encryption import decrypt_secret
from db import get_db

logger = logging.getLogger(__name__)


def get_jira_integration(db: Session, tenant_id: str) -> Dict[str, str]:
    """
    Get Jira integration credentials for a tenant.
    
    Args:
        db: Database session
        tenant_id: Tenant ID (UUID string)
    
    Returns:
        dict with keys:
            - base_url: Jira base URL
            - email: Jira user email
            - api_token: Decrypted Jira API token
    
    Raises:
        ValueError: If integration not found, inactive, or missing required fields
    """
    import uuid as uuid_module
    
    # Convert tenant_id to UUID if it's a string
    if isinstance(tenant_id, str):
        tenant_id = uuid_module.UUID(tenant_id)
    
    # Query for active Jira integration
    integration = db.query(TenantIntegration).filter(
        TenantIntegration.tenant_id == tenant_id,
        TenantIntegration.provider == 'jira',
        TenantIntegration.is_active == True
    ).first()
    
    if not integration:
        logger.warning(
            "Jira integration not found or inactive",
            extra={
                "tenant_id": str(tenant_id),
                "provider": "jira"
            }
        )
        raise ValueError(
            f"Jira integration not found for tenant {tenant_id}. "
            "Please configure Jira integration using the seed script or admin interface."
        )
    
    # Validate required fields
    if not integration.jira_base_url:
        raise ValueError(
            f"Jira integration for tenant {tenant_id} is missing jira_base_url"
        )
    if not integration.jira_user_email:
        raise ValueError(
            f"Jira integration for tenant {tenant_id} is missing jira_user_email"
        )
    if not integration.credentials_ciphertext:
        raise ValueError(
            f"Jira integration for tenant {tenant_id} is missing encrypted credentials"
        )
    
    # Log successful integration resolution (safe fields only)
    logger.info(
        "Jira integration resolved",
        extra={
            "tenant_id": str(tenant_id),
            "provider": "jira",
            "integration_id": str(integration.id),
            "base_url": integration.jira_base_url,
            "is_active": integration.is_active
        }
    )
    
    # Decrypt API token
    try:
        api_token = decrypt_secret(integration.credentials_ciphertext)
    except Exception as e:
        raise ValueError(
            f"Failed to decrypt Jira credentials for tenant {tenant_id}: {str(e)}"
        ) from e
    
    return {
        "base_url": integration.jira_base_url,
        "email": integration.jira_user_email,
        "api_token": api_token
    }


def get_jira_integration_for_current_tenant() -> Dict[str, str]:
    """
    Get Jira integration credentials for the current tenant from flask.g.
    This is a convenience function that uses the tenant_id from the JWT token.
    
    Returns:
        dict with keys:
            - base_url: Jira base URL
            - email: Jira user email
            - api_token: Decrypted Jira API token
    
    Raises:
        ValueError: If tenant_id not in flask.g, integration not found, inactive, or missing required fields
        RuntimeError: If not in Flask request context
    """
    from flask import g, has_request_context
    
    if not has_request_context():
        raise RuntimeError("get_jira_integration_for_current_tenant() must be called within a Flask request context")
    
    if not hasattr(g, 'tenant_id') or not g.tenant_id:
        raise ValueError("tenant_id not found in request context. Ensure JWT authentication is enabled.")
    
    # Get database session
    db = next(get_db())
    try:
        return get_jira_integration(db, g.tenant_id)
    finally:
        db.close()
