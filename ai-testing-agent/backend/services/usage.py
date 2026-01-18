"""
Service functions for recording agent usage events for billing and analytics.
"""
from typing import Optional
from sqlalchemy.orm import Session
from flask import g
from models import UsageEvent
from db import get_db
import uuid as uuid_module


def record_usage_event(
    db: Session,
    *,
    tenant_id: str,
    user_id: Optional[str] = None,
    agent: str,
    source: str,
    jira_ticket_count: int = 0,
    input_char_count: int = 0,
    success: bool,
    error_code: Optional[str] = None,
    run_id: Optional[str] = None,
    duration_ms: Optional[int] = None
) -> UsageEvent:
    """
    Record a usage event for agent billing and analytics.
    
    Args:
        db: Database session
        tenant_id: Tenant ID (REQUIRED, UUID string)
        user_id: Optional user ID (UUID string). If None, will try to get from flask.g.user_id
        agent: Agent identifier (e.g., 'requirements_ba', 'test_plan', 'jira_writeback')
        source: Source type ('jira' | 'text')
        jira_ticket_count: Number of Jira tickets processed (default: 0)
        input_char_count: Number of input characters (default: 0)
        success: Whether the operation succeeded
        error_code: Optional short machine-readable error code (no stack traces)
        run_id: Optional reference to runs.run_id if applicable
        duration_ms: Optional duration in milliseconds
    
    Returns:
        Created UsageEvent instance
    
    Raises:
        ValueError: If tenant_id is missing or invalid
    """
    # Validate tenant_id is provided (never accept from request body)
    if not tenant_id:
        raise ValueError("tenant_id is required and cannot be None")
    
    # Convert tenant_id to UUID if it's a string
    if isinstance(tenant_id, str):
        try:
            tenant_id = uuid_module.UUID(tenant_id)
        except ValueError:
            raise ValueError(f"Invalid tenant_id format: {tenant_id}")
    
    # Get user_id from flask.g if not provided and available
    if user_id is None:
        try:
            if hasattr(g, 'user_id') and g.user_id:
                user_id = g.user_id
        except RuntimeError:
            # Not in Flask request context, user_id remains None
            pass
    
    # Convert user_id to UUID if it's a string
    if user_id is not None:
        if isinstance(user_id, str):
            try:
                user_id = uuid_module.UUID(user_id)
            except ValueError:
                # Invalid user_id format, set to None
                user_id = None
    
    # Create usage event
    usage_event = UsageEvent(
        tenant_id=tenant_id,
        user_id=user_id,
        agent=agent,
        source=source,
        jira_ticket_count=jira_ticket_count,
        input_char_count=input_char_count,
        success=success,
        error_code=error_code,
        run_id=run_id,
        duration_ms=duration_ms
    )
    
    # Insert and commit
    db.add(usage_event)
    db.commit()
    db.refresh(usage_event)
    
    return usage_event
