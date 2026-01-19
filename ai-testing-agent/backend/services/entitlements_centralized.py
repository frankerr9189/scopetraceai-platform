"""
Centralized entitlement and plan tier enforcement for ScopeTraceAI.

TRUST BOUNDARY: This module is the SINGLE SOURCE OF TRUTH for all subscription,
plan tier, seat, and usage enforcement. Agent services MUST NOT implement
any policy logic - they are trusted internal executors only.

Plan Tiers:
- free: No paid subscription, trial only
- solo: Individual user plan
- team: Team plan with seat limits
- business: Business plan with higher limits

All enforcement happens BEFORE calling agent services.
"""
import logging
import os
import uuid
from typing import Tuple, Optional, Dict, Any
from sqlalchemy.orm import Session
from models import Tenant, TenantUser

logger = logging.getLogger(__name__)

# ============================================================================
# PLAN TIER DEFINITIONS
# ============================================================================

PLAN_TIERS = {
    "free": {
        "name": "Free",
        "seat_cap": 1,
        "max_tickets_per_run": 5,
        "max_input_chars": 10000,
        "trial_runs": {
            "requirements": 3,
            "testplan": 3,
            "writeback": 3
        }
    },
    "solo": {
        "name": "Solo",
        "seat_cap": 1,
        "max_tickets_per_run": 20,
        "max_input_chars": 50000,
        "trial_runs": None  # No trial limits for paid plans
    },
    "team": {
        "name": "Team",
        "seat_cap": 10,
        "max_tickets_per_run": 50,
        "max_input_chars": 200000,
        "trial_runs": None
    },
    "business": {
        "name": "Business",
        "seat_cap": 100,
        "max_tickets_per_run": 200,
        "max_input_chars": 1000000,
        "trial_runs": None
    }
}


def get_tenant_plan_tier(db: Session, tenant_id: str) -> str:
    """
    Determine plan tier for a tenant based on subscription_status.
    
    Args:
        db: Database session
        tenant_id: Tenant UUID string
        
    Returns:
        Plan tier string: "free", "solo", "team", or "business"
        Defaults to "free" if tenant not found or status unknown
    """
    try:
        tenant_uuid = tenant_id if isinstance(tenant_id, uuid.UUID) else uuid.UUID(tenant_id)
        tenant = db.query(Tenant).filter(Tenant.id == tenant_uuid).first()
        
        if not tenant:
            logger.warning(f"Tenant {tenant_id} not found, defaulting to 'free' tier")
            return "free"
        
        # Refresh the tenant object to ensure we have the latest subscription_status from the database
        db.refresh(tenant)
        
        # Read subscription_status directly from the database column
        subscription_status = tenant.subscription_status if hasattr(tenant, "subscription_status") else "unselected"
        
        # Map subscription_status to plan tier
        # TODO: Add plan_tier column to Tenant model for explicit tier assignment
        # For now, map based on subscription_status:
        # - unselected/trial/paywalled/canceled -> free
        # - individual -> solo
        # - team -> team
        if subscription_status == "individual":
            return "solo"
        elif subscription_status == "team":
            return "team"
        else:
            # unselected, trial, paywalled, canceled -> free tier
            return "free"
            
    except Exception as e:
        logger.error(f"Error determining plan tier for tenant {tenant_id}: {str(e)}", exc_info=True)
        return "free"


def check_seat_cap(db: Session, tenant_id: str) -> Tuple[bool, Optional[str], int]:
    """
    Check if tenant has exceeded seat cap for their plan tier.
    
    Args:
        db: Database session
        tenant_id: Tenant UUID string
        
    Returns:
        Tuple of (allowed: bool, reason: Optional[str], current_seats: int)
    """
    try:
        tenant_uuid = tenant_id if isinstance(tenant_id, uuid.UUID) else uuid.UUID(tenant_id)
        tenant = db.query(Tenant).filter(Tenant.id == tenant_uuid).first()
        
        if not tenant:
            return False, "TENANT_NOT_FOUND", 0
        
        plan_tier = get_tenant_plan_tier(db, tenant_id)
        tier_config = PLAN_TIERS.get(plan_tier, PLAN_TIERS["free"])
        seat_cap = tier_config["seat_cap"]
        
        # Count active users for this tenant
        active_users = db.query(TenantUser).filter(
            TenantUser.tenant_id == tenant_uuid,
            TenantUser.is_active == True
        ).count()
        
        if active_users >= seat_cap:
            return False, f"SEAT_CAP_EXCEEDED (plan={plan_tier}, cap={seat_cap}, current={active_users})", active_users
        
        return True, None, active_users
        
    except Exception as e:
        logger.error(f"Error checking seat cap for tenant {tenant_id}: {str(e)}", exc_info=True)
        return False, "SEAT_CHECK_ERROR", 0


def check_ticket_limit(db: Session, tenant_id: str, ticket_count: int, agent: str) -> Tuple[bool, Optional[str]]:
    """
    Check if ticket count exceeds plan tier limit.
    
    Args:
        db: Database session
        tenant_id: Tenant UUID string
        ticket_count: Number of tickets in the request
        agent: Agent name (for logging)
        
    Returns:
        Tuple of (allowed: bool, reason: Optional[str])
    """
    try:
        plan_tier = get_tenant_plan_tier(db, tenant_id)
        tier_config = PLAN_TIERS.get(plan_tier, PLAN_TIERS["free"])
        max_tickets = tier_config["max_tickets_per_run"]
        
        if ticket_count > max_tickets:
            return False, f"TICKET_LIMIT_EXCEEDED (plan={plan_tier}, limit={max_tickets}, requested={ticket_count})"
        
        return True, None
        
    except Exception as e:
        logger.error(f"Error checking ticket limit for tenant {tenant_id}: {str(e)}", exc_info=True)
        return False, "TICKET_CHECK_ERROR"


def check_input_size_limit(db: Session, tenant_id: str, input_char_count: int, agent: str) -> Tuple[bool, Optional[str]]:
    """
    Check if input size exceeds plan tier limit.
    
    Args:
        db: Database session
        tenant_id: Tenant UUID string
        input_char_count: Character count of input
        agent: Agent name (for logging)
        
    Returns:
        Tuple of (allowed: bool, reason: Optional[str])
    """
    try:
        plan_tier = get_tenant_plan_tier(db, tenant_id)
        tier_config = PLAN_TIERS.get(plan_tier, PLAN_TIERS["free"])
        max_chars = tier_config["max_input_chars"]
        
        if input_char_count > max_chars:
            return False, f"INPUT_SIZE_LIMIT_EXCEEDED (plan={plan_tier}, limit={max_chars}, requested={input_char_count})"
        
        return True, None
        
    except Exception as e:
        logger.error(f"Error checking input size limit for tenant {tenant_id}: {str(e)}", exc_info=True)
        return False, "INPUT_SIZE_CHECK_ERROR"


def check_subscription_status(db: Session, tenant_id: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Check subscription status gating (Trial/Active/Paywalled).
    This preserves existing trial logic behavior.
    
    Args:
        db: Database session
        tenant_id: Tenant UUID string
        
    Returns:
        Tuple of (allowed: bool, reason: Optional[str], subscription_status: Optional[str])
    """
    try:
        tenant_uuid = tenant_id if isinstance(tenant_id, uuid.UUID) else uuid.UUID(tenant_id)
        tenant = db.query(Tenant).filter(Tenant.id == tenant_uuid).first()
        
        if not tenant:
            return False, "TENANT_NOT_FOUND", None
        
        # Refresh the tenant object to ensure we have the latest subscription_status from the database
        db.refresh(tenant)
        
        # Read subscription_status directly from the database column
        subscription_status = tenant.subscription_status if hasattr(tenant, "subscription_status") else "unselected"
        
        if subscription_status == "paywalled":
            return False, "PAYWALLED", subscription_status
        
        if subscription_status == "canceled":
            return False, "SUBSCRIPTION_CANCELED", subscription_status
        
        if subscription_status == "unselected":
            return False, "SUBSCRIPTION_UNSELECTED", subscription_status
        
        # trial, individual, and team are allowed (trial counters checked separately for trial)
        return True, None, subscription_status
        
    except Exception as e:
        logger.error(f"Error checking subscription status for tenant {tenant_id}: {str(e)}", exc_info=True)
        # Fail closed unless ENTITLEMENT_FAIL_OPEN is set
        fail_open = os.getenv("ENTITLEMENT_FAIL_OPEN", "false").lower() == "true"
        if fail_open:
            logger.warning(f"ENTITLEMENT_FAIL_OPEN=true: Allowing despite subscription check error")
            return True, None, None
        return False, "SUBSCRIPTION_CHECK_ERROR", None


def check_trial_remaining(db: Session, tenant_id: str, agent: str) -> Tuple[bool, Optional[str], Optional[int]]:
    """
    Check if tenant has remaining trial runs for the specified agent.
    This preserves existing trial counter behavior.
    
    Args:
        db: Database session
        tenant_id: Tenant UUID string
        agent: Agent name ('requirements_ba', 'test_plan', 'jira_writeback')
        
    Returns:
        Tuple of (allowed: bool, reason: Optional[str], remaining: Optional[int])
    """
    try:
        tenant_uuid = tenant_id if isinstance(tenant_id, uuid.UUID) else uuid.UUID(tenant_id)
        tenant = db.query(Tenant).filter(Tenant.id == tenant_uuid).first()
        
        if not tenant:
            return False, "TENANT_NOT_FOUND", None
        
        # Refresh the tenant object to ensure we have the latest subscription_status from the database
        db.refresh(tenant)
        
        # Read subscription_status directly from the database column
        subscription_status = tenant.subscription_status if hasattr(tenant, "subscription_status") else "unselected"
        
        # Only check trial counters if in trial status
        if subscription_status != "trial":
            # Active or Paywalled - no trial limits
            return True, None, None
        
        # Map agent name to trial counter field
        counter_map = {
            "requirements_ba": "trial_requirements_runs_remaining",
            "test_plan": "trial_testplan_runs_remaining",
            "jira_writeback": "trial_writeback_runs_remaining"
        }
        
        counter_field = counter_map.get(agent)
        if not counter_field:
            logger.warning(f"Unknown agent '{agent}', allowing request")
            return True, None, None
        
        remaining = getattr(tenant, counter_field, 0)
        
        if remaining <= 0:
            return False, f"TRIAL_EXHAUSTED (agent={agent}, remaining={remaining})", 0
        
        return True, None, remaining
        
    except Exception as e:
        logger.error(f"Error checking trial remaining for tenant {tenant_id}, agent {agent}: {str(e)}", exc_info=True)
        # Fail closed unless ENTITLEMENT_FAIL_OPEN is set
        fail_open = os.getenv("ENTITLEMENT_FAIL_OPEN", "false").lower() == "true"
        if fail_open:
            logger.warning(f"ENTITLEMENT_FAIL_OPEN=true: Allowing despite trial check error")
            return True, None, None
        return False, "TRIAL_CHECK_ERROR", None


def enforce_entitlements(
    db: Session,
    tenant_id: str,
    agent: str,
    ticket_count: Optional[int] = None,
    input_char_count: Optional[int] = None
) -> Tuple[bool, Optional[str], Dict[str, Any]]:
    """
    Comprehensive entitlement enforcement - the single source of truth.
    Checks all limits and gates before allowing agent execution.
    
    Args:
        db: Database session
        tenant_id: Tenant UUID string
        agent: Agent name ('requirements_ba', 'test_plan', 'jira_writeback')
        ticket_count: Optional number of tickets (for ticket limit check)
        input_char_count: Optional input character count (for size limit check)
        
    Returns:
        Tuple of (allowed: bool, reason: Optional[str], metadata: Dict)
        metadata contains: subscription_status, plan_tier, remaining, etc.
    """
    metadata = {}
    
    # 1. Check subscription status (Trial/Active/Paywalled)
    allowed, reason, subscription_status = check_subscription_status(db, tenant_id)
    if not allowed:
        return False, reason, {"subscription_status": subscription_status}
    metadata["subscription_status"] = subscription_status
    
    # 2. Determine plan tier
    plan_tier = get_tenant_plan_tier(db, tenant_id)
    metadata["plan_tier"] = plan_tier
    
    # 3. Check seat cap (only for user creation, but we check it here for completeness)
    # Note: This is informational - actual seat enforcement happens at user creation
    seat_allowed, seat_reason, current_seats = check_seat_cap(db, tenant_id)
    metadata["current_seats"] = current_seats
    metadata["seat_cap"] = PLAN_TIERS.get(plan_tier, PLAN_TIERS["free"])["seat_cap"]
    
    # 4. Check ticket limit (if provided)
    if ticket_count is not None:
        allowed, reason = check_ticket_limit(db, tenant_id, ticket_count, agent)
        if not allowed:
            return False, reason, metadata
        metadata["ticket_count"] = ticket_count
    
    # 5. Check input size limit (if provided)
    if input_char_count is not None:
        allowed, reason = check_input_size_limit(db, tenant_id, input_char_count, agent)
        if not allowed:
            return False, reason, metadata
        metadata["input_char_count"] = input_char_count
    
    # 6. Check trial remaining (only if in trial status)
    if subscription_status == "trial":
        allowed, reason, remaining = check_trial_remaining(db, tenant_id, agent)
        if not allowed:
            return False, reason, {**metadata, "remaining": remaining}
        metadata["trial_remaining"] = remaining
    
    return True, None, metadata
