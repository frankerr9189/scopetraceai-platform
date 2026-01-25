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

BILLING DATA SOURCE: All billing data (subscription_status, plan_tier) MUST be
read from tenant_billing table. The tenants table is NOT a source of billing truth.
"""
import logging
import os
import uuid
from typing import Tuple, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import Table, Column, String, text
from sqlalchemy.dialects.postgresql import UUID
from models import Tenant, TenantUser

logger = logging.getLogger(__name__)

# ============================================================================
# ONBOARDING CONSTANTS
# ============================================================================

# Plan tier constants
PLAN_UNSELECTED = "unselected"

# Billing status constants (Stripe statuses)
STATUS_INCOMPLETE = "incomplete"
STATUS_TRIALING = "trialing"
STATUS_ACTIVE = "active"
STATUS_PAST_DUE = "past_due"
STATUS_CANCELED = "canceled"

# Statuses that allow running agent operations
ALLOWED_STATUSES = {STATUS_TRIALING, STATUS_ACTIVE}
# Note: past_due is explicitly NOT in ALLOWED_STATUSES (deny by default)

# ============================================================================
# TENANT_BILLING HELPER FUNCTIONS
# ============================================================================

def _map_subscription_status_to_billing_status(subscription_status: str, plan_tier: Optional[str] = None) -> str:
    """
    Map subscription_status values to tenant_billing.status (Stripe status values).
    
    Reverse mapping of _map_billing_status_to_subscription_status.
    
    Args:
        subscription_status: Our subscription_status value
        plan_tier: Optional plan tier to help determine Stripe status
        
    Returns:
        Stripe status value for tenant_billing.status
    """
    if not subscription_status:
        return "incomplete"
    
    status_lower = subscription_status.lower()
    
    # Map our subscription_status to Stripe statuses
    if status_lower == "trial":
        return "trialing"
    elif status_lower == "individual":
        return "active"  # Will be active with plan_tier
    elif status_lower == "team":
        return "active"  # Will be active with plan_tier
    elif status_lower == "paywalled":
        return "past_due"  # Or "unpaid" - using past_due for now
    elif status_lower == "canceled":
        return "canceled"
    elif status_lower == "suspended":
        return "paused"
    elif status_lower == "active":
        return "active"
    elif status_lower == "unselected":
        return "incomplete"
    else:
        logger.warning(f"Unknown subscription_status '{subscription_status}', defaulting to 'incomplete'")
        return "incomplete"


def _map_billing_status_to_subscription_status(billing_status: Optional[str]) -> str:
    """
    Map tenant_billing.status (Stripe status values) to subscription_status values.
    
    Stripe statuses: trialing, active, past_due, canceled, unpaid, incomplete, etc.
    Our subscription_status: trial, individual, team, paywalled, canceled, unselected, suspended, active
    
    IMPORTANT: This function does NOT auto-grant access. incomplete/unselected statuses
    are explicitly mapped to paywalled/unselected to enforce onboarding gates.
    """
    if not billing_status:
        return "unselected"
    
    billing_status_lower = billing_status.lower()
    
    # Map Stripe statuses to our subscription_status values
    # incomplete -> paywalled (NOT unselected) to enforce onboarding gate
    status_map = {
        "trialing": "trial",
        "active": "active",  # Will be mapped to individual/team based on plan_tier
        "past_due": "paywalled",  # Explicitly deny past_due
        "canceled": "canceled",
        "unpaid": "paywalled",
        "incomplete": "paywalled",  # Changed: incomplete -> paywalled (not unselected) to enforce onboarding
        "incomplete_expired": "paywalled",
        "paused": "suspended",
    }
    
    # Direct mapping if exists
    if billing_status_lower in status_map:
        return status_map[billing_status_lower]
    
    # Fallback: try to match common patterns
    if "trial" in billing_status_lower:
        return "trial"
    if "cancel" in billing_status_lower:
        return "canceled"
    if "suspend" in billing_status_lower or "pause" in billing_status_lower:
        return "suspended"
    if "paywall" in billing_status_lower or "past_due" in billing_status_lower:
        return "paywalled"
    
    # Default fallback - do NOT auto-grant access
    logger.warning(f"Unknown billing_status '{billing_status}', defaulting to 'unselected'")
    return "unselected"


def get_tenant_billing(db: Session, tenant_id: str) -> Dict[str, Any]:
    """
    Get billing data from tenant_billing table for a tenant.
    This is the ONLY source of truth for billing data.
    
    Args:
        db: Database session
        tenant_id: Tenant UUID string
        
    Returns:
        Dict with keys: subscription_status, plan_tier, and other billing fields
        
    Raises:
        RuntimeError: If tenant_billing row is missing (hard error, no fallbacks)
    """
    try:
        tenant_uuid = tenant_id if isinstance(tenant_id, uuid.UUID) else uuid.UUID(tenant_id)
        
        # Query tenant_billing table directly (table may not be in models.py)
        # Using raw SQL to avoid needing model definition
        # Note: tenant_billing.status maps to subscription_status
        # Trial counters are still in tenants table (not billing data)
        result = db.execute(
            text("""
                SELECT tb.status, tb.plan_tier,
                       tb.current_period_start, tb.current_period_end,
                       t.trial_requirements_runs_remaining,
                       t.trial_testplan_runs_remaining,
                       t.trial_writeback_runs_remaining
                FROM tenant_billing tb
                INNER JOIN tenants t ON t.id = tb.tenant_id
                WHERE tb.tenant_id = :tenant_id
            """),
            {"tenant_id": str(tenant_uuid)}
        ).first()
        
        if not result:
            error_msg = f"tenant_billing row missing for tenant_id={tenant_id}. Billing data is required."
            logger.error(error_msg)
            raise RuntimeError(error_msg)
        
        # Map billing status to subscription_status
        billing_status = result.status
        subscription_status = _map_billing_status_to_subscription_status(billing_status)
        
        # If status is "active" from Stripe, determine if it's individual or team based on plan_tier
        if subscription_status == "active":
            plan_tier = result.plan_tier or ""
            if plan_tier.lower() in ["solo", "individual"]:
                subscription_status = "individual"
            elif plan_tier.lower() in ["team", "business"]:
                subscription_status = "team"
            else:
                # Default to individual for active subscriptions
                subscription_status = "individual"
        
        return {
            "subscription_status": subscription_status,
            "plan_tier": result.plan_tier,
            "status": result.status,  # Raw billing status (Stripe status)
            "current_period_start": result.current_period_start,  # Stripe period start (datetime or None)
            "current_period_end": result.current_period_end,  # Stripe period end (datetime or None)
            "trial_requirements_runs_remaining": result.trial_requirements_runs_remaining or 0,
            "trial_testplan_runs_remaining": result.trial_testplan_runs_remaining or 0,
            "trial_writeback_runs_remaining": result.trial_writeback_runs_remaining or 0,
        }
    except RuntimeError:
        # Re-raise our hard errors
        raise
    except Exception as e:
        error_msg = f"Error reading tenant_billing for tenant_id={tenant_id}: {str(e)}"
        logger.error(error_msg, exc_info=True)
        raise RuntimeError(error_msg)

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
    "user": {
        "name": "User",
        "seat_cap": 5,
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


def create_tenant_billing_row(db: Session, tenant_id: str, subscription_status: str = "unselected", plan_tier: str = None) -> None:
    """
    Create a tenant_billing row for a new tenant.
    This should be called immediately after tenant creation.
    
    Args:
        db: Database session
        tenant_id: Tenant UUID string
        subscription_status: Initial subscription status (default: "unselected")
        plan_tier: Initial plan tier (default: None -> "unselected")
        
    Raises:
        RuntimeError: If tenant_billing row already exists or creation fails
    """
    try:
        tenant_uuid = tenant_id if isinstance(tenant_id, uuid.UUID) else uuid.UUID(tenant_id)
        
        # Check if tenant_billing row already exists
        existing = db.execute(
            text("SELECT tenant_id FROM tenant_billing WHERE tenant_id = :tenant_id"),
            {"tenant_id": str(tenant_uuid)}
        ).first()
        
        if existing:
            logger.warning(f"tenant_billing row already exists for tenant_id={tenant_id}, skipping creation")
            return
        
        # Default to unselected plan_tier if not provided
        if plan_tier is None:
            plan_tier = PLAN_UNSELECTED
        
        # Map subscription_status to tenant_billing.status (Stripe status)
        # For new tenants, default to incomplete status (enforces onboarding gate)
        if subscription_status == "unselected":
            billing_status = STATUS_INCOMPLETE
        else:
            billing_status = _map_subscription_status_to_billing_status(subscription_status, plan_tier)
        
        # Insert tenant_billing row
        db.execute(
            text("""
                INSERT INTO tenant_billing (
                    tenant_id,
                    status,
                    plan_tier,
                    cancel_at_period_end,
                    created_at,
                    updated_at
                ) VALUES (
                    :tenant_id,
                    :status,
                    :plan_tier,
                    false,
                    NOW(),
                    NOW()
                )
            """),
            {
                "tenant_id": str(tenant_uuid),
                "status": billing_status,
                "plan_tier": plan_tier
            }
        )
        
        db.commit()
        logger.info(f"Created tenant_billing row for tenant_id={tenant_id} with status='{billing_status}', plan_tier='{plan_tier}'")
        
    except Exception as e:
        db.rollback()
        error_msg = f"Error creating tenant_billing row for tenant_id={tenant_id}: {str(e)}"
        logger.error(error_msg, exc_info=True)
        raise RuntimeError(error_msg)


def update_tenant_billing_status(db: Session, tenant_id: str, subscription_status: str, plan_tier: Optional[str] = None) -> None:
    """
    Update tenant_billing.status for a tenant.
    This is the ONLY place billing status should be written.
    
    Args:
        db: Database session
        tenant_id: Tenant UUID string
        subscription_status: Subscription status value (trial, individual, team, paywalled, canceled, suspended, active, unselected)
        plan_tier: Optional plan tier (used to determine Stripe status for individual/team)
        
    Raises:
        RuntimeError: If tenant_billing row is missing or update fails
    """
    try:
        tenant_uuid = tenant_id if isinstance(tenant_id, uuid.UUID) else uuid.UUID(tenant_id)
        
        # Map subscription_status to tenant_billing.status (Stripe status)
        billing_status = _map_subscription_status_to_billing_status(subscription_status, plan_tier)
        
        # Get current plan_tier if not provided
        if not plan_tier:
            try:
                current_billing = get_tenant_billing(db, tenant_id)
                plan_tier = current_billing.get("plan_tier")
            except RuntimeError:
                # If tenant_billing doesn't exist, we need to create it or use default
                logger.warning(f"tenant_billing row missing for tenant_id={tenant_id}, cannot determine plan_tier")
                plan_tier = None
        
        # Update tenant_billing.status
        result = db.execute(
            text("""
                UPDATE tenant_billing
                SET status = :status,
                    updated_at = NOW()
                WHERE tenant_id = :tenant_id
            """),
            {
                "status": billing_status,
                "tenant_id": str(tenant_uuid)
            }
        )
        
        if result.rowcount == 0:
            error_msg = f"tenant_billing row missing for tenant_id={tenant_id}. Cannot update status."
            logger.error(error_msg)
            raise RuntimeError(error_msg)
        
        # Also update plan_tier if provided and different
        if plan_tier:
            db.execute(
                text("""
                    UPDATE tenant_billing
                    SET plan_tier = :plan_tier,
                        updated_at = NOW()
                    WHERE tenant_id = :tenant_id
                """),
                {
                    "plan_tier": plan_tier,
                    "tenant_id": str(tenant_uuid)
                }
            )
        
        db.commit()
        logger.info(f"Updated tenant_billing.status to '{billing_status}' (subscription_status='{subscription_status}') for tenant_id={tenant_id}")
        
    except RuntimeError:
        # Re-raise our hard errors
        raise
    except Exception as e:
        db.rollback()
        error_msg = f"Error updating tenant_billing.status for tenant_id={tenant_id}: {str(e)}"
        logger.error(error_msg, exc_info=True)
        raise RuntimeError(error_msg)


def get_tenant_plan_tier(db: Session, tenant_id: str) -> str:
    """
    Determine plan tier for a tenant from tenant_billing table.
    
    Args:
        db: Database session
        tenant_id: Tenant UUID string
        
    Returns:
        Plan tier string: "free", "solo", "team", or "business"
        
    Raises:
        RuntimeError: If tenant_billing row is missing (hard error)
    """
    try:
        billing = get_tenant_billing(db, tenant_id)
        plan_tier = billing.get("plan_tier")
        
        # If plan_tier is explicitly set in tenant_billing, use it
        if plan_tier:
            return plan_tier
        
        # Fallback: map subscription_status to plan tier (for backward compatibility during migration)
        subscription_status = billing.get("subscription_status", "unselected")
        if subscription_status == "individual":
            return "solo"
        elif subscription_status == "team":
            return "team"
        else:
            # unselected, trial, paywalled, canceled -> free tier
            return "free"
            
    except RuntimeError:
        # Re-raise hard errors from get_tenant_billing
        raise
    except Exception as e:
        error_msg = f"Error determining plan tier for tenant {tenant_id}: {str(e)}"
        logger.error(error_msg, exc_info=True)
        raise RuntimeError(error_msg)


def check_seat_cap(db: Session, tenant_id: str) -> Tuple[bool, Optional[str], int, Optional[int]]:
    """
    Check if tenant can add a new user (seat cap and billing status).
    Enforces seat caps based on plan tier and billing status.
    
    Args:
        db: Database session
        tenant_id: Tenant UUID string
        
    Returns:
        Tuple of (allowed: bool, error_code: Optional[str], current_seats: int, seat_cap: Optional[int])
        - error_code: "SEAT_CAP_EXCEEDED", "BILLING_INACTIVE", "TENANT_NOT_FOUND", or None
        - seat_cap: The seat cap for the plan tier (None if error)
    """
    try:
        tenant_uuid = tenant_id if isinstance(tenant_id, uuid.UUID) else uuid.UUID(tenant_id)
        tenant = db.query(Tenant).filter(Tenant.id == tenant_uuid).first()
        
        if not tenant:
            return False, "TENANT_NOT_FOUND", 0, None
        
        # Get billing data to check status and plan tier
        billing = get_tenant_billing(db, tenant_id)
        plan_tier = billing.get("plan_tier") or "free"
        raw_status = billing.get("status")  # Raw billing status (Stripe status)
        
        # Check billing status: must be trialing/active OR plan_tier == "free"
        # If status not in ALLOWED_STATUSES (trialing/active) AND plan_tier != "free":
        # treat as paywalled for seat creation
        if plan_tier != "free" and raw_status not in ALLOWED_STATUSES:
            return False, "BILLING_INACTIVE", 0, None
        
        # Get seat cap for plan tier (default to 1 for unknown tiers)
        tier_config = PLAN_TIERS.get(plan_tier, PLAN_TIERS["free"])
        seat_cap = tier_config["seat_cap"]
        
        # Count active users for this tenant
        active_users = db.query(TenantUser).filter(
            TenantUser.tenant_id == tenant_uuid,
            TenantUser.is_active == True
        ).count()
        
        if active_users >= seat_cap:
            return False, "SEAT_CAP_EXCEEDED", active_users, seat_cap
        
        return True, None, active_users, seat_cap
        
    except Exception as e:
        logger.error(f"Error checking seat cap for tenant {tenant_id}: {str(e)}", exc_info=True)
        return False, "SEAT_CHECK_ERROR", 0, None


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


def assert_onboarding_complete(billing: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Assert that onboarding is complete (plan must be chosen).
    This gate enforces that plan_tier != "unselected" AND status != "incomplete".
    
    Args:
        billing: Billing dict from get_tenant_billing() with keys: plan_tier, status (raw), etc.
        
    Returns:
        Tuple of (allowed: bool, reason: Optional[str])
        Returns False with "ONBOARDING_INCOMPLETE" if plan_tier is "unselected" or status is "incomplete"
    """
    plan_tier = billing.get("plan_tier")
    raw_status = billing.get("status")  # Raw billing status (Stripe status)
    
    # Check plan_tier first
    if plan_tier == PLAN_UNSELECTED or plan_tier is None:
        return False, "ONBOARDING_INCOMPLETE"
    
    # Check raw status - if status is "incomplete", deny (enforces onboarding gate)
    if raw_status and raw_status.lower() == STATUS_INCOMPLETE.lower():
        return False, "ONBOARDING_INCOMPLETE"
    
    # If we have a valid plan_tier and non-incomplete status, onboarding is complete
    return True, None


def check_subscription_status(db: Session, tenant_id: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Check subscription status gating (Trial/Active/Paywalled).
    Reads from tenant_billing table (single source of truth).
    
    IMPORTANT: This function now includes onboarding gate check.
    If plan_tier is "unselected" or status is "incomplete", returns ONBOARDING_INCOMPLETE.
    
    Args:
        db: Database session
        tenant_id: Tenant UUID string
        
    Returns:
        Tuple of (allowed: bool, reason: Optional[str], subscription_status: Optional[str])
        
    Raises:
        RuntimeError: If tenant_billing row is missing (hard error)
    """
    try:
        billing = get_tenant_billing(db, tenant_id)
        
        # First check onboarding gate (plan must be chosen)
        onboarding_allowed, onboarding_reason = assert_onboarding_complete(billing)
        if not onboarding_allowed:
            return False, onboarding_reason, billing.get("subscription_status", "unselected")
        
        subscription_status = billing.get("subscription_status", "unselected")
        raw_status = billing.get("status")  # Raw billing status (Stripe status)
        
        if subscription_status == "paywalled":
            return False, "PAYWALLED", subscription_status
        
        if subscription_status == "canceled":
            return False, "SUBSCRIPTION_CANCELED", subscription_status
        
        # Check raw billing status for past_due (explicitly deny)
        if raw_status and raw_status.lower() == STATUS_PAST_DUE.lower():
            return False, "SUBSCRIPTION_PAST_DUE", subscription_status
        
        # trial, individual, and team are allowed (trial counters checked separately for trial)
        return True, None, subscription_status
        
    except RuntimeError:
        # Re-raise hard errors from get_tenant_billing
        raise
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
    Reads from tenant_billing table (single source of truth).
    
    Args:
        db: Database session
        tenant_id: Tenant UUID string
        agent: Agent name ('requirements_ba', 'test_plan', 'jira_writeback')
        
    Returns:
        Tuple of (allowed: bool, reason: Optional[str], remaining: Optional[int])
        
    Raises:
        RuntimeError: If tenant_billing row is missing (hard error)
    """
    try:
        billing = get_tenant_billing(db, tenant_id)
        subscription_status = billing.get("subscription_status", "unselected")
        
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
        
        remaining = billing.get(counter_field, 0)
        
        if remaining <= 0:
            return False, f"TRIAL_EXHAUSTED (agent={agent}, remaining={remaining})", 0
        
        return True, None, remaining
        
    except RuntimeError:
        # Re-raise hard errors from get_tenant_billing
        raise
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
    seat_allowed, seat_reason, current_seats, seat_cap = check_seat_cap(db, tenant_id)
    metadata["current_seats"] = current_seats
    metadata["seat_cap"] = seat_cap or PLAN_TIERS.get(plan_tier, PLAN_TIERS["free"])["seat_cap"]
    
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
