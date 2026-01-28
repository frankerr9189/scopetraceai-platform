"""
Centralized entitlement helper for BA Agent.
Minimal implementation - only get_tenant_billing function.
"""
import logging
import uuid
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import text

logger = logging.getLogger(__name__)


def get_tenant_billing(db: Session, tenant_id: str) -> Dict[str, Any]:
    """
    Get billing data for a tenant from tenant_billing table (single source of truth).
    
    Args:
        db: Database session
        tenant_id: Tenant UUID string
        
    Returns:
        Dict with billing data:
        - subscription_status: Mapped from tenant_billing.status
        - plan_tier: Plan tier from tenant_billing
        - current_period_start: Stripe period start (datetime or None)
        - current_period_end: Stripe period end (datetime or None)
        - trial_requirements_runs_remaining: Trial runs remaining
        - trial_testplan_runs_remaining: Trial runs remaining
        - trial_writeback_runs_remaining: Trial runs remaining
        
    Raises:
        RuntimeError: If tenant_billing row is missing or query fails
    """
    try:
        tenant_uuid = tenant_id if isinstance(tenant_id, uuid.UUID) else uuid.UUID(tenant_id)
        
        # Query tenant_billing table (single source of truth)
        # Join with tenants table to get trial counters
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
            error_msg = f"tenant_billing row not found for tenant_id={tenant_id}"
            logger.error(error_msg)
            raise RuntimeError(error_msg)
        
        # Map tenant_billing.status (Stripe status) to subscription_status
        billing_status = result.status
        subscription_status = _map_billing_status_to_subscription_status(billing_status)
        
        # If status is "active" from Stripe, determine if it's individual or team based on plan_tier
        if subscription_status == "active":
            plan_tier = result.plan_tier or ""
            if plan_tier.lower() in ["solo", "individual"]:
                subscription_status = "individual"
            elif plan_tier.lower() in ["team", "business", "pro", "enterprise"]:
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


def _map_billing_status_to_subscription_status(billing_status: Optional[str]) -> str:
    """
    Map tenant_billing.status (Stripe status values) to subscription_status values.
    
    Stripe statuses: trialing, active, past_due, canceled, unpaid, incomplete, etc.
    Our subscription_status: trial, individual, team, paywalled, canceled, unselected, active
    
    Args:
        billing_status: Stripe status from tenant_billing.status
        
    Returns:
        subscription_status value
    """
    if not billing_status:
        return "unselected"
    
    status_lower = billing_status.lower()
    
    # Map Stripe statuses to our subscription_status
    if status_lower in ["trialing"]:
        return "trial"
    elif status_lower in ["active"]:
        return "active"  # Will be refined by plan_tier
    elif status_lower in ["past_due", "unpaid"]:
        return "paywalled"
    elif status_lower in ["canceled", "cancelled"]:
        return "canceled"
    elif status_lower in ["incomplete", "incomplete_expired"]:
        return "unselected"
    else:
        logger.warning(f"Unknown billing_status '{billing_status}', defaulting to 'unselected'")
        return "unselected"
