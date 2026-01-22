"""
Entitlement checking and trial consumption for tenant subscription management.
"""
import logging
import os
import uuid
from typing import Tuple, Optional
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def check_entitlement(db: Session, tenant_id: str) -> Tuple[bool, Optional[str], Optional[str], Optional[int]]:
    """
    Check if tenant is allowed to run a test plan generation.
    
    Args:
        db: SQLAlchemy database session
        tenant_id: Tenant UUID string
        
    Returns:
        Tuple of (allowed: bool, reason: Optional[str], subscription_status: Optional[str], remaining: Optional[int])
        - allowed: True if run is allowed, False if blocked
        - reason: Error reason if blocked (e.g., "PAYWALLED", "TRIAL_EXHAUSTED")
        - subscription_status: Current subscription status ("trial", "individual", "team", "paywalled", "canceled", "unselected")
        - remaining: Number of trial testplan runs remaining (None if not trial)
        
    Raises:
        Exception: If database error, UUID conversion error, or tenant not found (fail-closed by default).
                   Only fails open if ENTITLEMENT_FAIL_OPEN=true env var is set.
    """
    try:
        from models import Tenant
        
        # Convert string tenant_id to UUID if needed
        tenant_uuid = tenant_id if isinstance(tenant_id, uuid.UUID) else uuid.UUID(tenant_id)
        tenant = db.query(Tenant).filter(Tenant.id == tenant_uuid).first()
        if not tenant:
            error_msg = f"Tenant not found: {tenant_id}"
            logger.warning(error_msg)
            # Check fail-open escape hatch
            fail_open = os.getenv("ENTITLEMENT_FAIL_OPEN", "false").lower() == "true"
            if fail_open:
                logger.warning(f"ENTITLEMENT_FAIL_OPEN=true: Allowing request despite {error_msg}")
                return True, None, None, None
            raise ValueError(error_msg)
        
        # Get billing data from tenant_billing (single source of truth)
        from services.entitlements_centralized import get_tenant_billing
        billing = get_tenant_billing(db, tenant_id)
        subscription_status = billing.get("subscription_status", "unselected")
        trial_remaining = billing.get("trial_testplan_runs_remaining", 0)
        
        # Block paywalled and canceled
        if subscription_status == "paywalled":
            logger.info(f"Tenant {tenant_id} blocked: subscription_status=paywalled, remaining={trial_remaining}")
            return False, "PAYWALLED", subscription_status, trial_remaining
        
        if subscription_status == "canceled":
            logger.info(f"Tenant {tenant_id} blocked: subscription_status=canceled")
            return False, "SUBSCRIPTION_CANCELED", subscription_status, None
        
        # Block unselected (should be caught by middleware, but check here too)
        if subscription_status == "unselected":
            logger.info(f"Tenant {tenant_id} blocked: subscription_status=unselected")
            return False, "SUBSCRIPTION_UNSELECTED", subscription_status, None
        
        # Trial: check counters
        if subscription_status == "trial":
            if trial_remaining <= 0:
                logger.info(f"Tenant {tenant_id} blocked: Trial exhausted (remaining={trial_remaining})")
                return False, "TRIAL_EXHAUSTED", subscription_status, 0
            else:
                logger.info(f"Tenant {tenant_id} allowed: Trial (remaining={trial_remaining})")
                return True, None, subscription_status, trial_remaining
        
        # Individual and team: always allowed (no counter checks)
        if subscription_status in ["individual", "team"]:
            logger.info(f"Tenant {tenant_id} allowed: {subscription_status} subscription")
            return True, None, subscription_status, None
        
        # Unknown status - default to allow but log warning
        logger.warning(f"Tenant {tenant_id} has unknown subscription_status={subscription_status}, allowing")
        return True, None, subscription_status, None
        
    except Exception as e:
        logger.error(f"Error checking entitlement for tenant {tenant_id}: {str(e)}", exc_info=True)
        # Check fail-open escape hatch
        fail_open = os.getenv("ENTITLEMENT_FAIL_OPEN", "false").lower() == "true"
        if fail_open:
            logger.warning(f"ENTITLEMENT_FAIL_OPEN=true: Allowing request despite entitlement check error")
            return True, None, None, None
        # Fail closed by default - re-raise the exception
        raise


def consume_trial_run(db: Session, tenant_id: str, agent: str = "test_plan") -> None:
    """
    Consume one trial run for the tenant for the specified agent.
    
    This function preserves existing trial counter behavior:
    - Decrements the appropriate trial counter (requirements/testplan/writeback)
    - If all three counters reach 0, sets subscription_status='paywalled'
    
    Uses a database transaction to ensure atomicity.
    
    Args:
        db: SQLAlchemy database session
        tenant_id: Tenant UUID string
        agent: Agent name ('requirements_ba', 'test_plan', 'jira_writeback')
               Defaults to 'test_plan' for backward compatibility
        
    Raises:
        Exception: If tenant not found or database error occurs
    """
    try:
        from models import Tenant
        
        # Start transaction (SQLAlchemy auto-commits on commit(), but we'll be explicit)
        # Convert string tenant_id to UUID if needed
        tenant_uuid = tenant_id if isinstance(tenant_id, uuid.UUID) else uuid.UUID(tenant_id)
        tenant = db.query(Tenant).filter(Tenant.id == tenant_uuid).with_for_update().first()
        if not tenant:
            raise ValueError(f"Tenant not found: {tenant_id}")
        
        # Get billing data from tenant_billing (single source of truth)
        from services.entitlements_centralized import get_tenant_billing
        billing = get_tenant_billing(db, tenant_id)
        subscription_status = billing.get("subscription_status", "unselected")
        trial_requirements = billing.get("trial_requirements_runs_remaining", 0)
        trial_testplan = billing.get("trial_testplan_runs_remaining", 0)
        trial_writeback = billing.get("trial_writeback_runs_remaining", 0)
        
        # Only decrement if in trial status
        if subscription_status == "trial":
            # Map agent name to counter field
            counter_map = {
                "requirements_ba": ("trial_requirements_runs_remaining", trial_requirements),
                "test_plan": ("trial_testplan_runs_remaining", trial_testplan),
                "jira_writeback": ("trial_writeback_runs_remaining", trial_writeback)
            }
            
            counter_field, current_value = counter_map.get(agent, ("trial_testplan_runs_remaining", trial_testplan))
            
            if current_value > 0:
                new_value = current_value - 1
                setattr(tenant, counter_field, new_value)
                
                # Update other counters for the check
                if agent == "requirements_ba":
                    trial_requirements = new_value
                elif agent == "test_plan":
                    trial_testplan = new_value
                else:  # jira_writeback
                    trial_writeback = new_value
                
                # Check if all three counters are now 0
                if trial_requirements == 0 and trial_testplan == 0 and trial_writeback == 0:
                    # Update tenant_billing.status (single source of truth for billing)
                    from services.entitlements_centralized import update_tenant_billing_status
                    try:
                        update_tenant_billing_status(db, tenant_id, "paywalled")
                        logger.info(
                            f"Tenant {tenant_id}: All trial counters exhausted. "
                            f"Set tenant_billing.status=paywalled. "
                            f"Remaining: requirements={trial_requirements}, testplan={trial_testplan}, writeback={trial_writeback}"
                        )
                    except RuntimeError as e:
                        logger.error(f"Failed to update tenant_billing.status to paywalled: {e}")
                        # Continue - trial counters are already updated
                else:
                    logger.info(
                        f"Tenant {tenant_id}: Decremented {counter_field} "
                        f"({current_value} -> {new_value}) for agent={agent}. "
                        f"Remaining: requirements={trial_requirements}, testplan={trial_testplan}, writeback={trial_writeback}"
                    )
                
                db.commit()
            else:
                logger.warning(f"Tenant {tenant_id}: Attempted to consume trial run for agent={agent} but remaining={current_value}")
        else:
            logger.info(f"Tenant {tenant_id}: Not in trial status (status={subscription_status}), skipping decrement for agent={agent}")
            
    except Exception as e:
        db.rollback()
        logger.error(f"Error consuming trial run for tenant {tenant_id}, agent {agent}: {str(e)}", exc_info=True)
        raise
