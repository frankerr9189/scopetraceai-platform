"""
Entitlement checking and trial consumption for tenant subscription management.
"""
import logging
import sys
import os
import uuid
from typing import Tuple, Optional
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def check_entitlement(db: Session, tenant_id: str) -> Tuple[bool, Optional[str], Optional[str], Optional[int]]:
    """
    Check if tenant is allowed to run a requirements generation.
    
    Args:
        db: SQLAlchemy database session
        tenant_id: Tenant UUID string
        
    Returns:
        Tuple of (allowed: bool, reason: Optional[str], subscription_status: Optional[str], remaining: Optional[int])
        - allowed: True if run is allowed, False if blocked
        - reason: Error reason if blocked (e.g., "PAYWALLED", "TRIAL_EXHAUSTED")
        - subscription_status: Current subscription status ("Trial", "Active", "Paywalled")
        - remaining: Number of trial runs remaining (None if not Trial or Active)
        
    Raises:
        Exception: If database error, UUID conversion error, or tenant not found (fail-closed by default).
                   Only fails open if ENTITLEMENT_FAIL_OPEN=true env var is set.
    """
    try:
        # Import Tenant model from testing agent backend
        # The db session is from the testing agent backend, so we need to import from there
        # The caller (analyze.py) should have set up the path and changed directory,
        # but we'll ensure the path is set up here as well for robustness
        current_file = os.path.abspath(__file__)
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
        backend_path = os.path.join(project_root, "ai-testing-agent", "backend")
        
        # Ensure backend path is in sys.path
        if backend_path not in sys.path:
            sys.path.insert(0, backend_path)
        
        # Clear cached models module to force fresh import (but be careful not to break other imports)
        modules_to_clear = [k for k in sys.modules.keys() if k == 'models' or k.startswith('models.')]
        for mod in modules_to_clear:
            try:
                del sys.modules[mod]
            except KeyError:
                pass
        
        # Import Tenant - this should work now that path is set up
        try:
            from models import Tenant
        except ImportError as import_err:
            logger.error(f"Failed to import Tenant model from {backend_path}: {str(import_err)}")
            logger.error(f"Current sys.path: {sys.path[:3]}...")
            raise
        
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
        
        subscription_status = getattr(tenant, "subscription_status", "Trial")
        trial_remaining = getattr(tenant, "trial_requirements_runs_remaining", 3)
        
        if subscription_status == "Paywalled":
            logger.info(f"Tenant {tenant_id} blocked: subscription_status=Paywalled, remaining={trial_remaining}")
            return False, "PAYWALLED", subscription_status, trial_remaining
        
        if subscription_status == "Trial":
            if trial_remaining <= 0:
                logger.info(f"Tenant {tenant_id} blocked: Trial exhausted (remaining={trial_remaining})")
                return False, "TRIAL_EXHAUSTED", subscription_status, 0
            else:
                logger.info(f"Tenant {tenant_id} allowed: Trial (remaining={trial_remaining})")
                return True, None, subscription_status, trial_remaining
        
        if subscription_status == "Active":
            logger.info(f"Tenant {tenant_id} allowed: Active subscription")
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


def consume_trial_run(db: Session, tenant_id: str) -> None:
    """
    Consume one trial requirements run for the tenant.
    Decrements trial_requirements_runs_remaining by 1.
    If all three counters (requirements, testplan, writeback) reach 0, sets subscription_status='Paywalled'.
    
    Uses a database transaction to ensure atomicity.
    
    Args:
        db: SQLAlchemy database session
        tenant_id: Tenant UUID string
        
    Raises:
        Exception: If tenant not found or database error occurs
    """
    try:
        # Import Tenant model from testing agent backend
        # The db session is from the testing agent backend, so we need to import from there
        # The caller (analyze.py) should have set up the path and changed directory,
        # but we'll ensure the path is set up here as well for robustness
        current_file = os.path.abspath(__file__)
        # Path: app/services/entitlements.py -> app -> ai-sr-business-req-analyst -> appscopetraceai -> ai-testing-agent/backend
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
        backend_path = os.path.join(project_root, "ai-testing-agent", "backend")
        
        # Ensure backend path is in sys.path
        if backend_path not in sys.path:
            sys.path.insert(0, backend_path)
        
        # Clear cached models module to force fresh import (but be careful not to break other imports)
        modules_to_clear = [k for k in sys.modules.keys() if k == 'models' or k.startswith('models.')]
        for mod in modules_to_clear:
            try:
                del sys.modules[mod]
            except KeyError:
                pass
        
        # Import Tenant - this should work now that path is set up
        try:
            from models import Tenant
        except ImportError as import_err:
            logger.error(f"Failed to import Tenant model from {backend_path}: {str(import_err)}")
            logger.error(f"Current sys.path: {sys.path[:3]}...")
            raise
        
        from sqlalchemy import text
        
        # Start transaction (SQLAlchemy auto-commits on commit(), but we'll be explicit)
        # Convert string tenant_id to UUID if needed
        tenant_uuid = tenant_id if isinstance(tenant_id, uuid.UUID) else uuid.UUID(tenant_id)
        tenant = db.query(Tenant).filter(Tenant.id == tenant_uuid).with_for_update().first()
        if not tenant:
            raise ValueError(f"Tenant not found: {tenant_id}")
        
        subscription_status = getattr(tenant, "subscription_status", "Trial")
        trial_requirements = getattr(tenant, "trial_requirements_runs_remaining", 3)
        trial_testplan = getattr(tenant, "trial_testplan_runs_remaining", 3)
        trial_writeback = getattr(tenant, "trial_writeback_runs_remaining", 3)
        
        # Only decrement if in Trial status
        if subscription_status == "Trial":
            if trial_requirements > 0:
                new_requirements = trial_requirements - 1
                tenant.trial_requirements_runs_remaining = new_requirements
                
                # Check if all three counters are now 0
                if new_requirements == 0 and trial_testplan == 0 and trial_writeback == 0:
                    tenant.subscription_status = "Paywalled"
                    logger.info(
                        f"Tenant {tenant_id}: All trial counters exhausted. "
                        f"Set subscription_status=Paywalled. "
                        f"Remaining: requirements={new_requirements}, testplan={trial_testplan}, writeback={trial_writeback}"
                    )
                else:
                    logger.info(
                        f"Tenant {tenant_id}: Decremented trial_requirements_runs_remaining "
                        f"({trial_requirements} -> {new_requirements}). "
                        f"Remaining: requirements={new_requirements}, testplan={trial_testplan}, writeback={trial_writeback}"
                    )
                
                db.commit()
            else:
                logger.warning(f"Tenant {tenant_id}: Attempted to consume trial run but remaining={trial_requirements}")
        else:
            logger.info(f"Tenant {tenant_id}: Not in Trial status (status={subscription_status}), skipping decrement")
            
    except Exception as e:
        db.rollback()
        logger.error(f"Error consuming trial run for tenant {tenant_id}: {str(e)}", exc_info=True)
        raise
