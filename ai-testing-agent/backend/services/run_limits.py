"""
Run limit enforcement service.

This module enforces run limits per period based on plan tier.
Uses tenant_usage table to track runs_used and runs_limit per period.
"""
import logging
from typing import Tuple, Optional, Dict, Any
from datetime import datetime, timezone, timedelta
from calendar import monthrange
from sqlalchemy.orm import Session
from sqlalchemy import text
import uuid

logger = logging.getLogger(__name__)

# Locked run limits per plan tier
RUN_LIMITS = {
    "trial": 3,
    "individual": 20,
    "team": 75,
    "pro": 200,
    "enterprise": 1000000,  # Effectively unlimited (very high limit)
}

# Default limit for unknown tiers
DEFAULT_RUN_LIMIT = 0


def get_runs_limit_for_plan_tier(plan_tier: Optional[str]) -> int:
    """
    Get runs_limit for a plan_tier.
    
    Args:
        plan_tier: Plan tier value (trial, individual, team, pro, enterprise)
        
    Returns:
        runs_limit: Integer limit for the plan tier
    """
    if not plan_tier:
        return DEFAULT_RUN_LIMIT
    
    plan_tier_lower = plan_tier.lower()
    return RUN_LIMITS.get(plan_tier_lower, DEFAULT_RUN_LIMIT)


def compute_usage_period(
    current_period_start: Optional[datetime],
    current_period_end: Optional[datetime],
    now: Optional[datetime] = None
) -> Tuple[datetime, datetime]:
    """
    Compute the current usage period for a tenant.
    
    Prefers Stripe-driven current_period_start/current_period_end when present.
    Falls back to calendar month boundaries (1st -> last day) for trial/unselected.
    
    Args:
        current_period_start: Stripe period start (from tenant_billing)
        current_period_end: Stripe period end (from tenant_billing)
        now: Current datetime (defaults to now in UTC)
        
    Returns:
        Tuple of (period_start, period_end) as datetime objects
    """
    if now is None:
        now = datetime.now(timezone.utc)
    
    # Prefer Stripe period if available
    if current_period_start and current_period_end:
        # Ensure timezone-aware
        if current_period_start.tzinfo is None:
            current_period_start = current_period_start.replace(tzinfo=timezone.utc)
        if current_period_end.tzinfo is None:
            current_period_end = current_period_end.replace(tzinfo=timezone.utc)
        
        # Check if now is within the Stripe period
        if current_period_start <= now < current_period_end:
            return current_period_start, current_period_end
        # If period has ended, use calendar month fallback
        # (Stripe will update on next webhook)
    
    # Fallback: Calendar month boundaries (1st -> last day of month)
    period_start = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
    last_day = monthrange(now.year, now.month)[1]
    period_end = datetime(now.year, now.month, last_day, 23, 59, 59, 999999, tzinfo=timezone.utc)
    
    return period_start, period_end


def get_tenant_usage(
    db: Session,
    tenant_id: str,
    period_start: datetime,
    period_end: datetime
) -> Optional[Dict[str, Any]]:
    """
    Get tenant_usage row for a tenant and period.
    
    Args:
        db: Database session
        tenant_id: Tenant UUID string
        period_start: Period start datetime
        period_end: Period end datetime
        
    Returns:
        Dict with runs_used, runs_limit, or None if not found
    """
    try:
        tenant_uuid = tenant_id if isinstance(tenant_id, uuid.UUID) else uuid.UUID(tenant_id)
        
        result = db.execute(
            text("""
                SELECT runs_used, runs_limit
                FROM tenant_usage
                WHERE tenant_id = :tenant_id
                  AND period_start = :period_start
                  AND period_end = :period_end
            """),
            {
                "tenant_id": str(tenant_uuid),
                "period_start": period_start,
                "period_end": period_end
            }
        ).first()
        
        if result:
            return {
                "runs_used": result.runs_used,
                "runs_limit": result.runs_limit
            }
        return None
    except Exception as e:
        logger.error(f"Error getting tenant_usage for tenant_id={tenant_id}: {str(e)}", exc_info=True)
        raise


def upsert_tenant_usage(
    db: Session,
    tenant_id: str,
    period_start: datetime,
    period_end: datetime,
    runs_limit: int
) -> None:
    """
    Upsert tenant_usage row with correct runs_limit.
    
    Args:
        db: Database session
        tenant_id: Tenant UUID string
        period_start: Period start datetime
        period_end: Period end datetime
        runs_limit: Runs limit for this period
    """
    try:
        tenant_uuid = tenant_id if isinstance(tenant_id, uuid.UUID) else uuid.UUID(tenant_id)
        
        db.execute(
            text("""
                INSERT INTO tenant_usage (tenant_id, period_start, period_end, runs_used, runs_limit)
                VALUES (:tenant_id, :period_start, :period_end, 0, :runs_limit)
                ON CONFLICT (tenant_id, period_start, period_end)
                DO UPDATE SET
                    runs_limit = EXCLUDED.runs_limit
                WHERE tenant_usage.runs_limit != EXCLUDED.runs_limit
            """),
            {
                "tenant_id": str(tenant_uuid),
                "period_start": period_start,
                "period_end": period_end,
                "runs_limit": runs_limit
            }
        )
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Error upserting tenant_usage for tenant_id={tenant_id}: {str(e)}", exc_info=True)
        raise


def increment_run_usage_atomic(
    db: Session,
    tenant_id: str,
    period_start: datetime,
    period_end: datetime
) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Atomically increment runs_used if under limit.
    
    Uses a single SQL UPDATE with a guard (runs_used < runs_limit) to ensure
    atomicity and prevent race conditions.
    
    Args:
        db: Database session
        tenant_id: Tenant UUID string
        period_start: Period start datetime
        period_end: Period end datetime
        
    Returns:
        Tuple of (success: bool, usage_data: Optional[Dict])
        - success: True if increment succeeded, False if limit reached
        - usage_data: Dict with runs_used, runs_limit, period_start, period_end if available
    """
    try:
        tenant_uuid = tenant_id if isinstance(tenant_id, uuid.UUID) else uuid.UUID(tenant_id)
        
        # Atomic increment with limit check
        result = db.execute(
            text("""
                UPDATE tenant_usage
                SET runs_used = runs_used + 1
                WHERE tenant_id = :tenant_id
                  AND period_start = :period_start
                  AND period_end = :period_end
                  AND runs_used < runs_limit
                RETURNING runs_used, runs_limit
            """),
            {
                "tenant_id": str(tenant_uuid),
                "period_start": period_start,
                "period_end": period_end
            }
        ).first()
        
        if result:
            # Increment succeeded
            db.commit()
            return True, {
                "runs_used": result.runs_used,
                "runs_limit": result.runs_limit,
                "period_start": period_start.isoformat(),
                "period_end": period_end.isoformat()
            }
        else:
            # Limit reached or row not found
            db.rollback()
            
            # Get current usage for error response
            usage = get_tenant_usage(db, tenant_id, period_start, period_end)
            if usage:
                return False, {
                    "runs_used": usage["runs_used"],
                    "runs_limit": usage["runs_limit"],
                    "period_start": period_start.isoformat(),
                    "period_end": period_end.isoformat()
                }
            else:
                # Row missing (should not happen after upsert)
                logger.error(f"tenant_usage row missing after upsert for tenant_id={tenant_id}")
                return False, None
                
    except Exception as e:
        db.rollback()
        logger.error(f"Error incrementing run usage for tenant_id={tenant_id}: {str(e)}", exc_info=True)
        raise


def check_and_increment_run_usage(
    db: Session,
    tenant_id: str,
    plan_tier: Optional[str],
    current_period_start: Optional[datetime] = None,
    current_period_end: Optional[datetime] = None
) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
    """
    Check run limit and atomically increment if allowed.
    
    This is the main entry point for run limit enforcement.
    
    Args:
        db: Database session
        tenant_id: Tenant UUID string
        plan_tier: Plan tier from tenant_billing
        current_period_start: Stripe period start (optional)
        current_period_end: Stripe period end (optional)
        
    Returns:
        Tuple of (allowed: bool, error_code: Optional[str], usage_data: Optional[Dict])
        - allowed: True if run can proceed, False if limit reached
        - error_code: "RUN_LIMIT_REACHED" if limit reached, None otherwise
        - usage_data: Dict with runs_used, runs_limit, period_start, period_end
    """
    try:
        # Get runs_limit for plan tier
        runs_limit = get_runs_limit_for_plan_tier(plan_tier)
        
        # Compute usage period
        period_start, period_end = compute_usage_period(current_period_start, current_period_end)
        
        # Upsert tenant_usage row if missing
        upsert_tenant_usage(db, tenant_id, period_start, period_end, runs_limit)
        
        # Atomically increment runs_used
        success, usage_data = increment_run_usage_atomic(db, tenant_id, period_start, period_end)
        
        if success:
            return True, None, usage_data
        else:
            return False, "RUN_LIMIT_REACHED", usage_data
            
    except Exception as e:
        logger.error(f"Error in check_and_increment_run_usage for tenant_id={tenant_id}: {str(e)}", exc_info=True)
        # Fail closed: deny on error
        return False, "RUN_LIMIT_CHECK_ERROR", None


def get_tenant_usage_for_ui(
    db: Session,
    tenant_id: str,
    plan_tier: Optional[str],
    current_period_start: Optional[datetime] = None,
    current_period_end: Optional[datetime] = None
) -> Dict[str, Any]:
    """
    Get current usage data for UI display.
    
    Args:
        db: Database session
        tenant_id: Tenant UUID string
        plan_tier: Plan tier from tenant_billing
        current_period_start: Stripe period start (optional)
        current_period_end: Stripe period end (optional)
        
    Returns:
        Dict with runs_used, runs_limit, period_start, period_end
    """
    try:
        # Get runs_limit for plan tier
        runs_limit = get_runs_limit_for_plan_tier(plan_tier)
        
        # Compute usage period
        period_start, period_end = compute_usage_period(current_period_start, current_period_end)
        
        # Get current usage
        usage = get_tenant_usage(db, tenant_id, period_start, period_end)
        
        if usage:
            return {
                "runs_used": usage["runs_used"],
                "runs_limit": runs_limit,
                "period_start": period_start.isoformat(),
                "period_end": period_end.isoformat()
            }
        else:
            # No usage row yet (no runs this period)
            return {
                "runs_used": 0,
                "runs_limit": runs_limit,
                "period_start": period_start.isoformat(),
                "period_end": period_end.isoformat()
            }
    except Exception as e:
        logger.error(f"Error getting tenant usage for UI for tenant_id={tenant_id}: {str(e)}", exc_info=True)
        # Return safe defaults
        return {
            "runs_used": 0,
            "runs_limit": 0,
            "period_start": None,
            "period_end": None
        }
