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


def compute_current_period_key(
    current_period_start: Optional[datetime],
    current_period_end: Optional[datetime],
    now: Optional[datetime] = None
) -> str:
    """
    Compute a deterministic period_key for tenant_usage lookups.
    
    Uses format "YYYY-MM" for calendar months, or "YYYY-MM-DD_YYYY-MM-DD" for Stripe periods.
    This eliminates timestamp precision mismatches between upsert and increment operations.
    
    Args:
        current_period_start: Stripe period start (from tenant_billing)
        current_period_end: Stripe period end (from tenant_billing)
        now: Current datetime (defaults to now in UTC)
        
    Returns:
        period_key: String key like "2026-01" or "2026-01-15_2026-02-15"
    """
    if now is None:
        now = datetime.now(timezone.utc)
    
    # Prefer Stripe period if available and current
    if current_period_start and current_period_end:
        # Ensure timezone-aware
        if current_period_start.tzinfo is None:
            current_period_start = current_period_start.replace(tzinfo=timezone.utc)
        if current_period_end.tzinfo is None:
            current_period_end = current_period_end.replace(tzinfo=timezone.utc)
        
        # Check if now is within the Stripe period
        if current_period_start <= now < current_period_end:
            # Use full period range for Stripe periods
            return f"{current_period_start.strftime('%Y-%m-%d')}_{current_period_end.strftime('%Y-%m-%d')}"
        # If period has ended, fall through to calendar month
    
    # Fallback: Calendar month boundaries (YYYY-MM format)
    return now.strftime('%Y-%m')


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
    period_key: str
) -> Optional[Dict[str, Any]]:
    """
    Get tenant_usage row for a tenant and period_key.
    
    Args:
        db: Database session
        tenant_id: Tenant UUID string
        period_key: Period key (e.g., "2026-01" or "2026-01-15_2026-02-15")
        
    Returns:
        Dict with runs_used, runs_limit, or None if not found
    """
    try:
        tenant_uuid = tenant_id if isinstance(tenant_id, uuid.UUID) else uuid.UUID(tenant_id)
        
        result = db.execute(
            text("""
                SELECT runs_used, runs_limit, period_start, period_end
                FROM tenant_usage
                WHERE tenant_id = :tenant_id
                  AND period_key = :period_key
            """),
            {
                "tenant_id": str(tenant_uuid),
                "period_key": period_key
            }
        ).first()
        
        if result:
            return {
                "runs_used": result.runs_used,
                "runs_limit": result.runs_limit,
                "period_start": result.period_start.isoformat() if result.period_start else None,
                "period_end": result.period_end.isoformat() if result.period_end else None
            }
        return None
    except Exception as e:
        logger.error(f"Error getting tenant_usage for tenant_id={tenant_id} period_key={period_key}: {str(e)}", exc_info=True)
        raise


def upsert_tenant_usage(
    db: Session,
    tenant_id: str,
    period_key: str,
    period_start: datetime,
    period_end: datetime,
    runs_limit: int
) -> None:
    """
    Upsert tenant_usage row with correct runs_limit.
    
    Uses period_key for deterministic lookups and ensures row always exists after call.
    
    Args:
        db: Database session
        tenant_id: Tenant UUID string
        period_key: Period key (e.g., "2026-01" or "2026-01-15_2026-02-15")
        period_start: Period start datetime
        period_end: Period end datetime
        runs_limit: Runs limit for this period
        
    Raises:
        RuntimeError: If upsert fails to create/return a row (should never happen)
    """
    try:
        tenant_uuid = tenant_id if isinstance(tenant_id, uuid.UUID) else uuid.UUID(tenant_id)
        
        # Upsert with RETURNING to verify row exists
        result = db.execute(
            text("""
                INSERT INTO tenant_usage (tenant_id, period_key, period_start, period_end, runs_used, runs_limit)
                VALUES (:tenant_id, :period_key, :period_start, :period_end, 0, :runs_limit)
                ON CONFLICT (tenant_id, period_key)
                DO UPDATE SET
                    runs_limit = EXCLUDED.runs_limit,
                    updated_at = NOW()
                WHERE tenant_usage.runs_limit != EXCLUDED.runs_limit
                RETURNING tenant_id, period_key, runs_used, runs_limit
            """),
            {
                "tenant_id": str(tenant_uuid),
                "period_key": period_key,
                "period_start": period_start,
                "period_end": period_end,
                "runs_limit": runs_limit
            }
        ).first()
        
        # Verify row was created/updated
        if not result:
            # This should never happen, but check if row exists anyway
            existing = db.execute(
                text("""
                    SELECT tenant_id, period_key
                    FROM tenant_usage
                    WHERE tenant_id = :tenant_id AND period_key = :period_key
                """),
                {
                    "tenant_id": str(tenant_uuid),
                    "period_key": period_key
                }
            ).first()
            
            if existing:
                # Row exists but RETURNING didn't return it (runs_limit already matched)
                # This is fine - row exists with correct limit
                logger.debug(f"tenant_usage row exists for tenant_id={tenant_id} period_key={period_key} (runs_limit already correct)")
            else:
                # Row missing after upsert - this is a critical error
                error_msg = f"USAGE_ROW_MISSING: tenant_usage row missing after upsert for tenant_id={tenant_id} period_key={period_key}"
                logger.error(error_msg)
                db.rollback()
                raise RuntimeError(error_msg)
        
        db.commit()
    except RuntimeError:
        # Re-raise our custom error
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Error upserting tenant_usage for tenant_id={tenant_id} period_key={period_key}: {str(e)}", exc_info=True)
        raise


def is_owner_user(
    db: Session,
    tenant_id: str,
    user_id: str
) -> bool:
    """
    Check if a user has owner role for the given tenant.
    
    Queries database to ensure role is current (not from stale JWT claim).
    
    Args:
        db: Database session
        tenant_id: Tenant UUID string
        user_id: User UUID string
        
    Returns:
        True if user is owner and active, False otherwise
    """
    try:
        tenant_uuid = tenant_id if isinstance(tenant_id, uuid.UUID) else uuid.UUID(tenant_id)
        user_uuid = user_id if isinstance(user_id, uuid.UUID) else uuid.UUID(user_id)
        
        result = db.execute(
            text("""
                SELECT role
                FROM tenant_users
                WHERE tenant_id = :tenant_id
                  AND id = :user_id
                  AND is_active = true
                LIMIT 1
            """),
            {
                "tenant_id": str(tenant_uuid),
                "user_id": str(user_uuid)
            }
        ).first()
        
        if result and result.role == "owner":
            return True
        return False
    except Exception as e:
        logger.error(f"Error checking owner role for tenant_id={tenant_id} user_id={user_id}: {str(e)}", exc_info=True)
        # Fail safe: if we can't verify, don't grant bypass
        return False


def increment_run_usage_atomic(
    db: Session,
    tenant_id: str,
    period_key: str,
    bypass_limit: bool = False
) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
    """
    Atomically increment runs_used if under limit (or if bypass_limit is True).
    
    Uses a single SQL UPDATE with a guard (runs_used < runs_limit) to ensure
    atomicity and prevent race conditions. If bypass_limit is True, increments
    without the limit check.
    
    Args:
        db: Database session
        tenant_id: Tenant UUID string
        period_key: Period key (e.g., "2026-01" or "2026-01-15_2026-02-15")
        bypass_limit: If True, increment without limit check (for owner bypass)
        
    Returns:
        Tuple of (success: bool, error_code: Optional[str], usage_data: Optional[Dict])
        - success: True if increment succeeded, False if limit reached or row missing
        - error_code: "RUN_LIMIT_REACHED" if limit reached, "USAGE_ROW_MISSING" if row missing, None if success
        - usage_data: Dict with runs_used, runs_limit, period_start, period_end if available
    """
    try:
        tenant_uuid = tenant_id if isinstance(tenant_id, uuid.UUID) else uuid.UUID(tenant_id)
        
        if bypass_limit:
            # Owner bypass: increment without limit check
            result = db.execute(
                text("""
                    UPDATE tenant_usage
                    SET runs_used = runs_used + 1
                    WHERE tenant_id = :tenant_id
                      AND period_key = :period_key
                    RETURNING runs_used, runs_limit, period_start, period_end
                """),
                {
                    "tenant_id": str(tenant_uuid),
                    "period_key": period_key
                }
            ).first()
            
            if result:
                # Increment succeeded
                db.commit()
                return True, None, {
                    "runs_used": result.runs_used,
                    "runs_limit": result.runs_limit,
                    "period_start": result.period_start.isoformat() if result.period_start else None,
                    "period_end": result.period_end.isoformat() if result.period_end else None
                }
            else:
                # Row missing (should not happen after upsert)
                db.rollback()
                error_code = "USAGE_ROW_MISSING"
                logger.error(f"{error_code}: tenant_usage row missing for tenant_id={tenant_id} period_key={period_key} after upsert (owner bypass)")
                return False, error_code, None
        else:
            # Normal path: atomic increment with limit check
            result = db.execute(
                text("""
                    UPDATE tenant_usage
                    SET runs_used = runs_used + 1
                    WHERE tenant_id = :tenant_id
                      AND period_key = :period_key
                      AND runs_used < runs_limit
                    RETURNING runs_used, runs_limit, period_start, period_end
                """),
                {
                    "tenant_id": str(tenant_uuid),
                    "period_key": period_key
                }
            ).first()
            
            if result:
                # Increment succeeded
                db.commit()
                return True, None, {
                    "runs_used": result.runs_used,
                    "runs_limit": result.runs_limit,
                    "period_start": result.period_start.isoformat() if result.period_start else None,
                    "period_end": result.period_end.isoformat() if result.period_end else None
                }
            else:
                # UPDATE affected 0 rows - need to determine why
                db.rollback()
                
                # Check if row exists
                usage = get_tenant_usage(db, tenant_id, period_key)
                if usage:
                    # Row exists but limit was reached (runs_used >= runs_limit)
                    logger.info(f"RUN_LIMIT_REACHED: tenant_id={tenant_id} period_key={period_key} runs_used={usage['runs_used']} runs_limit={usage['runs_limit']}")
                    return False, "RUN_LIMIT_REACHED", usage
                else:
                    # Row missing (should not happen after upsert)
                    error_code = "USAGE_ROW_MISSING"
                    logger.error(f"{error_code}: tenant_usage row missing for tenant_id={tenant_id} period_key={period_key} after upsert")
                    return False, error_code, None
                
    except Exception as e:
        db.rollback()
        logger.error(f"Error incrementing run usage for tenant_id={tenant_id} period_key={period_key} bypass_limit={bypass_limit}: {str(e)}", exc_info=True)
        raise


def check_and_increment_run_usage(
    db: Session,
    tenant_id: str,
    plan_tier: Optional[str],
    current_period_start: Optional[datetime] = None,
    current_period_end: Optional[datetime] = None,
    user_id: Optional[str] = None
) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
    """
    Check run limit and atomically increment if allowed.
    
    This is the main entry point for run limit enforcement.
    
    Owner users (role == "owner") bypass run limits but usage is still tracked.
    
    Args:
        db: Database session
        tenant_id: Tenant UUID string
        plan_tier: Plan tier from tenant_billing
        current_period_start: Stripe period start (optional)
        current_period_end: Stripe period end (optional)
        user_id: User UUID string (optional, used for owner bypass check)
        
    Returns:
        Tuple of (allowed: bool, error_code: Optional[str], usage_data: Optional[Dict])
        - allowed: True if run can proceed, False if limit reached or error
        - error_code: "RUN_LIMIT_REACHED", "USAGE_ROW_MISSING", "RUN_LIMIT_CHECK_ERROR", or None
        - usage_data: Dict with runs_used, runs_limit, period_start, period_end
    """
    try:
        # Get runs_limit for plan tier
        runs_limit = get_runs_limit_for_plan_tier(plan_tier)
        
        # Compute deterministic period_key (used for all lookups)
        period_key = compute_current_period_key(current_period_start, current_period_end)
        
        # Compute period boundaries (for storage)
        period_start, period_end = compute_usage_period(current_period_start, current_period_end)
        
        # Upsert tenant_usage row if missing (ensures row exists)
        upsert_tenant_usage(db, tenant_id, period_key, period_start, period_end, runs_limit)
        
        # Check if user is owner (bypass run limits)
        owner_bypass = False
        if user_id:
            owner_bypass = is_owner_user(db, tenant_id, user_id)
            if owner_bypass:
                logger.info(f"OWNER_BYPASS: user_id={user_id} tenant_id={tenant_id} - run limit bypassed (role=owner)")
        
        # Atomically increment runs_used (with or without limit check based on owner_bypass)
        success, increment_error_code, usage_data = increment_run_usage_atomic(
            db, tenant_id, period_key, bypass_limit=owner_bypass
        )
        
        if success:
            # Add bypass metadata to usage_data for logging
            if owner_bypass and usage_data:
                usage_data["bypassed_limits"] = True
                usage_data["bypass_reason"] = "ROLE_OWNER"
            return True, None, usage_data
        else:
            # Return the specific error code from increment
            return False, increment_error_code, usage_data
            
    except RuntimeError as e:
        # Upsert failed to create row (critical error)
        error_code = "USAGE_ROW_MISSING"
        logger.error(f"{error_code} in check_and_increment_run_usage for tenant_id={tenant_id}: {str(e)}", exc_info=True)
        return False, error_code, None
    except Exception as e:
        logger.error(f"RUN_LIMIT_CHECK_ERROR in check_and_increment_run_usage for tenant_id={tenant_id}: {str(e)}", exc_info=True)
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
        
        # Compute deterministic period_key
        period_key = compute_current_period_key(current_period_start, current_period_end)
        
        # Compute period boundaries (for display)
        period_start, period_end = compute_usage_period(current_period_start, current_period_end)
        
        # Get current usage
        usage = get_tenant_usage(db, tenant_id, period_key)
        
        if usage:
            return {
                "runs_used": usage["runs_used"],
                "runs_limit": runs_limit,
                "period_start": usage.get("period_start") or period_start.isoformat(),
                "period_end": usage.get("period_end") or period_end.isoformat()
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
