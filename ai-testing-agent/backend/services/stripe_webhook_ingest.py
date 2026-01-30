"""
Stripe webhook event ingestion service.

This module handles the ingestion of Stripe webhook events into the stripe_events table.
It verifies Stripe signatures and handles idempotency via ON CONFLICT DO NOTHING.

Phase 2: Ingest-only (no billing updates).
Phase 4A: Handle checkout.session.completed to update tenant_billing.
Phase 4B.1: Handle customer.subscription.updated and customer.subscription.deleted.
Phase 4B.2: Handle invoice.payment_failed and invoice.payment_succeeded.
"""
import os
import json
import logging
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import text

try:
    import stripe
except ImportError:
    stripe = None
    logging.warning("stripe package not found. Webhook ingestion will fail.")


logger = logging.getLogger(__name__)


def _map_price_id_to_plan_tier(price_id: str) -> Optional[str]:
    """
    Map Stripe price_id to plan_tier using authoritative env vars.
    
    Args:
        price_id: Stripe price ID from subscription line items
        
    Returns:
        plan_tier: 'individual', 'team', or 'pro', or None if not found
    """
    if not price_id:
        return None
    
    # Map price_id to plan_tier using authoritative env vars
    price_to_tier = {
        os.getenv("STRIPE_PRICE_INDIVIDUAL"): "individual",
        os.getenv("STRIPE_PRICE_TEAM"): "team",
        os.getenv("STRIPE_PRICE_PRO"): "pro",
    }
    
    # Remove None values (env vars not set)
    price_to_tier = {k: v for k, v in price_to_tier.items() if k is not None}
    
    plan_tier = price_to_tier.get(price_id)
    return plan_tier


def _normalize_plan_tier(plan_tier: Optional[str]) -> Optional[str]:
    """
    Normalize legacy 'user' tier to 'individual'.
    
    Args:
        plan_tier: Plan tier value (may be 'user', 'individual', 'team', 'pro', etc.)
        
    Returns:
        Normalized plan_tier ('individual' if input was 'user', otherwise unchanged)
    """
    if plan_tier == "user":
        logger.warning(f"Normalizing legacy plan_tier 'user' to 'individual'")
        return "individual"
    return plan_tier


def _process_checkout_session_completed(event: Dict[str, Any], db: Session, event_id: str) -> None:
    """
    Process checkout.session.completed event to update tenant_billing.
    
    Phase 4A: Updates tenant_billing when a checkout session is completed.
    
    Args:
        event: Stripe event object (already verified)
        db: SQLAlchemy database session
        event_id: Stripe event ID for logging/updates
        
    Raises:
        Exception: If processing fails (will be caught and logged by caller)
    """
    if stripe is None:
        raise RuntimeError("stripe package not installed")
    
    # Get Stripe secret key
    stripe_secret_key = os.getenv("STRIPE_SECRET_KEY")
    if not stripe_secret_key:
        raise RuntimeError("STRIPE_SECRET_KEY environment variable not set")
    
    stripe.api_key = stripe_secret_key
    
    # Extract session data from event
    session = event.get("data", {}).get("object", {})
    if not session:
        raise ValueError("Missing session object in event data")
    
    # Extract metadata
    metadata = session.get("metadata", {})
    tenant_id = metadata.get("tenant_id")
    
    # Extract Stripe IDs
    stripe_customer_id = session.get("customer")
    stripe_subscription_id = session.get("subscription")
    
    # Validate required fields
    if not tenant_id:
        error_msg = "missing_metadata: tenant_id not found in session metadata"
        logger.warning(f"checkout.session.completed event {event_id}: {error_msg}")
        _mark_event_error(db, event_id, error_msg)
        return

    # Guardrail log: verify webhook writes use same schema as app (DB_SCHEMA + search_path)
    try:
        from db import get_db_schema
        current_schema = db.execute(text("SELECT current_schema()")).scalar()
        logger.info(
            "Stripe webhook guardrail: DB_SCHEMA=%s, current_schema()=%s, tenant_id=%s",
            get_db_schema(),
            current_schema,
            tenant_id,
        )
    except Exception as guardrail_err:
        logger.warning("Stripe webhook guardrail log failed: %s", guardrail_err)

    if not stripe_subscription_id:
        error_msg = "missing_metadata: subscription_id not found in session (not a subscription checkout)"
        logger.warning(f"checkout.session.completed event {event_id}: {error_msg}")
        _mark_event_error(db, event_id, error_msg)
        return
    
    # Retrieve Stripe subscription object
    try:
        subscription = stripe.Subscription.retrieve(stripe_subscription_id)
    except stripe.error.StripeError as e:
        error_msg = f"stripe_api_error: Failed to retrieve subscription {stripe_subscription_id}: {str(e)}"
        logger.error(f"checkout.session.completed event {event_id}: {error_msg}")
        _mark_event_error(db, event_id, error_msg)
        return
    
    # Extract price_id from subscription line items to determine plan_tier
    # Use first line item's price_id (subscriptions typically have one line item)
    line_items = subscription.get("items", {}).get("data", [])
    if not line_items:
        error_msg = "missing_line_items: subscription has no line items"
        logger.warning(f"checkout.session.completed event {event_id}: {error_msg}")
        _mark_event_error(db, event_id, error_msg)
        return
    
    price_id = line_items[0].get("price", {}).get("id")
    if not price_id:
        error_msg = "missing_price_id: line item has no price ID"
        logger.warning(f"checkout.session.completed event {event_id}: {error_msg}")
        _mark_event_error(db, event_id, error_msg)
        return
    
    # Map price_id to plan_tier using authoritative env vars
    plan_tier = _map_price_id_to_plan_tier(price_id)
    
    # Fallback to metadata if price_id mapping fails (backward compatibility)
    if not plan_tier:
        plan_tier = metadata.get("plan_tier")
        if plan_tier:
            logger.warning(f"checkout.session.completed event {event_id}: price_id {price_id} not mapped, using metadata plan_tier={plan_tier}")
        else:
            error_msg = f"unknown_price_id: price_id {price_id} not mapped to plan_tier and no metadata plan_tier found"
            logger.warning(f"checkout.session.completed event {event_id}: {error_msg}")
            _mark_event_error(db, event_id, error_msg)
            return
    
    # Normalize legacy 'user' tier to 'individual'
    plan_tier = _normalize_plan_tier(plan_tier)
    
    # Validate plan_tier against locked plan tiers
    valid_plan_tiers = {"individual", "team", "pro"}
    if plan_tier not in valid_plan_tiers:
        error_msg = f"invalid_plan_tier: plan_tier must be one of {valid_plan_tiers}, got '{plan_tier}'"
        logger.warning(f"checkout.session.completed event {event_id}: {error_msg}")
        _mark_event_error(db, event_id, error_msg)
        return
    
    # Extract subscription data
    sub_status = subscription.get("status")
    current_period_start = subscription.get("current_period_start")  # epoch seconds
    current_period_end = subscription.get("current_period_end")  # epoch seconds
    cancel_at_period_end = subscription.get("cancel_at_period_end", False)
    
    # Map subscription status to tenant_billing.status
    # Phase 4A: active/trialing -> active, others -> as-is or mapped
    if sub_status in ("active", "trialing"):
        billing_status = "active"
    elif sub_status == "past_due":
        billing_status = "past_due"
    elif sub_status in ("canceled", "unpaid", "incomplete_expired"):
        billing_status = "canceled"
    else:
        # Use status as-is for other cases
        billing_status = sub_status
    
    # Ensure tenant_billing row exists (create if missing)
    try:
        from services.entitlements_centralized import get_tenant_billing, create_tenant_billing_row
        
        try:
            # Try to get existing billing data
            existing_billing = get_tenant_billing(db, tenant_id)
            existing_subscription_id = None
            # Check if we already have this subscription (idempotency check)
            result = db.execute(
                text("SELECT stripe_subscription_id FROM tenant_billing WHERE tenant_id = :tenant_id"),
                {"tenant_id": tenant_id}
            ).first()
            if result:
                existing_subscription_id = result.stripe_subscription_id
        except RuntimeError:
            # tenant_billing row doesn't exist - create it
            logger.info(f"Creating tenant_billing row for tenant {tenant_id} from checkout.session.completed")
            create_tenant_billing_row(db, tenant_id, "unselected", None)
            db.commit()
            existing_subscription_id = None
        
        # Idempotency check: if this subscription is already recorded, treat as no-op
        if existing_subscription_id == stripe_subscription_id:
            logger.info(f"Subscription {stripe_subscription_id} already recorded for tenant {tenant_id}, skipping update")
            _mark_event_processed(db, event_id)
            return
        
    except Exception as e:
        error_msg = f"billing_setup_error: Failed to ensure tenant_billing exists: {str(e)}"
        logger.error(f"checkout.session.completed event {event_id}: {error_msg}", exc_info=True)
        _mark_event_error(db, event_id, error_msg)
        return
    
    # Update tenant_billing with subscription data
    try:
        # Convert epoch seconds to PostgreSQL timestamps using to_timestamp
        db.execute(
            text("""
                UPDATE tenant_billing
                SET plan_tier = :plan_tier,
                    status = :status,
                    stripe_customer_id = :stripe_customer_id,
                    stripe_subscription_id = :stripe_subscription_id,
                    current_period_start = to_timestamp(:current_period_start),
                    current_period_end = to_timestamp(:current_period_end),
                    cancel_at_period_end = :cancel_at_period_end,
                    updated_at = NOW()
                WHERE tenant_id = :tenant_id
            """),
            {
                "plan_tier": plan_tier,
                "status": billing_status,
                "stripe_customer_id": stripe_customer_id,
                "stripe_subscription_id": stripe_subscription_id,
                "current_period_start": current_period_start,
                "current_period_end": current_period_end,
                "cancel_at_period_end": cancel_at_period_end,
                "tenant_id": tenant_id
            }
        )
        db.commit()
        
        logger.info(
            f"Updated tenant_billing for tenant {tenant_id}: "
            f"plan_tier={plan_tier}, status={billing_status}, "
            f"subscription_id={stripe_subscription_id}"
        )
        
        # Send upgrade thank-you email after successful paid plan activation
        # This email is sent when a tenant upgrades from trial to a paid plan via Stripe checkout
        # Email failure should not block webhook processing
        try:
            from services.email_service import send_upgrade_thank_you_email
            from models import TenantUser
            import uuid as uuid_module
            
            # Convert tenant_id string to UUID for query
            tenant_uuid = uuid_module.UUID(tenant_id)
            
            # Get first admin user in tenant for upgrade email
            # Query for admin user created first (original onboarding user)
            admin_user = db.query(TenantUser).filter(
                TenantUser.tenant_id == tenant_uuid,
                TenantUser.role == "admin"
            ).order_by(TenantUser.created_at.asc()).first()
            
            if admin_user:
                send_upgrade_thank_you_email(admin_user.email, admin_user.first_name)
                logger.info(f"UPGRADE_EMAIL_SENT tenant_id={tenant_id} to={admin_user.email}")
            else:
                logger.warning(f"No admin user found for tenant {tenant_id} when sending upgrade email")
        except Exception as email_error:
            # Log error but don't fail webhook processing
            logger.error(f"Failed to send upgrade thank-you email after paid plan activation: {email_error}", exc_info=True)
        
        # Mark event as processed
        _mark_event_processed(db, event_id)
        
    except Exception as e:
        db.rollback()
        error_msg = f"update_error: Failed to update tenant_billing: {str(e)}"
        logger.error(f"checkout.session.completed event {event_id}: {error_msg}", exc_info=True)
        _mark_event_error(db, event_id, error_msg)
        raise


def _mark_event_processed(db: Session, event_id: str) -> None:
    """Mark stripe_events row as processed."""
    try:
        db.execute(
            text("""
                UPDATE stripe_events
                SET processing_status = 'processed',
                    processed_at = NOW(),
                    error = NULL
                WHERE event_id = :event_id
            """),
            {"event_id": event_id}
        )
        db.commit()
    except Exception as e:
        logger.error(f"Failed to mark event {event_id} as processed: {e}", exc_info=True)
        db.rollback()


def _mark_event_error(db: Session, event_id: str, error_msg: str) -> None:
    """Mark stripe_events row as error with error message."""
    try:
        db.execute(
            text("""
                UPDATE stripe_events
                SET processing_status = 'error',
                    error = :error,
                    processed_at = NOW()
                WHERE event_id = :event_id
            """),
            {
                "error": error_msg[:255],  # Limit error length
                "event_id": event_id
            }
        )
        db.commit()
    except Exception as e:
        logger.error(f"Failed to mark event {event_id} as error: {e}", exc_info=True)
        db.rollback()


def _mark_event_ignored(db: Session, event_id: str, reason: str) -> None:
    """Mark stripe_events row as ignored with reason."""
    try:
        db.execute(
            text("""
                UPDATE stripe_events
                SET processing_status = 'ignored',
                    error = :error,
                    processed_at = NOW()
                WHERE event_id = :event_id
            """),
            {
                "error": reason[:255],  # Limit error length
                "event_id": event_id
            }
        )
        db.commit()
    except Exception as e:
        logger.error(f"Failed to mark event {event_id} as ignored: {e}", exc_info=True)
        db.rollback()


def _process_customer_subscription_updated(event: Dict[str, Any], db: Session, event_id: str) -> None:
    """
    Process customer.subscription.updated event to update tenant_billing.
    
    Phase 4B.1: Updates tenant_billing when a subscription is updated.
    Matches tenant via stripe_subscription_id (not metadata).
    
    Args:
        event: Stripe event object (already verified)
        db: SQLAlchemy database session
        event_id: Stripe event ID for logging/updates
        
    Raises:
        Exception: If processing fails (will be caught and logged by caller)
    """
    # Extract subscription data from event
    subscription = event.get("data", {}).get("object", {})
    if not subscription:
        error_msg = "missing_subscription: subscription object not found in event data"
        logger.warning(f"customer.subscription.updated event {event_id}: {error_msg}")
        _mark_event_error(db, event_id, error_msg)
        return
    
    stripe_subscription_id = subscription.get("id")
    if not stripe_subscription_id:
        error_msg = "missing_subscription_id: subscription ID not found in event data"
        logger.warning(f"customer.subscription.updated event {event_id}: {error_msg}")
        _mark_event_error(db, event_id, error_msg)
        return
    
    # Look up tenant_billing by stripe_subscription_id
    result = db.execute(
        text("""
            SELECT tenant_id, status, plan_tier, cancel_at_period_end,
                   EXTRACT(EPOCH FROM current_period_start)::BIGINT as cps_epoch,
                   EXTRACT(EPOCH FROM current_period_end)::BIGINT as cpe_epoch
            FROM tenant_billing
            WHERE stripe_subscription_id = :subscription_id
        """),
        {"subscription_id": stripe_subscription_id}
    ).first()
    
    if not result:
        # Subscription not found - mark as ignored (not error)
        reason = "unknown_subscription"
        logger.info(f"customer.subscription.updated event {event_id}: Subscription {stripe_subscription_id} not found in tenant_billing")
        _mark_event_ignored(db, event_id, reason)
        return
    
    tenant_id = str(result.tenant_id)
    existing_status = result.status
    existing_plan_tier = result.plan_tier
    existing_cap = result.cancel_at_period_end
    existing_cps_epoch = result.cps_epoch
    existing_cpe_epoch = result.cpe_epoch
    
    # Extract subscription data
    sub_status = subscription.get("status")
    stripe_customer_id = subscription.get("customer")  # May be string or expanded object
    if isinstance(stripe_customer_id, dict):
        stripe_customer_id = stripe_customer_id.get("id")
    current_period_start = subscription.get("current_period_start")  # epoch seconds
    current_period_end = subscription.get("current_period_end")  # epoch seconds
    cancel_at_period_end = subscription.get("cancel_at_period_end", False)
    
    # Extract price_id from subscription line items to determine plan_tier
    line_items = subscription.get("items", {}).get("data", [])
    new_plan_tier = None
    if line_items:
        price_id = line_items[0].get("price", {}).get("id")
        if price_id:
            new_plan_tier = _map_price_id_to_plan_tier(price_id)
            if new_plan_tier:
                # Normalize legacy 'user' tier to 'individual'
                new_plan_tier = _normalize_plan_tier(new_plan_tier)
    
    # Normalize existing plan_tier if it's legacy 'user'
    if existing_plan_tier:
        existing_plan_tier = _normalize_plan_tier(existing_plan_tier)
        # Update DB if normalization changed it
        if existing_plan_tier != result.plan_tier:
            db.execute(
                text("UPDATE tenant_billing SET plan_tier = :plan_tier WHERE tenant_id = :tenant_id"),
                {"plan_tier": existing_plan_tier, "tenant_id": tenant_id}
            )
            db.commit()
    
    # Map subscription status to tenant_billing.status
    # Keep consistent with Phase 4A mapping
    if sub_status in ("active", "trialing"):
        billing_status = "active"
    elif sub_status in ("past_due", "unpaid"):
        billing_status = "past_due"
    elif sub_status in ("canceled", "incomplete_expired"):
        billing_status = "canceled"
    else:
        # Use status as-is for other cases
        billing_status = sub_status
    
    # Use new_plan_tier if available, otherwise keep existing
    final_plan_tier = new_plan_tier if new_plan_tier else existing_plan_tier
    
    # Idempotency check: if all fields are already equal, treat as no-op
    if (existing_status == billing_status and
        (not new_plan_tier or existing_plan_tier == new_plan_tier) and
        existing_cap == cancel_at_period_end and
        (existing_cps_epoch is None or existing_cps_epoch == current_period_start) and
        (existing_cpe_epoch is None or existing_cpe_epoch == current_period_end)):
        logger.info(f"Subscription {stripe_subscription_id} already up to date, skipping update")
        _mark_event_processed(db, event_id)
        return
    
    # Update tenant_billing
    try:
        # Build update query with conditional timestamp, plan_tier, and customer_id updates
        update_params = {
            "status": billing_status,
            "cancel_at_period_end": cancel_at_period_end,
            "subscription_id": stripe_subscription_id
        }
        
        # Build SET clause conditionally
        set_clauses = [
            "status = :status",
            "cancel_at_period_end = :cancel_at_period_end",
            "updated_at = NOW()"
        ]
        
        # Update plan_tier if it changed
        if new_plan_tier and new_plan_tier != existing_plan_tier:
            set_clauses.append("plan_tier = :plan_tier")
            update_params["plan_tier"] = new_plan_tier
        
        # Update stripe_customer_id if available
        if stripe_customer_id:
            set_clauses.append("stripe_customer_id = :stripe_customer_id")
            update_params["stripe_customer_id"] = stripe_customer_id
        
        if current_period_start is not None:
            set_clauses.append("current_period_start = to_timestamp(:current_period_start)")
            update_params["current_period_start"] = current_period_start
        
        if current_period_end is not None:
            set_clauses.append("current_period_end = to_timestamp(:current_period_end)")
            update_params["current_period_end"] = current_period_end
        
        update_query = f"""
            UPDATE tenant_billing
            SET {', '.join(set_clauses)}
            WHERE stripe_subscription_id = :subscription_id
        """
        
        db.execute(text(update_query), update_params)
        db.commit()
        
        log_msg = f"Updated tenant_billing for subscription {stripe_subscription_id} (tenant {tenant_id}): status={billing_status}"
        if new_plan_tier and new_plan_tier != existing_plan_tier:
            log_msg += f", plan_tier={new_plan_tier} (was {existing_plan_tier})"
        log_msg += f", cancel_at_period_end={cancel_at_period_end}"
        logger.info(log_msg)
        
        # Mark event as processed
        _mark_event_processed(db, event_id)
        
    except Exception as e:
        db.rollback()
        error_msg = f"update_error: Failed to update tenant_billing: {str(e)}"
        logger.error(f"customer.subscription.updated event {event_id}: {error_msg}", exc_info=True)
        _mark_event_error(db, event_id, error_msg)
        raise


def _process_customer_subscription_deleted(event: Dict[str, Any], db: Session, event_id: str) -> None:
    """
    Process customer.subscription.deleted event to update tenant_billing.
    
    Phase 4B.1: Updates tenant_billing when a subscription is deleted.
    Matches tenant via stripe_subscription_id (not metadata).
    
    Args:
        event: Stripe event object (already verified)
        db: SQLAlchemy database session
        event_id: Stripe event ID for logging/updates
        
    Raises:
        Exception: If processing fails (will be caught and logged by caller)
    """
    # Extract subscription data from event
    subscription = event.get("data", {}).get("object", {})
    if not subscription:
        error_msg = "missing_subscription: subscription object not found in event data"
        logger.warning(f"customer.subscription.deleted event {event_id}: {error_msg}")
        _mark_event_error(db, event_id, error_msg)
        return
    
    stripe_subscription_id = subscription.get("id")
    if not stripe_subscription_id:
        error_msg = "missing_subscription_id: subscription ID not found in event data"
        logger.warning(f"customer.subscription.deleted event {event_id}: {error_msg}")
        _mark_event_error(db, event_id, error_msg)
        return
    
    # Look up tenant_billing by stripe_subscription_id
    result = db.execute(
        text("""
            SELECT tenant_id, status
            FROM tenant_billing
            WHERE stripe_subscription_id = :subscription_id
        """),
        {"subscription_id": stripe_subscription_id}
    ).first()
    
    if not result:
        # Subscription not found - mark as ignored (not error)
        reason = "unknown_subscription"
        logger.info(f"customer.subscription.deleted event {event_id}: Subscription {stripe_subscription_id} not found in tenant_billing")
        _mark_event_ignored(db, event_id, reason)
        return
    
    tenant_id = str(result.tenant_id)
    
    # Update tenant_billing: set status to canceled, cancel_at_period_end to false
    # Keep existing period_start/end as last known values
    try:
        db.execute(
            text("""
                UPDATE tenant_billing
                SET status = 'canceled',
                    cancel_at_period_end = false,
                    updated_at = NOW()
                WHERE stripe_subscription_id = :subscription_id
            """),
            {"subscription_id": stripe_subscription_id}
        )
        db.commit()
        
        logger.info(
            f"Marked subscription {stripe_subscription_id} as canceled for tenant {tenant_id}"
        )
        
        # Mark event as processed
        _mark_event_processed(db, event_id)
        
    except Exception as e:
        db.rollback()
        error_msg = f"update_error: Failed to update tenant_billing: {str(e)}"
        logger.error(f"customer.subscription.deleted event {event_id}: {error_msg}", exc_info=True)
        _mark_event_error(db, event_id, error_msg)
        raise


def _process_invoice_payment_failed(event: Dict[str, Any], db: Session, event_id: str) -> None:
    """
    Process invoice.payment_failed event to update tenant_billing.
    
    Phase 4B.2: Updates tenant_billing.status to "past_due" when payment fails.
    Matches tenant via stripe_subscription_id from invoice.
    
    Args:
        event: Stripe event object (already verified)
        db: SQLAlchemy database session
        event_id: Stripe event ID for logging/updates
        
    Raises:
        Exception: If processing fails (will be caught and logged by caller)
    """
    # Extract invoice data from event
    invoice = event.get("data", {}).get("object", {})
    if not invoice:
        error_msg = "missing_invoice: invoice object not found in event data"
        logger.warning(f"invoice.payment_failed event {event_id}: {error_msg}")
        _mark_event_error(db, event_id, error_msg)
        return
    
    stripe_subscription_id = invoice.get("subscription")
    if not stripe_subscription_id:
        # Subscription ID missing - mark as ignored
        reason = "missing_subscription"
        logger.info(f"invoice.payment_failed event {event_id}: Invoice has no subscription_id")
        _mark_event_ignored(db, event_id, reason)
        return
    
    # Look up tenant_billing by stripe_subscription_id
    result = db.execute(
        text("""
            SELECT tenant_id, status
            FROM tenant_billing
            WHERE stripe_subscription_id = :subscription_id
        """),
        {"subscription_id": stripe_subscription_id}
    ).first()
    
    if not result:
        # Subscription not found - mark as ignored
        reason = "unknown_subscription"
        logger.info(f"invoice.payment_failed event {event_id}: Subscription {stripe_subscription_id} not found in tenant_billing")
        _mark_event_ignored(db, event_id, reason)
        return
    
    tenant_id = str(result.tenant_id)
    existing_status = result.status
    
    # Idempotency check: if already past_due, treat as no-op
    if existing_status == "past_due":
        logger.info(f"Subscription {stripe_subscription_id} already has status 'past_due', skipping update")
        _mark_event_processed(db, event_id)
        return
    
    # Update tenant_billing status to past_due
    try:
        db.execute(
            text("""
                UPDATE tenant_billing
                SET status = 'past_due',
                    updated_at = NOW()
                WHERE stripe_subscription_id = :subscription_id
            """),
            {"subscription_id": stripe_subscription_id}
        )
        db.commit()
        
        logger.info(
            f"Updated tenant_billing for subscription {stripe_subscription_id} (tenant {tenant_id}): "
            f"status=past_due (payment failed)"
        )
        
        # Mark event as processed
        _mark_event_processed(db, event_id)
        
    except Exception as e:
        db.rollback()
        error_msg = f"update_error: Failed to update tenant_billing: {str(e)}"
        logger.error(f"invoice.payment_failed event {event_id}: {error_msg}", exc_info=True)
        _mark_event_error(db, event_id, error_msg)
        raise


def _process_invoice_payment_succeeded(event: Dict[str, Any], db: Session, event_id: str) -> None:
    """
    Process invoice.payment_succeeded event to update tenant_billing.
    
    Phase 4B.2: Updates tenant_billing.status to "active" if currently "past_due".
    Matches tenant via stripe_subscription_id from invoice.
    
    Args:
        event: Stripe event object (already verified)
        db: SQLAlchemy database session
        event_id: Stripe event ID for logging/updates
        
    Raises:
        Exception: If processing fails (will be caught and logged by caller)
    """
    # Extract invoice data from event
    invoice = event.get("data", {}).get("object", {})
    if not invoice:
        error_msg = "missing_invoice: invoice object not found in event data"
        logger.warning(f"invoice.payment_succeeded event {event_id}: {error_msg}")
        _mark_event_error(db, event_id, error_msg)
        return
    
    stripe_subscription_id = invoice.get("subscription")
    if not stripe_subscription_id:
        # Subscription ID missing - mark as ignored
        reason = "missing_subscription"
        logger.info(f"invoice.payment_succeeded event {event_id}: Invoice has no subscription_id")
        _mark_event_ignored(db, event_id, reason)
        return
    
    # Look up tenant_billing by stripe_subscription_id
    result = db.execute(
        text("""
            SELECT tenant_id, status
            FROM tenant_billing
            WHERE stripe_subscription_id = :subscription_id
        """),
        {"subscription_id": stripe_subscription_id}
    ).first()
    
    if not result:
        # Subscription not found - mark as ignored
        reason = "unknown_subscription"
        logger.info(f"invoice.payment_succeeded event {event_id}: Subscription {stripe_subscription_id} not found in tenant_billing")
        _mark_event_ignored(db, event_id, reason)
        return
    
    tenant_id = str(result.tenant_id)
    existing_status = result.status
    
    # Only update if status is currently "past_due"
    if existing_status != "past_due":
        # Idempotency: if not past_due, treat as no-op
        logger.info(
            f"Subscription {stripe_subscription_id} has status '{existing_status}' (not past_due), "
            f"skipping update (idempotent no-op)"
        )
        _mark_event_processed(db, event_id)
        return
    
    # Update tenant_billing status to active
    try:
        db.execute(
            text("""
                UPDATE tenant_billing
                SET status = 'active',
                    updated_at = NOW()
                WHERE stripe_subscription_id = :subscription_id
            """),
            {"subscription_id": stripe_subscription_id}
        )
        db.commit()
        
        logger.info(
            f"Updated tenant_billing for subscription {stripe_subscription_id} (tenant {tenant_id}): "
            f"status=active (payment succeeded, recovered from past_due)"
        )
        
        # Mark event as processed
        _mark_event_processed(db, event_id)
        
    except Exception as e:
        db.rollback()
        error_msg = f"update_error: Failed to update tenant_billing: {str(e)}"
        logger.error(f"invoice.payment_succeeded event {event_id}: {error_msg}", exc_info=True)
        _mark_event_error(db, event_id, error_msg)
        raise


def ingest_stripe_event(raw_body: bytes, signature: str, db: Session) -> Dict[str, Any]:
    """
    Ingest a Stripe webhook event into the stripe_events table.
    
    This function:
    1. Verifies the Stripe webhook signature
    2. Parses the event data
    3. Checks STRIPE_MODE guard (test vs live)
    4. Inserts into stripe_events table with idempotency handling
    
    Args:
        raw_body: Raw request body bytes from Stripe webhook
        signature: Stripe-Signature header value
        db: SQLAlchemy database session
        
    Returns:
        Dict with keys:
            - success: bool
            - event_id: str (if successful)
            - error: str (if failed)
            - ignored: bool (if mode mismatch)
            
    Raises:
        ValueError: If signature verification fails
    """
    if stripe is None:
        raise RuntimeError("stripe package not installed")
    
    # Get webhook secret from environment
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")
    if not webhook_secret:
        raise RuntimeError("STRIPE_WEBHOOK_SECRET environment variable not set")
    
    # Verify Stripe signature
    try:
        event = stripe.Webhook.construct_event(
            raw_body,
            signature,
            webhook_secret
        )
    except ValueError as e:
        # Invalid signature
        logger.warning(f"Stripe webhook signature verification failed: {e}")
        raise ValueError(f"Invalid webhook signature: {str(e)}")
    except stripe.error.SignatureVerificationError as e:
        # Signature verification error
        logger.warning(f"Stripe webhook signature verification error: {e}")
        raise ValueError(f"Signature verification failed: {str(e)}")
    
    # Extract event data
    event_id = event.get("id")
    event_type = event.get("type")
    api_version = event.get("api_version")
    created_at_epoch = event.get("created")
    livemode = event.get("livemode", False)
    # Store entire event as JSONB (includes data.object and other fields)
    event_data = event
    
    # STRIPE_MODE guard: Check if event mode matches expected mode
    expected_mode = os.getenv("STRIPE_MODE", "test").lower()
    should_ignore = False
    
    if expected_mode == "live" and not livemode:
        # Production expects live events, but received test event
        should_ignore = True
        logger.info(f"Ignoring test-mode event {event_id} in live-mode environment")
    elif expected_mode == "test" and livemode:
        # Local/test expects test events, but received live event
        should_ignore = True
        logger.info(f"Ignoring live-mode event {event_id} in test-mode environment")
    
    # Extract tenant_id from event data if available
    # Stripe events may contain customer/subscription data that we can use to find tenant_id
    tenant_id = None
    try:
        # Try to extract tenant_id from event data
        # This is a placeholder - actual extraction logic depends on event type
        # For now, we'll store NULL and extract in Phase 3
        # Stripe event structure: event.data.object contains the actual object
        if "data" in event and "object" in event["data"]:
            obj = event["data"]["object"]
            # Placeholder: tenant_id extraction will be implemented in Phase 3
            # We can look for customer_id, subscription metadata, etc.
            pass
    except Exception as e:
        logger.debug(f"Could not extract tenant_id from event: {e}")
    
    # Determine processing status
    if should_ignore:
        processing_status = "ignored"
        error_msg = "livemode_mismatch"
    else:
        processing_status = "received"
        error_msg = None
    
    # Insert into stripe_events table with ON CONFLICT DO NOTHING for idempotency
    try:
        # Convert event data to JSON string for JSONB column
        data_json = json.dumps(event_data)
        
        # Use CAST to properly handle JSONB conversion
        result = db.execute(
            text("""
                INSERT INTO stripe_events (
                    event_id,
                    event_type,
                    api_version,
                    created_at_epoch,
                    livemode,
                    tenant_id,
                    data,
                    processing_status,
                    error
                ) VALUES (
                    :event_id,
                    :event_type,
                    :api_version,
                    :created_at_epoch,
                    :livemode,
                    :tenant_id,
                    CAST(:data AS jsonb),
                    :processing_status,
                    :error
                )
                ON CONFLICT (event_id) DO NOTHING
                RETURNING id, event_id
            """),
            {
                "event_id": event_id,
                "event_type": event_type,
                "api_version": api_version,
                "created_at_epoch": created_at_epoch,
                "livemode": livemode,
                "tenant_id": tenant_id,
                "data": data_json,
                "processing_status": processing_status,
                "error": error_msg
            }
        )
        
        row = result.first()
        db.commit()
        
        if row:
            # New event inserted
            logger.info(f"Inserted Stripe event {event_id} (type: {event_type}, status: {processing_status})")
            
            # Phase 4A: Process checkout.session.completed events
            if not should_ignore and event_type == "checkout.session.completed":
                try:
                    _process_checkout_session_completed(event, db, event_id)
                except Exception as process_error:
                    # Log error but don't fail the webhook ingestion
                    logger.error(f"Error processing checkout.session.completed for event {event_id}: {process_error}", exc_info=True)
                    # Mark event as error in stripe_events
                    try:
                        db.execute(
                            text("""
                                UPDATE stripe_events
                                SET processing_status = 'error',
                                    error = :error,
                                    processed_at = NOW()
                                WHERE event_id = :event_id
                            """),
                            {
                                "error": str(process_error)[:255],  # Limit error length
                                "event_id": event_id
                            }
                        )
                        db.commit()
                    except Exception as update_error:
                        logger.error(f"Failed to update stripe_events error status: {update_error}", exc_info=True)
                        db.rollback()
            
            # Phase 4B.1: Process subscription lifecycle events
            if not should_ignore and event_type == "customer.subscription.updated":
                try:
                    _process_customer_subscription_updated(event, db, event_id)
                except Exception as process_error:
                    # Log error but don't fail the webhook ingestion
                    logger.error(f"Error processing customer.subscription.updated for event {event_id}: {process_error}", exc_info=True)
                    # Mark event as error in stripe_events
                    try:
                        db.execute(
                            text("""
                                UPDATE stripe_events
                                SET processing_status = 'error',
                                    error = :error,
                                    processed_at = NOW()
                                WHERE event_id = :event_id
                            """),
                            {
                                "error": str(process_error)[:255],  # Limit error length
                                "event_id": event_id
                            }
                        )
                        db.commit()
                    except Exception as update_error:
                        logger.error(f"Failed to update stripe_events error status: {update_error}", exc_info=True)
                        db.rollback()
            
            if not should_ignore and event_type == "customer.subscription.deleted":
                try:
                    _process_customer_subscription_deleted(event, db, event_id)
                except Exception as process_error:
                    # Log error but don't fail the webhook ingestion
                    logger.error(f"Error processing customer.subscription.deleted for event {event_id}: {process_error}", exc_info=True)
                    # Mark event as error in stripe_events
                    try:
                        db.execute(
                            text("""
                                UPDATE stripe_events
                                SET processing_status = 'error',
                                    error = :error,
                                    processed_at = NOW()
                                WHERE event_id = :event_id
                            """),
                            {
                                "error": str(process_error)[:255],  # Limit error length
                                "event_id": event_id
                            }
                        )
                        db.commit()
                    except Exception as update_error:
                        logger.error(f"Failed to update stripe_events error status: {update_error}", exc_info=True)
                        db.rollback()
            
            # Phase 4B.2: Process invoice payment events
            if not should_ignore and event_type == "invoice.payment_failed":
                try:
                    _process_invoice_payment_failed(event, db, event_id)
                except Exception as process_error:
                    # Log error but don't fail the webhook ingestion
                    logger.error(f"Error processing invoice.payment_failed for event {event_id}: {process_error}", exc_info=True)
                    # Mark event as error in stripe_events
                    try:
                        db.execute(
                            text("""
                                UPDATE stripe_events
                                SET processing_status = 'error',
                                    error = :error,
                                    processed_at = NOW()
                                WHERE event_id = :event_id
                            """),
                            {
                                "error": str(process_error)[:255],  # Limit error length
                                "event_id": event_id
                            }
                        )
                        db.commit()
                    except Exception as update_error:
                        logger.error(f"Failed to update stripe_events error status: {update_error}", exc_info=True)
                        db.rollback()
            
            if not should_ignore and event_type == "invoice.payment_succeeded":
                try:
                    _process_invoice_payment_succeeded(event, db, event_id)
                except Exception as process_error:
                    # Log error but don't fail the webhook ingestion
                    logger.error(f"Error processing invoice.payment_succeeded for event {event_id}: {process_error}", exc_info=True)
                    # Mark event as error in stripe_events
                    try:
                        db.execute(
                            text("""
                                UPDATE stripe_events
                                SET processing_status = 'error',
                                    error = :error,
                                    processed_at = NOW()
                                WHERE event_id = :event_id
                            """),
                            {
                                "error": str(process_error)[:255],  # Limit error length
                                "event_id": event_id
                            }
                        )
                        db.commit()
                    except Exception as update_error:
                        logger.error(f"Failed to update stripe_events error status: {update_error}", exc_info=True)
                        db.rollback()
            
            return {
                "success": True,
                "event_id": event_id,
                "ignored": should_ignore
            }
        else:
            # Event already exists (idempotency)
            logger.info(f"Stripe event {event_id} already exists (idempotent)")
            
            # Phase 4A/4B.1/4B.2: Check if event needs processing (may have been inserted but not processed)
            if not should_ignore:
                # Check if event is already processed
                status_result = db.execute(
                    text("""
                        SELECT processing_status, processed_at
                        FROM stripe_events
                        WHERE event_id = :event_id
                    """),
                    {"event_id": event_id}
                ).first()
                
                if status_result and status_result.processing_status not in ("processed", "error", "ignored"):
                    # Event exists but not processed - try to process it
                    logger.info(f"Processing existing unprocessed event {event_id} (type: {event_type})")
                    try:
                        if event_type == "checkout.session.completed":
                            _process_checkout_session_completed(event, db, event_id)
                        elif event_type == "customer.subscription.updated":
                            _process_customer_subscription_updated(event, db, event_id)
                        elif event_type == "customer.subscription.deleted":
                            _process_customer_subscription_deleted(event, db, event_id)
                        elif event_type == "invoice.payment_failed":
                            _process_invoice_payment_failed(event, db, event_id)
                        elif event_type == "invoice.payment_succeeded":
                            _process_invoice_payment_succeeded(event, db, event_id)
                    except Exception as process_error:
                        logger.error(f"Error processing existing {event_type} for event {event_id}: {process_error}", exc_info=True)
                        try:
                            db.execute(
                                text("""
                                    UPDATE stripe_events
                                    SET processing_status = 'error',
                                        error = :error,
                                        processed_at = NOW()
                                    WHERE event_id = :event_id
                                """),
                                {
                                    "error": str(process_error)[:255],
                                    "event_id": event_id
                                }
                            )
                            db.commit()
                        except Exception as update_error:
                            logger.error(f"Failed to update stripe_events error status: {update_error}", exc_info=True)
                            db.rollback()
            
            return {
                "success": True,
                "event_id": event_id,
                "ignored": should_ignore,
                "duplicate": True
            }
            
    except Exception as e:
        db.rollback()
        logger.error(f"Error inserting Stripe event {event_id}: {e}", exc_info=True)
        raise RuntimeError(f"Failed to insert event: {str(e)}")
