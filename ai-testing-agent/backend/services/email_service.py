"""
Email service for sending transactional emails via Resend.

This module handles sending welcome emails and other transactional emails
to users after successful onboarding or account actions.
"""
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import resend
except ImportError:
    resend = None
    logger.warning("resend package not found. Email sending will fail.")


def send_welcome_email(to_email: str, first_name: Optional[str] = None) -> bool:
    """
    Send welcome email to new user after successful onboarding.
    
    This function sends a welcome email with next steps after the user
    completes onboarding (either by selecting trial plan or completing Stripe checkout).
    
    Args:
        to_email: Recipient email address
        first_name: Optional first name for personalization
    
    Returns:
        bool: True if email sent successfully, False otherwise
    
    Note:
        This function logs errors but does not raise exceptions.
        Email failures should not block onboarding completion.
    """
    if resend is None:
        logger.error("resend package not installed. Cannot send welcome email.")
        return False
    
    # Get Resend API key from environment
    resend_api_key = os.getenv("RESEND_API_KEY")
    if not resend_api_key:
        logger.error("RESEND_API_KEY environment variable not set. Cannot send welcome email.")
        return False
    
    # Get email from address (default to hello@scopetraceai.com)
    email_from = os.getenv("EMAIL_FROM", "ScopeTraceAI <hello@scopetraceai.com>")
    
    # Set Resend API key
    resend.api_key = resend_api_key
    
    # Personalize greeting with safe fallback
    # Use first_name if provided and non-empty, otherwise fall back to "there"
    personalized_name = first_name.strip() if first_name and first_name.strip() else "there"
    greeting = f"Hi {personalized_name},"
    
    # Email body with finalized copy
    email_body = f"""{greeting}

Thanks for joining ScopeTraceAI — we're excited to have you.

You can now turn requirements, specs, and Jira tickets into clear, testable, and traceable outputs in minutes.

Here's how to get started:
• Connect Jira (optional)
• Upload requirements or add tickets
• Generate your first test plan or analysis

If you have any questions or want help getting set up, just reply to this email — it goes straight to our team.

Welcome aboard,
— ScopeTraceAI
"""
    
    try:
        # Send email via Resend
        # Resend Python SDK: https://github.com/resendlabs/resend-python
        # Set API key (if not already set globally)
        if not hasattr(resend, 'api_key') or not resend.api_key:
            resend.api_key = resend_api_key
        
        # Send email using Resend API
        params = {
            "from": email_from,
            "to": [to_email],
            "subject": "Welcome to ScopeTraceAI 👋",
            "html": email_body.replace('\n', '<br>'),  # Convert newlines to HTML breaks
            "reply_to": "hello@scopetraceai.com"
        }
        
        result = resend.Emails.send(params)
        
        if result and hasattr(result, 'id'):
            logger.info(f"Welcome email sent successfully to {to_email} (Resend ID: {result.id})")
            return True
        else:
            logger.warning(f"Welcome email sent to {to_email} but no confirmation ID received")
            return True  # Assume success if no error raised
        
    except Exception as e:
        # Log error but don't raise exception (onboarding should not fail due to email)
        logger.error(f"Failed to send welcome email to {to_email}: {str(e)}", exc_info=True)
        return False


def send_upgrade_thank_you_email(to_email: str, first_name: Optional[str] = None) -> bool:
    """
    Send upgrade thank-you email when tenant upgrades from trial to a paid plan.
    
    This function sends an upgrade confirmation email after a tenant successfully
    activates a paid plan via Stripe checkout.
    
    Args:
        to_email: Recipient email address
        first_name: Optional first name for personalization
    
    Returns:
        bool: True if email sent successfully, False otherwise
    
    Note:
        This function logs errors but does not raise exceptions.
        Email failures should not block webhook processing.
    """
    if resend is None:
        logger.error("resend package not installed. Cannot send upgrade email.")
        return False
    
    # Get Resend API key from environment
    resend_api_key = os.getenv("RESEND_API_KEY")
    if not resend_api_key:
        logger.error("RESEND_API_KEY environment variable not set. Cannot send upgrade email.")
        return False
    
    # Get email from address (default to hello@scopetraceai.com)
    email_from = os.getenv("EMAIL_FROM", "ScopeTraceAI <hello@scopetraceai.com>")
    
    # Set Resend API key
    resend.api_key = resend_api_key
    
    # Personalize greeting with safe fallback
    # Use first_name if provided and non-empty, otherwise fall back to "there"
    personalized_name = first_name.strip() if first_name and first_name.strip() else "there"
    greeting = f"Hi {personalized_name},"
    
    # Email body with finalized copy
    email_body = f"""{greeting}

Thanks for upgrading to a paid ScopeTraceAI plan — we really appreciate it.

You now have access to higher usage limits, team features, and priority support to help you move faster and with confidence.

Here are a few things you might want to do next:
• Invite teammates
• Run your first production project
• Explore advanced analysis and traceability features

If you have any questions about your plan or need help getting started, just reply to this email — we're here to help.

Thanks again,
— ScopeTraceAI
"""
    
    try:
        # Send email via Resend
        # Resend Python SDK: https://github.com/resendlabs/resend-python
        # Set API key (if not already set globally)
        if not hasattr(resend, 'api_key') or not resend.api_key:
            resend.api_key = resend_api_key
        
        # Send email using Resend API
        params = {
            "from": email_from,
            "to": [to_email],
            "subject": "Thanks for upgrading to ScopeTraceAI 🎉",
            "html": email_body.replace('\n', '<br>'),  # Convert newlines to HTML breaks
            "reply_to": "hello@scopetraceai.com"
        }
        
        result = resend.Emails.send(params)
        
        if result and hasattr(result, 'id'):
            logger.info(f"Upgrade thank-you email sent successfully to {to_email} (Resend ID: {result.id})")
            return True
        else:
            logger.warning(f"Upgrade thank-you email sent to {to_email} but no confirmation ID received")
            return True  # Assume success if no error raised
        
    except Exception as e:
        # Log error but don't raise exception (webhook should not fail due to email)
        logger.error(f"Failed to send upgrade thank-you email to {to_email}: {str(e)}", exc_info=True)
        return False


def send_team_invite_email(
    to_email: str,
    tenant_name: Optional[str],
    invite_link: str,
    expiry_hours: int,
    inviter_name: Optional[str] = None
) -> bool:
    """
    Send team invite email when a tenant admin invites a user to join their team.
    
    This function sends an invitation email with an accept link after a tenant admin
    successfully creates an invite for a new or inactive user.
    
    Args:
        to_email: Recipient email address
        tenant_name: Name of the tenant/organization (optional, falls back to "your team")
        invite_link: Full URL to accept invite page with token
        expiry_hours: Number of hours until invite expires
        inviter_name: Optional first name of the person sending the invite
    
    Returns:
        bool: True if email sent successfully, False otherwise
    
    Note:
        This function logs errors but does not raise exceptions.
        Email failures should not block invite creation.
    """
    if resend is None:
        logger.error("resend package not installed. Cannot send team invite email.")
        return False
    
    # Get Resend API key from environment
    resend_api_key = os.getenv("RESEND_API_KEY")
    if not resend_api_key:
        logger.error("RESEND_API_KEY environment variable not set. Cannot send team invite email.")
        return False
    
    # Get email from address (default to hello@scopetraceai.com)
    email_from = os.getenv("EMAIL_FROM", "ScopeTraceAI <hello@scopetraceai.com>")
    
    # Set Resend API key
    resend.api_key = resend_api_key
    
    # Safe fallback for tenant name
    display_tenant_name = tenant_name.strip() if tenant_name and tenant_name.strip() else "your team"
    
    # Build inviter line if inviter name is provided
    inviter_line = ""
    if inviter_name and inviter_name.strip():
        inviter_line = f"\n\nInvited by: {inviter_name.strip()}\n\n"
    
    # Build email body in plain text format first (using \n\n for paragraph spacing)
    text_body = f"""Hi,

You've been invited to join {display_tenant_name} on ScopeTraceAI.{inviter_line}To accept the invitation, click the link below:
{invite_link}

This link will expire in {expiry_hours} hours.

If you weren't expecting this invitation, you can ignore this email.

— ScopeTraceAI
"""
    
    # Derive HTML body from text body (replace \n\n with <br><br> and \n with <br>)
    # This ensures both versions have identical content
    html_body = text_body.replace('\n\n', '<br><br>').replace('\n', '<br>')
    
    try:
        # Send email via Resend
        # Resend Python SDK: https://github.com/resendlabs/resend-python
        # Set API key (if not already set globally)
        if not hasattr(resend, 'api_key') or not resend.api_key:
            resend.api_key = resend_api_key
        
        # Send email using Resend API with both text and HTML versions
        params = {
            "from": email_from,
            "to": [to_email],
            "subject": "You've been invited to join ScopeTraceAI",
            "text": text_body,  # Plain text version
            "html": html_body,  # HTML version
            "reply_to": "hello@scopetraceai.com"
        }
        
        result = resend.Emails.send(params)
        
        if result and hasattr(result, 'id'):
            logger.info(f"Team invite email sent successfully to {to_email} (Resend ID: {result.id})")
            return True
        else:
            logger.warning(f"Team invite email sent to {to_email} but no confirmation ID received")
            return True  # Assume success if no error raised
        
    except Exception as e:
        # Log error but don't raise exception (invite creation should not fail due to email)
        logger.error(f"Failed to send team invite email to {to_email}: {str(e)}", exc_info=True)
        return False


def send_password_reset_email_resend(to_email: str, reset_url: str) -> None:
    """
    Send password reset email via Resend.
    
    This function sends a password reset email with a reset link after a user
    requests a password reset via the forgot password flow.
    
    Args:
        to_email: Recipient email address
        reset_url: Full URL to reset password page with token
    
    Note:
        This function logs errors but does not raise exceptions.
        Email failures should not block password reset flow.
    """
    if resend is None:
        logger.error("resend package not installed. Cannot send password reset email.")
        return
    
    # Get Resend API key from environment
    resend_api_key = os.getenv("RESEND_API_KEY")
    if not resend_api_key:
        logger.error("RESEND_API_KEY environment variable not set. Cannot send password reset email.")
        return
    
    # Get email from address (default to hello@scopetraceai.com)
    email_from = os.getenv("EMAIL_FROM", "ScopeTraceAI <hello@scopetraceai.com>")
    
    # Set Resend API key
    resend.api_key = resend_api_key
    
    # Build email body in plain text format first (using \n\n for paragraph spacing)
    text_body = f"""Hi,

We received a request to reset your ScopeTraceAI password.

Reset your password using this link (valid for 30 minutes):
{reset_url}

If you didn't request a password reset, you can ignore this email.

— ScopeTraceAI
"""
    
    # Derive HTML body from text body (replace \n\n with <br><br> and \n with <br>)
    # This ensures both versions have identical content
    html_body = text_body.replace('\n\n', '<br><br>').replace('\n', '<br>')
    
    try:
        # Send email via Resend
        # Resend Python SDK: https://github.com/resendlabs/resend-python
        # Set API key (if not already set globally)
        if not hasattr(resend, 'api_key') or not resend.api_key:
            resend.api_key = resend_api_key
        
        # Send email using Resend API with both text and HTML versions
        params = {
            "from": email_from,
            "to": [to_email],
            "subject": "Reset your ScopeTraceAI password",
            "text": text_body,  # Plain text version
            "html": html_body,  # HTML version
            "reply_to": "hello@scopetraceai.com"
        }
        
        result = resend.Emails.send(params)
        
        if result and hasattr(result, 'id'):
            logger.info(f"PASSWORD_RESET_EMAIL_SENT to={to_email} (Resend ID: {result.id})")
        else:
            logger.warning(f"PASSWORD_RESET_EMAIL_SENT to={to_email} but no confirmation ID received")
        
    except Exception as e:
        # Log error but don't raise exception (password reset flow should not fail due to email)
        logger.error(f"PASSWORD_RESET_EMAIL_FAILED to={to_email} error={str(e)}", exc_info=True)
