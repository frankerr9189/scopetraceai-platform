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
