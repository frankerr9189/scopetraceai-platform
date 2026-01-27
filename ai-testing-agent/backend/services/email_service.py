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
    
    # Personalize greeting
    greeting = f"Hi {first_name}," if first_name else "Hi there,"
    
    # Email body with next steps
    email_body = f"""{greeting}

Thanks for joining ScopeTraceAI!

Here are your next steps to get started:
1. Connect your Jira instance
2. Add tickets or specs
3. Generate your first test plan

Reply to this email if you have any questions.

- The ScopeTraceAI Team
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
