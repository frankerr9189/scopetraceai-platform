"""
Authentication service functions for password management and password reset.
Phase 2.1: User Profile + Password Update + Forgot Password flow.
"""
import os
import secrets
import hashlib
import hmac
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
import bcrypt
from sqlalchemy.orm import Session
from models import TenantUser, PasswordResetToken, UserInviteToken

logger = logging.getLogger(__name__)

# Get server secret for token hashing (use JWT_SECRET if available, otherwise generate a warning)
SERVER_SECRET = os.getenv("JWT_SECRET") or os.getenv("SECRET_KEY")
if not SERVER_SECRET:
    logger.warning(
        "JWT_SECRET or SECRET_KEY not set. Password reset tokens may not be secure. "
        "Set JWT_SECRET environment variable."
    )
    SERVER_SECRET = "default-insecure-secret-change-in-production"

# Password reset token expiration (30 minutes)
PASSWORD_RESET_TOKEN_EXPIRY_MINUTES = 30

# User invite token expiration (7 days - longer than password reset since it's for new users)
USER_INVITE_TOKEN_EXPIRY_DAYS = 7

# Password policy: minimum 12 characters
MIN_PASSWORD_LENGTH = 12

# Rate limiting: simple in-memory store (per IP + email)
# In production, consider using Redis or similar
_rate_limit_store = {}
_rate_limit_window_seconds = 60  # 1 minute window
_rate_limit_max_requests = 3  # Max 3 requests per window


def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt.
    
    Args:
        password: Plain text password string
        
    Returns:
        str: Bcrypt hashed password as UTF-8 string (for storage in Postgres)
    """
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_bytes = bcrypt.hashpw(password_bytes, salt)
    return hashed_bytes.decode('utf-8')


def verify_password(password: str, hashed: str) -> bool:
    """
    Verify a password against a stored bcrypt hash.
    
    Args:
        password: Plain text password string to verify
        hashed: Stored bcrypt hash (UTF-8 string)
        
    Returns:
        bool: True if password matches hash, False otherwise
    """
    password_bytes = password.encode('utf-8')
    hashed_bytes = hashed.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_bytes)


def validate_password_strength(password: str) -> Tuple[bool, Optional[str]]:
    """
    Validate password meets minimum requirements.
    
    Args:
        password: Plain text password to validate
        
    Returns:
        tuple: (is_valid, error_message)
        - If valid: (True, None)
        - If invalid: (False, error_message)
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long"
    return True, None


def hash_token(raw_token: str) -> str:
    """
    Hash a raw token using HMAC-SHA256 with server secret.
    
    Args:
        raw_token: Raw token string to hash
        
    Returns:
        str: Hex-encoded HMAC-SHA256 hash
    """
    secret_bytes = SERVER_SECRET.encode('utf-8')
    token_bytes = raw_token.encode('utf-8')
    hash_bytes = hmac.new(secret_bytes, token_bytes, hashlib.sha256).digest()
    return hash_bytes.hex()


def generate_reset_token() -> Tuple[str, str]:
    """
    Generate a new password reset token.
    
    Returns:
        tuple: (raw_token, token_hash)
        - raw_token: The token to send to user (URL-safe base64)
        - token_hash: The hashed token to store in database
    """
    raw_token = secrets.token_urlsafe(32)
    token_hash = hash_token(raw_token)
    return raw_token, token_hash


def check_rate_limit(client_ip: str, email: str) -> Tuple[bool, Optional[str]]:
    """
    Simple in-memory rate limiting for password reset requests.
    
    Args:
        client_ip: Client IP address
        email: User email address
        
    Returns:
        tuple: (is_allowed, error_message)
        - If allowed: (True, None)
        - If rate limited: (False, error_message)
    """
    key = f"{client_ip}:{email.lower()}"
    now = datetime.now(timezone.utc)
    
    # Clean old entries (simple cleanup - in production use TTL)
    expired_keys = [
        k for k, v in _rate_limit_store.items()
        if (now - v['first_request']).total_seconds() > _rate_limit_window_seconds
    ]
    for k in expired_keys:
        del _rate_limit_store[k]
    
    # Check rate limit
    if key in _rate_limit_store:
        entry = _rate_limit_store[key]
        if entry['count'] >= _rate_limit_max_requests:
            return False, "Too many requests. Please try again later."
        entry['count'] += 1
    else:
        _rate_limit_store[key] = {
            'count': 1,
            'first_request': now
        }
    
    return True, None


def create_reset_token(db: Session, user_id: str) -> Tuple[str, PasswordResetToken]:
    """
    Create a new password reset token for a user.
    Invalidates any existing unused tokens for that user.
    
    Args:
        db: Database session
        user_id: UUID string of the user
        
    Returns:
        tuple: (raw_token, token_model)
        - raw_token: The token to send to user
        - token_model: The PasswordResetToken database model
    """
    # Invalidate existing unused tokens for this user
    now = datetime.now(timezone.utc)
    db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user_id,
        PasswordResetToken.used_at.is_(None),
        PasswordResetToken.expires_at > now
    ).update({'used_at': now})
    
    # Generate new token
    raw_token, token_hash = generate_reset_token()
    expires_at = now + timedelta(minutes=PASSWORD_RESET_TOKEN_EXPIRY_MINUTES)
    
    token_model = PasswordResetToken(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires_at
    )
    db.add(token_model)
    db.flush()  # Flush to get ID, but don't commit yet
    
    return raw_token, token_model


def consume_reset_token(db: Session, raw_token: str) -> Optional[str]:
    """
    Consume a password reset token (one-time use).
    Checks expiration and marks token as used.
    
    Args:
        db: Database session
        raw_token: Raw token string from user
        
    Returns:
        Optional[str]: User ID (UUID string) if token is valid, None otherwise
    """
    token_hash = hash_token(raw_token)
    now = datetime.now(timezone.utc)
    
    # Find token
    token = db.query(PasswordResetToken).filter(
        PasswordResetToken.token_hash == token_hash,
        PasswordResetToken.used_at.is_(None),
        PasswordResetToken.expires_at > now
    ).first()
    
    if not token:
        return None
    
    # Mark as used
    token.used_at = now
    db.flush()
    
    return str(token.user_id)


def send_password_reset_email(to_email: str, reset_url: str) -> None:
    """
    Send password reset email to user via Resend.
    
    Args:
        to_email: Recipient email address
        reset_url: Full URL to reset password page with token
    
    Note:
        Email failures are logged but do not raise exceptions.
        Password reset flow continues even if email send fails.
    """
    try:
        from services.email_service import send_password_reset_email_resend
        send_password_reset_email_resend(to_email, reset_url)
    except Exception as e:
        # Log error but don't raise exception (password reset flow should not fail due to email)
        logger.error(f"PASSWORD_RESET_EMAIL_FAILED to={to_email} error={str(e)}", exc_info=True)


def get_reset_url(token: str) -> str:
    """
    Build password reset URL from token.
    
    Args:
        token: Raw reset token
        
    Returns:
        str: Full URL to reset password page
    """
    base_url = os.getenv("APP_PUBLIC_BASE_URL", "http://localhost:5173")
    return f"{base_url}/reset-password?token={token}"


# ============================================================================
# USER INVITE TOKEN FUNCTIONS (Phase A: Tenant User Management)
# ============================================================================

def create_invite_token(db: Session, user_id: str, created_by_user_id: Optional[str] = None) -> Tuple[str, UserInviteToken]:
    """
    Create a new user invite token for a user.
    Does NOT invalidate existing unused tokens (allows re-invites).
    
    Args:
        db: Database session
        user_id: UUID string of the user being invited
        created_by_user_id: Optional UUID string of the user who created the invite
        
    Returns:
        tuple: (raw_token, token_model)
        - raw_token: The token to send to user
        - token_model: The UserInviteToken database model
    """
    import uuid as uuid_module
    
    # Generate new token
    raw_token, token_hash = generate_reset_token()  # Reuse same token generation logic
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=USER_INVITE_TOKEN_EXPIRY_DAYS)
    
    # Convert user_id and created_by_user_id to UUID if they're strings
    user_id_uuid = user_id if isinstance(user_id, uuid_module.UUID) else uuid_module.UUID(user_id)
    created_by_uuid = None
    if created_by_user_id:
        created_by_uuid = created_by_user_id if isinstance(created_by_user_id, uuid_module.UUID) else uuid_module.UUID(created_by_user_id)
    
    token_model = UserInviteToken(
        user_id=user_id_uuid,
        token_hash=token_hash,
        expires_at=expires_at,
        created_by_user_id=created_by_uuid
    )
    db.add(token_model)
    db.flush()  # Flush to get ID, but don't commit yet
    
    return raw_token, token_model


def consume_invite_token(db: Session, raw_token: str) -> Optional[str]:
    """
    Consume a user invite token (one-time use).
    Checks expiration and marks token as used.
    
    Args:
        db: Database session
        raw_token: Raw token string from user
        
    Returns:
        Optional[str]: User ID (UUID string) if token is valid, None otherwise
    """
    token_hash = hash_token(raw_token)
    now = datetime.now(timezone.utc)
    
    # Find token
    token = db.query(UserInviteToken).filter(
        UserInviteToken.token_hash == token_hash,
        UserInviteToken.used_at.is_(None),
        UserInviteToken.expires_at > now
    ).first()
    
    if not token:
        return None
    
    # Mark as used
    token.used_at = now
    db.flush()
    
    return str(token.user_id)


def send_invite_email(to_email: str, invite_url: str) -> None:
    """
    Send user invite email.
    
    In development: logs the invite URL to server logs.
    In production: should integrate with email provider (SendGrid, SES, etc.).
    
    Args:
        to_email: Recipient email address
        invite_url: Full URL to accept invite page with token
    """
    # For now, log to server logs (development mode)
    # In production, integrate with email service
    # Use WARNING level so it always shows (default log level is WARNING)
    logger.warning(
        f"[USER_INVITE] Invite link for {to_email}: {invite_url}\n"
        f"NOTE: In production, this should be sent via email service."
    )
    
    # TODO: Integrate with email provider when available
    # Example:
    # if os.getenv("EMAIL_PROVIDER") == "sendgrid":
    #     sendgrid_send_email(to_email, "You're invited to ScopeTraceAI", f"Click here to accept: {invite_url}")
    # elif os.getenv("EMAIL_PROVIDER") == "ses":
    #     ses_send_email(to_email, "You're invited to ScopeTraceAI", f"Click here to accept: {invite_url}")


def get_invite_url(token: str) -> str:
    """
    Build user invite URL from token.
    
    Args:
        token: Raw invite token
        
    Returns:
        str: Full URL to accept invite page
    """
    base_url = os.getenv("APP_BASE_URL") or os.getenv("APP_PUBLIC_BASE_URL", "http://localhost:5173")
    return f"{base_url}/invite?token={token}"
