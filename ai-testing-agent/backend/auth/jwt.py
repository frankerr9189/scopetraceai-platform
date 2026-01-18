"""
JWT token creation and verification utilities.
"""
import os
import jwt
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple


# JWT configuration
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_EXPIRES_MINUTES = int(os.getenv("JWT_EXPIRES_MINUTES", "60"))
JWT_ALGORITHM = "HS256"

# Validate JWT_SECRET is set
if not JWT_SECRET:
    raise RuntimeError(
        "JWT_SECRET environment variable is required. "
        "Please set JWT_SECRET to a secure random string."
    )


def create_access_token(user_id: str, tenant_id: str, role: str, expires_minutes: Optional[int] = None) -> str:
    """
    Create a JWT access token for a user.
    
    Args:
        user_id: UUID string of the user
        tenant_id: UUID string of the tenant
        role: User role (e.g., "owner", "admin", "member")
        expires_minutes: Optional expiration time in minutes (defaults to JWT_EXPIRES_MINUTES)
        
    Returns:
        str: Encoded JWT token
    """
    if expires_minutes is None:
        expires_minutes = JWT_EXPIRES_MINUTES
    
    # Calculate expiration time
    exp = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    
    # Create payload
    payload = {
        "sub": str(user_id),  # Subject (user ID)
        "tenant_id": str(tenant_id),
        "role": role,
        "exp": exp,  # Expiration time
        "iat": datetime.now(timezone.utc),  # Issued at
    }
    
    # Encode and return token
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_and_verify_token(token: str) -> Tuple[Dict, Optional[str]]:
    """
    Decode and verify a JWT token.
    
    Args:
        token: JWT token string
        
    Returns:
        tuple: (payload dict, error_message)
        - If valid: (payload, None)
        - If invalid: (None, error_message)
    """
    try:
        # Decode and verify token
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={"verify_exp": True}
        )
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, "Token has expired"
    except jwt.InvalidTokenError as e:
        return None, f"Invalid token: {str(e)}"
    except Exception as e:
        return None, f"Token verification failed: {str(e)}"
