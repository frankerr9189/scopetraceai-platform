#!/usr/bin/env python3
"""
Script to manually reset a user's password in test/development environment.

Usage:
    python reset_password.py <email> [new_password]

If new_password is not provided, generates a reset token and prints it.
If new_password is provided, directly resets the password.
"""

import sys
import os

# Add parent directory to path to import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db import get_db, PSYCOPG_DSN
from models import TenantUser, PasswordResetToken
from services.auth import create_reset_token, hash_password, get_reset_url
from sqlalchemy import func
from datetime import datetime, timezone

def reset_password(email: str, new_password: str = None):
    """Reset password for a user."""
    db = next(get_db())
    try:
        # Find user by email (case-insensitive)
        user = db.query(TenantUser).filter(
            func.lower(TenantUser.email) == email.lower(),
            TenantUser.is_active == True
        ).first()
        
        if not user:
            print(f"❌ User with email '{email}' not found or not active")
            return False
        
        print(f"✅ Found user: {user.email} (ID: {user.id})")
        
        if new_password:
            # Direct password reset
            user.password_hash = hash_password(new_password)
            user.updated_at = datetime.now(timezone.utc)
            db.commit()
            print(f"✅ Password reset successfully for {user.email}")
            return True
        else:
            # Generate reset token
            raw_token, token_model = create_reset_token(db, str(user.id))
            db.commit()
            
            reset_url = get_reset_url(raw_token)
            
            print(f"\n✅ Reset token generated for {user.email}")
            print(f"\n📧 Reset URL:")
            print(f"   {reset_url}")
            print(f"\n🔑 Token (for API use):")
            print(f"   {raw_token}")
            print(f"\n💡 To reset password via API:")
            print(f"   POST /api/v1/auth/reset-password")
            print(f"   Body: {{'token': '{raw_token}', 'new_password': 'your-new-password'}}")
            print(f"\n⏰ Token expires in 30 minutes")
            return True
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        db.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python reset_password.py <email> [new_password]")
        print("\nExamples:")
        print("  # Generate reset token:")
        print("  python reset_password.py user@example.com")
        print("\n  # Directly reset password:")
        print("  python reset_password.py user@example.com 'NewPassword123!'")
        sys.exit(1)
    
    email = sys.argv[1]
    new_password = sys.argv[2] if len(sys.argv) > 2 else None
    
    if new_password and len(new_password) < 12:
        print("❌ Password must be at least 12 characters long")
        sys.exit(1)
    
    success = reset_password(email, new_password)
    sys.exit(0 if success else 1)
