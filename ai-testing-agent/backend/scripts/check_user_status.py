#!/usr/bin/env python3
"""
Quick script to check if a user exists and their status.
Usage: python3 scripts/check_user_status.py <email>
"""
import os
import sys
from sqlalchemy import func
from dotenv import load_dotenv

# Load environment variables
try:
    env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
    load_dotenv(env_path, override=True)
    load_dotenv(override=False)
except (PermissionError, OSError):
    pass

from db import get_db
from models import TenantUser, Tenant

if len(sys.argv) < 2:
    print("Usage: python3 scripts/check_user_status.py <email>")
    sys.exit(1)

email = sys.argv[1].lower().strip()

db = next(get_db())
try:
    users = db.query(TenantUser).filter(
        func.lower(TenantUser.email) == email
    ).all()
    
    if not users:
        print(f"❌ No user found with email: {email}")
        sys.exit(1)
    
    print(f"Found {len(users)} user(s) with email: {email}\n")
    
    for user in users:
        tenant = db.query(Tenant).filter(Tenant.id == user.tenant_id).first()
        print(f"User ID: {user.id}")
        print(f"Email: {user.email}")
        print(f"Tenant: {tenant.name if tenant else 'N/A'} ({tenant.slug if tenant else 'N/A'})")
        print(f"Role: {user.role}")
        print(f"Active: {'✅ YES' if user.is_active else '❌ NO (needs to accept invite)'}")
        print(f"Has Password: {'✅ YES' if user.password_hash else '❌ NO'}")
        print(f"Created: {user.created_at}")
        print(f"Last Login: {user.last_login_at or 'Never'}")
        print("-" * 50)
        
finally:
    db.close()
