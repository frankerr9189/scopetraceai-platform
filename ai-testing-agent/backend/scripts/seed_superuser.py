#!/usr/bin/env python3
"""
Seed script for creating a tenant and superuser.

This script creates a tenant and a superuser account for development/testing.
It is idempotent - safe to run multiple times.

SAFETY CONSTRAINTS:
- Requires ENVIRONMENT=development (exits otherwise)

Environment Variables:
- SEED_TENANT_NAME (default: "Demo Client")
- SEED_SUPERUSER_EMAIL (required)
- SEED_SUPERUSER_PASSWORD (required)
- SEED_SUPERUSER_ROLE (default: "owner")

Usage:
    cd ai-testing-agent/backend
    source venv/bin/activate
    export ENVIRONMENT=development
    export SEED_SUPERUSER_EMAIL=admin@example.com
    export SEED_SUPERUSER_PASSWORD=securepassword123
    python3 scripts/seed_superuser.py
"""
import os
import sys
from dotenv import load_dotenv
import bcrypt

# Add parent directory to path to import backend modules
script_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.dirname(script_dir)
sys.path.insert(0, backend_dir)

from db import SessionLocal
from models import Tenant, TenantUser
from utils.slugify import slugify

# Load environment variables
try:
    load_dotenv()
except (PermissionError, OSError):
    pass


def validate_environment():
    """
    Validate that script is running in development environment.
    
    Raises:
        SystemExit: If ENVIRONMENT is not development
    """
    environment = os.getenv("ENVIRONMENT", "").lower()
    if environment != "development":
        print("ERROR: This script can only run in development environment.")
        print(f"Current ENVIRONMENT: {environment or '(not set)'}")
        print("Set ENVIRONMENT=development to proceed.")
        sys.exit(1)
    
    print(f"✓ Environment check passed: ENVIRONMENT={environment}")


def get_seed_config():
    """
    Get seed configuration from environment variables.
    
    Returns:
        dict: Configuration with tenant_name, email, password, role
        
    Raises:
        SystemExit: If required environment variables are missing or invalid
    """
    tenant_name = os.getenv("SEED_TENANT_NAME", "Demo Client")
    email = os.getenv("SEED_SUPERUSER_EMAIL", "").strip()
    password = os.getenv("SEED_SUPERUSER_PASSWORD", "").strip()
    role_raw = os.getenv("SEED_SUPERUSER_ROLE", "owner")
    
    if not email:
        print("ERROR: SEED_SUPERUSER_EMAIL environment variable is required.")
        sys.exit(1)
    
    if not password:
        print("ERROR: SEED_SUPERUSER_PASSWORD environment variable is required.")
        sys.exit(1)
    
    # Normalize email to lowercase and trim
    email = email.lower().strip()
    
    # Normalize role: strip whitespace and lowercase
    role = role_raw.strip().lower()
    
    # Enforce allowed roles only
    allowed_roles = {"owner", "admin", "user", "superAdmin"}
    if role not in allowed_roles:
        print("ERROR: Invalid SEED_SUPERUSER_ROLE.")
        print(f"  Provided: '{role_raw}' (normalized: '{role}')")
        print(f"  Allowed roles: {', '.join(sorted(allowed_roles))}")
        sys.exit(1)
    
    return {
        "tenant_name": tenant_name,
        "email": email,
        "password": password,
        "role": role,
    }


def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt.
    
    Args:
        password: Plain text password string
        
    Returns:
        str: Bcrypt hashed password as UTF-8 string (for storage in Postgres)
    """
    # Convert password string to bytes with UTF-8 encoding
    password_bytes = password.encode('utf-8')
    
    # Generate salt
    salt = bcrypt.gensalt()
    
    # Hash password with salt
    hashed_bytes = bcrypt.hashpw(password_bytes, salt)
    
    # Decode to UTF-8 string for clean storage in Postgres
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
    # Convert inputs to bytes
    password_bytes = password.encode('utf-8')
    hashed_bytes = hashed.encode('utf-8')
    
    # Verify password against hash
    return bcrypt.checkpw(password_bytes, hashed_bytes)


def find_or_create_tenant_with_collision_handling(db, tenant_name: str):
    """
    Find existing tenant or create new one with collision-safe slug generation.
    
    Idempotent: If tenant with base slug exists, ALWAYS reuse it (regardless of name).
    Collision-safe: Only generate slug-2, slug-3, etc. when base_slug is NOT available
    AND we are creating a new tenant but the candidate slug is already taken.
    
    Args:
        db: Database session
        tenant_name: Name of the tenant to find or create
        
    Returns:
        tuple: (tenant, was_created: bool, final_slug: str)
    """
    base_slug = slugify(tenant_name)
    
    # ALWAYS reuse tenant if base_slug exists (idempotent - no duplicate tenants)
    existing_tenant = db.query(Tenant).filter(Tenant.slug == base_slug).first()
    if existing_tenant:
        return existing_tenant, False, base_slug
    
    # Base slug is NOT available, find an unused slug starting from base_slug
    # Only generate slug-2, slug-3, etc. when candidate slug is already taken
    counter = 1
    
    while True:
        if counter == 1:
            final_slug = base_slug
        else:
            final_slug = f"{base_slug}-{counter}"
        
        # Check if this slug is available
        existing = db.query(Tenant).filter(Tenant.slug == final_slug).first()
        if not existing:
            # Slug is available, create tenant
            tenant = Tenant(
                name=tenant_name,
                slug=final_slug,
                is_active=True,
            )
            db.add(tenant)
            db.commit()
            db.refresh(tenant)
            
            # Create tenant_billing row (single source of truth for billing data)
            # Initialize with plan_tier="unselected", status="incomplete" (enforces onboarding gate)
            try:
                from services.entitlements_centralized import create_tenant_billing_row
                create_tenant_billing_row(db, str(tenant.id), "unselected", None)  # None -> defaults to "unselected"
            except Exception as e:
                print(f"Warning: Failed to create tenant_billing row: {e}")
                # Continue - tenant is created, billing row can be created later if needed
            
            return tenant, True, final_slug
        
        # Slug is taken, try next variant
        counter += 1


def seed_tenant_and_superuser(config: dict):
    """
    Seed tenant and superuser (idempotent).
    
    Args:
        config: Configuration dict with tenant_name, email, password, role
    """
    db = SessionLocal()
    try:
        # Find or create tenant with collision-safe slug handling
        tenant, was_created, final_slug = find_or_create_tenant_with_collision_handling(
            db, config["tenant_name"]
        )
        
        if was_created:
            print(f"\n✓ Created tenant '{config['tenant_name']}' (slug: {final_slug}, id: {tenant.id})")
        else:
            print(f"\n✓ Selected existing tenant '{config['tenant_name']}' (slug: {final_slug}, id: {tenant.id})")
        
        # Check if tenant user exists by (tenant_id, email)
        tenant_user = db.query(TenantUser).filter(
            TenantUser.tenant_id == tenant.id,
            TenantUser.email == config["email"]
        ).first()
        
        if tenant_user:
            print(f"✓ Tenant user '{config['email']}' already exists for tenant '{config['tenant_name']}'")
        else:
            # Hash password
            password_hash = hash_password(config["password"])
            
            # Create tenant user
            tenant_user = TenantUser(
                tenant_id=tenant.id,
                email=config["email"],
                password_hash=password_hash,
                role=config["role"],
                is_active=True,
            )
            db.add(tenant_user)
            db.commit()
            db.refresh(tenant_user)
            
            # Self-check: verify the stored hash matches the password (non-fatal)
            try:
                if verify_password(config["password"], tenant_user.password_hash):
                    print(f"✓ Created tenant user '{config['email']}' with role '{config['role']}'")
                    print(f"  ✓ Password hash verified (password not displayed)")
                else:
                    print(f"⚠ WARNING: Created tenant user '{config['email']}' but password verification failed")
                    print(f"  This may indicate a hashing issue. Please investigate.")
            except Exception as verify_error:
                print(f"⚠ WARNING: Created tenant user '{config['email']}' but password verification raised error: {verify_error}")
                print(f"  User was created, but verification check failed. Please investigate.")
        
        print("\n" + "=" * 60)
        print("✓ Seeding complete!")
        print("=" * 60)
        
    except Exception as e:
        db.rollback()
        print(f"ERROR: Failed to seed tenant/superuser: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        db.close()


def main():
    """Main entry point for the seed script."""
    print("=" * 60)
    print("Tenant & Superuser Seeding Script")
    print("=" * 60)
    print()
    
    # Validate environment
    validate_environment()
    
    # Get configuration
    config = get_seed_config()
    
    print(f"\nConfiguration:")
    print(f"  Tenant name: {config['tenant_name']}")
    print(f"  Email: {config['email']}")
    print(f"  Role: {config['role']}")
    print(f"  Password: {'*' * len(config['password'])} (hidden)")
    
    # Seed tenant and superuser
    seed_tenant_and_superuser(config)


if __name__ == "__main__":
    main()
