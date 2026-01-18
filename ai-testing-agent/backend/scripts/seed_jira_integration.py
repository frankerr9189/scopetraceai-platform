#!/usr/bin/env python3
"""
Seed script for creating a Jira integration for the development tenant.

This script creates or updates a Jira integration for the dev tenant.
It is idempotent - safe to run multiple times.

SAFETY CONSTRAINTS:
- Requires ENVIRONMENT=development (exits otherwise)

Environment Variables:
- SEED_JIRA_BASE_URL (required)
- SEED_JIRA_EMAIL (required)
- SEED_JIRA_API_TOKEN (required)
- INTEGRATION_SECRET_KEY (required for encryption)

Usage:
    cd ai-testing-agent/backend
    source venv/bin/activate
    export ENVIRONMENT=development
    export INTEGRATION_SECRET_KEY=<your-fernet-key>
    export SEED_JIRA_BASE_URL=https://your-domain.atlassian.net
    export SEED_JIRA_EMAIL=your-email@example.com
    export SEED_JIRA_API_TOKEN=your-api-token
    python3 scripts/seed_jira_integration.py
"""
import os
import sys
from dotenv import load_dotenv

# Add parent directory to path to import backend modules
script_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.dirname(script_dir)
sys.path.insert(0, backend_dir)

from db import SessionLocal
from models import Tenant, TenantIntegration
from utils.encryption import encrypt_secret

# Load environment variables
try:
    load_dotenv()
except (PermissionError, OSError):
    pass


def validate_environment():
    """
    Validate that script is running in development environment.
    
    Raises:
        SystemExit: If not in development environment
    """
    env = os.getenv("ENVIRONMENT", "").lower()
    if env != "development":
        print("ERROR: This script can only be run in development environment.")
        print(f"Current ENVIRONMENT: {env}")
        print("Set ENVIRONMENT=development to proceed.")
        sys.exit(1)


def get_seed_config():
    """
    Get seed configuration from environment variables.
    
    Returns:
        dict with tenant_slug, jira_base_url, jira_email, jira_api_token
    
    Raises:
        SystemExit: If required env vars are missing
    """
    tenant_slug = os.getenv("SEED_TENANT_SLUG", "kerr-ai-studio")
    jira_base_url = os.getenv("SEED_JIRA_BASE_URL")
    jira_email = os.getenv("SEED_JIRA_EMAIL")
    jira_api_token = os.getenv("SEED_JIRA_API_TOKEN")
    
    if not jira_base_url:
        print("ERROR: SEED_JIRA_BASE_URL environment variable is required")
        sys.exit(1)
    
    if not jira_email:
        print("ERROR: SEED_JIRA_EMAIL environment variable is required")
        sys.exit(1)
    
    if not jira_api_token:
        print("ERROR: SEED_JIRA_API_TOKEN environment variable is required")
        sys.exit(1)
    
    # Normalize email
    jira_email = jira_email.lower().strip()
    
    return {
        "tenant_slug": tenant_slug,
        "jira_base_url": jira_base_url.strip(),
        "jira_email": jira_email,
        "jira_api_token": jira_api_token
    }


def seed_jira_integration():
    """
    Create or update Jira integration for the dev tenant.
    """
    validate_environment()
    config = get_seed_config()
    
    db = SessionLocal()
    try:
        # Find tenant by slug
        tenant = db.query(Tenant).filter(Tenant.slug == config["tenant_slug"]).first()
        
        if not tenant:
            # Fallback to first tenant
            tenant = db.query(Tenant).order_by(Tenant.created_at.asc()).first()
            if not tenant:
                print("ERROR: No tenant found. Please run seed_superuser.py first.")
                sys.exit(1)
            print(f"⚠ WARNING: Tenant with slug '{config['tenant_slug']}' not found.")
            print(f"Using first tenant: '{tenant.name}' (slug: {tenant.slug}, id: {tenant.id})")
        else:
            print(f"\n✓ Found tenant '{tenant.name}' (slug: {tenant.slug}, id: {tenant.id})")
        
        # Check if integration already exists
        integration = db.query(TenantIntegration).filter(
            TenantIntegration.tenant_id == tenant.id,
            TenantIntegration.provider == 'jira'
        ).first()
        
        # Encrypt API token
        try:
            encrypted_token = encrypt_secret(config["jira_api_token"])
        except Exception as e:
            print(f"ERROR: Failed to encrypt Jira API token: {str(e)}")
            sys.exit(1)
        
        if integration:
            # Update existing integration
            integration.jira_base_url = config["jira_base_url"]
            integration.jira_user_email = config["jira_email"]
            integration.credentials_ciphertext = encrypted_token
            integration.is_active = True
            db.commit()
            db.refresh(integration)
            print(f"\n✓ Updated Jira integration for tenant '{tenant.name}'")
            print(f"  - Base URL: {config['jira_base_url']}")
            print(f"  - Email: {config['jira_email']}")
            print(f"  - Credentials: encrypted (not displayed)")
        else:
            # Create new integration
            integration = TenantIntegration(
                tenant_id=tenant.id,
                provider='jira',
                is_active=True,
                jira_base_url=config["jira_base_url"],
                jira_user_email=config["jira_email"],
                credentials_ciphertext=encrypted_token,
                credentials_version=1
            )
            db.add(integration)
            db.commit()
            db.refresh(integration)
            print(f"\n✓ Created Jira integration for tenant '{tenant.name}'")
            print(f"  - Base URL: {config['jira_base_url']}")
            print(f"  - Email: {config['jira_email']}")
            print(f"  - Credentials: encrypted (not displayed)")
            print(f"  - Integration ID: {integration.id}")
        
        print("\n✓ Jira integration seeded successfully")
        
    except Exception as e:
        db.rollback()
        print(f"\n✗ ERROR: Failed to seed Jira integration: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    seed_jira_integration()
