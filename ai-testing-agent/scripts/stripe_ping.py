#!/usr/bin/env python3
"""
Minimal Stripe connectivity check script.

This script verifies that Stripe API connectivity is working by:
1. Loading STRIPE_SECRET_KEY from .env
2. Initializing the Stripe SDK
3. Making a simple API call to retrieve account information

Usage:
    python scripts/stripe_ping.py

Requirements:
    - .env file at repo root with STRIPE_SECRET_KEY
    - stripe==10.* package installed
    - python-dotenv package installed
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

try:
    import stripe
except ImportError:
    print("ERROR: stripe package not found. Install with: pip install stripe==10.*")
    sys.exit(1)


def main():
    """Main function to check Stripe connectivity."""
    # Get repo root directory (parent of scripts/)
    repo_root = Path(__file__).parent.parent
    env_path = repo_root / ".env"
    
    # Load environment variables from .env
    if not env_path.exists():
        print(f"ERROR: .env file not found at {env_path}")
        print("Please create .env file at repo root with STRIPE_SECRET_KEY")
        sys.exit(1)
    
    load_dotenv(env_path)
    
    # Read STRIPE_SECRET_KEY
    stripe_secret_key = os.getenv("STRIPE_SECRET_KEY")
    if not stripe_secret_key:
        print("ERROR: STRIPE_SECRET_KEY not found in .env file")
        print("Please add STRIPE_SECRET_KEY to your .env file")
        sys.exit(1)
    
    # Initialize Stripe SDK
    stripe.api_key = stripe_secret_key
    
    # Make a simple API call to verify connectivity
    try:
        account = stripe.Account.retrieve()
        account_id = account.id
        print(f"Stripe OK: {account_id}")
        sys.exit(0)
    except stripe.error.StripeError as e:
        print(f"ERROR: Stripe API call failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
