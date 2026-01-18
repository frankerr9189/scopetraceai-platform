#!/usr/bin/env python3
"""
Test script to verify config loading.
"""
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

try:
    from app.config import settings
    print("✅ Config loaded successfully")
    print(f"   OPENAI_API_KEY: {'SET' if settings.openai_api_key else 'NOT SET'}")
    print(f"   OPENAI_MODEL: {settings.openai_model}")
    print(f"   API_VERSION: {settings.api_version}")
    
    if settings.openai_api_key:
        # Mask the key for security
        masked_key = settings.openai_api_key[:7] + "..." + settings.openai_api_key[-4:] if len(settings.openai_api_key) > 11 else "***"
        print(f"   API Key (masked): {masked_key}")
    else:
        print("\n❌ ERROR: OPENAI_API_KEY is not set!")
        print("   Please check your .env file in the project root")
        sys.exit(1)
except Exception as e:
    print(f"❌ Error loading config: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

