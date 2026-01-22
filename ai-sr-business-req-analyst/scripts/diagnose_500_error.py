#!/usr/bin/env python3
"""
Diagnostic script to identify why BA Requirements Agent is returning 500 errors.
Run this on the production server or locally with production environment variables.
"""
import os
import sys
from pathlib import Path

print("=" * 60)
print("BA Requirements Agent - 500 Error Diagnostic")
print("=" * 60)
print()

# Check environment variables
print("1. Checking Environment Variables...")
print("-" * 60)

required_vars = {
    "INTERNAL_SERVICE_KEY": "Required for service-to-service authentication",
    "OPENAI_API_KEY": "Required for LLM calls",
    "DATABASE_URL": "Required for database access (run records, usage tracking)",
    "JWT_SECRET": "Required for JWT operations (if needed)"
}

missing_vars = []
for var_name, description in required_vars.items():
    value = os.getenv(var_name)
    if value:
        # Show first/last chars for security
        masked = f"{value[:4]}...{value[-4:]}" if len(value) > 8 else "***"
        print(f"  ✅ {var_name}: SET ({masked})")
    else:
        print(f"  ❌ {var_name}: NOT SET - {description}")
        missing_vars.append(var_name)

print()

# Check if we can import critical modules
print("2. Checking Module Imports...")
print("-" * 60)

try:
    from app.middleware.internal_auth import verify_internal_service_key
    print("  ✅ Internal auth middleware: OK")
except ImportError as e:
    print(f"  ❌ Internal auth middleware: FAILED - {e}")

try:
    from app.agent.analyst import BusinessRequirementAnalyst
    print("  ✅ BusinessRequirementAnalyst: OK")
except ImportError as e:
    print(f"  ❌ BusinessRequirementAnalyst: FAILED - {e}")

try:
    from app.services.llm_client import analyze_requirements
    print("  ✅ LLM client: OK")
except ImportError as e:
    print(f"  ❌ LLM client: FAILED - {e}")

print()

# Check database connection
print("3. Checking Database Connection...")
print("-" * 60)

db_url = os.getenv("DATABASE_URL")
if db_url:
    try:
        # Try to import and connect
        import sys
        current_file = Path(__file__).resolve()
        project_root = current_file.parent.parent
        backend_path = project_root.parent / "ai-testing-agent" / "backend"
        
        if backend_path.exists():
            sys.path.insert(0, str(backend_path))
            from db import get_db, engine
            from sqlalchemy import text
            
            db = next(get_db())
            try:
                # Try a simple query
                result = db.execute(text("SELECT 1"))
                result.fetchone()
                print("  ✅ Database connection: OK")
            except Exception as e:
                print(f"  ❌ Database connection: FAILED - {e}")
            finally:
                db.close()
        else:
            print(f"  ⚠️  Testing agent backend not found at {backend_path}")
            print("     (This is OK if running standalone, but DB features won't work)")
    except Exception as e:
        print(f"  ❌ Database setup: FAILED - {e}")
else:
    print("  ⚠️  DATABASE_URL not set - skipping database check")

print()

# Check OpenAI API key validity
print("4. Checking OpenAI API Key...")
print("-" * 60)

openai_key = os.getenv("OPENAI_API_KEY")
if openai_key:
    # Check if it looks valid (starts with sk-)
    if openai_key.startswith("sk-"):
        print("  ✅ OpenAI API key format: Valid (starts with sk-)")
        # Try a simple validation (just check if we can create a client)
        try:
            from openai import OpenAI
            client = OpenAI(api_key=openai_key)
            print("  ✅ OpenAI client creation: OK")
        except Exception as e:
            print(f"  ⚠️  OpenAI client creation: {e}")
    else:
        print(f"  ⚠️  OpenAI API key format: Unexpected (doesn't start with sk-)")
else:
    print("  ❌ OpenAI API key: NOT SET")

print()

# Check internal service key
print("5. Checking Internal Service Key...")
print("-" * 60)

internal_key = os.getenv("INTERNAL_SERVICE_KEY")
if internal_key:
    if len(internal_key) >= 16:
        print(f"  ✅ Internal service key: SET (length: {len(internal_key)})")
    else:
        print(f"  ⚠️  Internal service key: Too short (length: {len(internal_key)})")
else:
    print("  ❌ Internal service key: NOT SET")

print()

# Summary
print("=" * 60)
print("Summary")
print("=" * 60)

if missing_vars:
    print(f"❌ Missing required environment variables: {', '.join(missing_vars)}")
    print()
    print("To fix:")
    for var in missing_vars:
        print(f"  - Set {var} in your production environment")
else:
    print("✅ All required environment variables are set")
    print()
    print("If you're still getting 500 errors, check:")
    print("  1. Server logs for detailed error messages")
    print("  2. That INTERNAL_SERVICE_KEY matches between services")
    print("  3. That OPENAI_API_KEY is valid and has credits")
    print("  4. That DATABASE_URL is accessible from the BA agent server")

print()
