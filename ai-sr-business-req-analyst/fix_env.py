#!/usr/bin/env python3
"""
Helper script to verify and fix .env file configuration.
"""
import os
from pathlib import Path

def fix_env_file():
    """Check and fix .env file in project root."""
    project_root = Path(__file__).parent
    env_file = project_root / ".env"
    
    print(f"Checking .env file at: {env_file}")
    
    # Read existing .env if it exists
    env_vars = {}
    if env_file.exists():
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    env_vars[key.strip()] = value.strip()
        print(f"Found existing .env with {len(env_vars)} variables")
    else:
        print("No .env file found, creating new one")
    
    # Check for required variables
    required_vars = {
        'OPENAI_API_KEY': env_vars.get('OPENAI_API_KEY', ''),
        'OPENAI_MODEL': env_vars.get('OPENAI_MODEL', 'gpt-4o-mini'),
    }
    
    # Check if API key is missing or empty
    if not required_vars['OPENAI_API_KEY']:
        print("\n⚠️  OPENAI_API_KEY is not set!")
        api_key = input("Please enter your OpenAI API key (or press Enter to skip): ").strip()
        if api_key:
            required_vars['OPENAI_API_KEY'] = api_key
        else:
            print("⚠️  OPENAI_API_KEY will remain unset. You'll need to set it manually.")
    
    # Write/update .env file
    env_lines = [
        "# OpenAI Configuration",
        f"OPENAI_API_KEY={required_vars['OPENAI_API_KEY']}",
        f"OPENAI_MODEL={required_vars['OPENAI_MODEL']}",
        "",
        "# Application Configuration",
        f"DEBUG={env_vars.get('DEBUG', 'false')}",
        f"LOG_LEVEL={env_vars.get('LOG_LEVEL', 'INFO')}",
        "",
        "# API Configuration",
        f"API_TITLE={env_vars.get('API_TITLE', 'AI Senior Business Requirement Analyst')}",
        f"API_VERSION={env_vars.get('API_VERSION', '0.1.0')}",
    ]
    
    with open(env_file, 'w') as f:
        f.write('\n'.join(env_lines))
    
    print(f"\n✅ .env file updated at: {env_file}")
    print(f"   OPENAI_API_KEY: {'SET' if required_vars['OPENAI_API_KEY'] else 'NOT SET'}")
    print(f"   OPENAI_MODEL: {required_vars['OPENAI_MODEL']}")
    
    # Verify it can be loaded
    try:
        from dotenv import load_dotenv
        load_dotenv(env_file)
        api_key = os.getenv('OPENAI_API_KEY')
        if api_key:
            print(f"\n✅ Verified: OPENAI_API_KEY is loaded correctly")
        else:
            print(f"\n⚠️  Warning: OPENAI_API_KEY is still not set after reload")
    except ImportError:
        print("\n⚠️  Could not verify (python-dotenv not available in this environment)")

if __name__ == "__main__":
    fix_env_file()

