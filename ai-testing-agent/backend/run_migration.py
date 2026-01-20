#!/usr/bin/env python3
"""
Script to run Alembic migrations.
Usage: python3 run_migration.py
"""
import os
import sys

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

from app import app
from flask_migrate import upgrade

with app.app_context():
    print("Running database migrations...")
    upgrade()
    print("✓ Migrations complete!")
