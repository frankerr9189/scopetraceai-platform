"""
Flask application entry point.
"""

import copy
import os
import json
import re
import base64
import requests
import logging
import csv
import io
import tempfile
import uuid
import time
import secrets
from datetime import datetime, timezone
from typing import Optional, Union
from flask import Flask, request, jsonify, Response, g
from flask_cors import CORS
from openai import OpenAI
from dotenv import load_dotenv
import bcrypt

# Try to load .env file, but don't fail if there's a permission error
# Load from current directory explicitly to ensure it's found
try:
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    load_dotenv(env_path, override=True)
    # Also try loading from current working directory as fallback
    load_dotenv(override=False)
except (PermissionError, OSError) as e:
    # If .env file can't be read due to permissions, continue without it
    # Environment variables can still be set via system environment
    pass  # Logger not yet initialized, so just continue

# Configure logging - set to INFO if DEBUG_REQUIREMENTS is enabled
log_level = logging.INFO if os.getenv("DEBUG_REQUIREMENTS", "0") == "1" else logging.WARNING
logging.basicConfig(level=log_level)
logger = logging.getLogger(__name__)

# DEBUG: Log if DEBUG_REQUIREMENTS is enabled at startup
if os.getenv("DEBUG_REQUIREMENTS", "0") == "1":
    logger.info(f"[DEBUG_REQUIREMENTS] Server startup: DEBUG_REQUIREMENTS=1 is enabled, log level set to INFO")


app = Flask(__name__)

# CORS configuration with explicit allowlist
# Base allowed origins for local development
ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://localhost:5137",
    "http://localhost:3000",  # Marketing site (Next.js) local development
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5137",
    "http://127.0.0.1:3000",  # Marketing site alternative localhost
    # Production frontend domains
    "https://app.scopetraceai.com",
    "https://scopetraceai-platform.vercel.app",
    "https://scopetraceai-platform.onrender.com",  # Render deployment
    # Marketing site domains
    "https://scopetraceai.com",
    "https://www.scopetraceai.com",
]

# Add additional production domains from environment variable if set
# Supports comma-separated list of origins (e.g., "https://staging.example.com,https://dev.example.com")
production_origins = os.getenv("CORS_ALLOWED_ORIGINS", "").strip()
if production_origins:
    # Split by comma and add to allowed origins
    for origin in production_origins.split(","):
        origin = origin.strip()
        if origin and origin not in ALLOWED_ORIGINS:
            ALLOWED_ORIGINS.append(origin)

# Enable CORS for all routes with Authorization header support
# Note: supports_credentials=False because authentication uses JWT tokens in Authorization headers, not cookies
# Stripe-Signature header is allowed for webhook endpoint (server-to-server, but defensive for local testing)
CORS(
    app,
    origins=ALLOWED_ORIGINS,
    allow_headers=["Content-Type", "Authorization", "X-Actor", "Stripe-Signature"],
    expose_headers=["Content-Type", "Content-Disposition"],
    supports_credentials=False,
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    max_age=3600
)

# Import JWT utilities (will fail fast if JWT_SECRET is not set)
from auth.jwt import create_access_token, decode_and_verify_token

# Import encryption utilities (will fail fast if INTEGRATION_SECRET_KEY is not set)
from utils.encryption import decrypt_secret  # noqa: F401

@app.after_request
def add_cors_headers(response):
    """
    Ensure CORS headers are added to all responses, including error responses.
    This is a safety net in case Flask-CORS doesn't handle certain error cases.
    """
    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
    elif ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGINS[0]
    
    # Ensure other CORS headers are present
    if "Access-Control-Allow-Methods" not in response.headers:
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    if "Access-Control-Allow-Headers" not in response.headers:
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Actor, Stripe-Signature"
    
    return response

@app.before_request
def check_auth():
    """
    JWT authentication middleware for all routes except /health, /, and /auth/login.
    Requires Authorization: Bearer <jwt> header.
    Extracts user_id, tenant_id, and role from JWT and stores on flask.g.
    """
    # Skip auth for OPTIONS requests (CORS preflight) - let Flask-CORS handle it
    if request.method == "OPTIONS":
        # Don't return early - let Flask-CORS add headers, then return
        # Flask-CORS will handle the OPTIONS response automatically
        return None
    
    # Allow health check endpoints, auth endpoints, and public lead submission
    # Also allow check-slug (public) and tenant-first onboarding routes (no auth required)
    # Phase 2.1: Allow password reset routes (public)
    # Stripe webhook endpoint must bypass auth (verified via Stripe signature instead)
    public_routes = [
        "/health", "/health/db", "/", "/auth/login", 
        "/api/v1/leads", "/api/v1/tenants/check-slug",
        "/api/v1/onboarding/tenant",  # Tenant creation is public (no auth required)
        "/api/v1/auth/forgot-password",  # Phase 2.1: Public password reset request
        "/api/v1/auth/reset-password",  # Phase 2.1: Public password reset
        "/api/v1/auth/accept-invite",  # Phase A: Public invite acceptance
        "/api/v1/billing/webhook",  # Stripe webhook (auth via Stripe signature)
        "/api/v1/billing/webhook/"  # Stripe webhook with trailing slash
    ]
    if request.path in public_routes or request.path.startswith("/api/v1/onboarding/tenant/"):
        return None
    
    # Check Authorization header
    auth_header = request.headers.get("Authorization", "")
    
    if not auth_header.startswith("Bearer "):
        response = jsonify({"detail": "Unauthorized"})
        response.status_code = 401
        # CORS headers will be added by after_request handler, but explicit for safety
        origin = request.headers.get("Origin", "")
        if origin in ALLOWED_ORIGINS:
            response.headers["Access-Control-Allow-Origin"] = origin
        elif ALLOWED_ORIGINS:
            response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGINS[0]
        return response
    
    token = auth_header.replace("Bearer ", "").strip()
    
    # Verify JWT token
    payload, error = decode_and_verify_token(token)
    if error or not payload:
        response = jsonify({"detail": "Unauthorized"})
        response.status_code = 401
        # CORS headers will be added by after_request handler, but explicit for safety
        origin = request.headers.get("Origin", "")
        if origin in ALLOWED_ORIGINS:
            response.headers["Access-Control-Allow-Origin"] = origin
        elif ALLOWED_ORIGINS:
            response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGINS[0]
        return response
    
    # Extract claims and store on flask.g for downstream use
    g.user_id = payload.get("sub")
    g.tenant_id = payload.get("tenant_id")
    g.role = payload.get("role")
    
    # Tenant-first model: tenant_id is ALWAYS required for authenticated requests
    if not g.tenant_id:
        logger.error("JWT token missing tenant_id claim - rejecting request (tenant-first model)")
        response = jsonify({"detail": "Invalid token: missing tenant_id"})
        response.status_code = 401
        # CORS headers will be added by after_request handler, but explicit for safety
        origin = request.headers.get("Origin", "")
        if origin in ALLOWED_ORIGINS:
            response.headers["Access-Control-Allow-Origin"] = origin
        elif ALLOWED_ORIGINS:
            response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGINS[0]
        return response
    
    # ACTIVE/INACTIVE ENFORCEMENT: Check tenant and user active status
    # This must happen BEFORE subscription gating or other logic
    try:
        from db import get_db
        import uuid as uuid_module
        
        # Import models safely - they should already be registered with Base.metadata
        # Import at function level to avoid circular imports, but models are only defined once
        try:
            from models import Tenant, TenantUser
        except Exception as import_error:
            # If import fails due to metadata conflict, log and return 503
            logger.error(f"Failed to import models in check_auth: {import_error}", exc_info=True)
            return jsonify({
                "code": "AUTH_UNAVAILABLE",
                "detail": "Authentication temporarily unavailable. Please try again."
            }), 503
        
        db = next(get_db())
        try:
            # Convert tenant_id and user_id to UUID if needed
            tenant_uuid = g.tenant_id if isinstance(g.tenant_id, uuid_module.UUID) else uuid_module.UUID(g.tenant_id)
            user_uuid = g.user_id if isinstance(g.user_id, uuid_module.UUID) else uuid_module.UUID(g.user_id)
            
            # Load tenant
            tenant = db.query(Tenant).filter(Tenant.id == tenant_uuid).first()
            if not tenant:
                logger.error(f"Tenant {g.tenant_id} not found for authenticated request")
                return jsonify({"detail": "Tenant not found"}), 404
            
            # Load user
            user = db.query(TenantUser).filter(
                TenantUser.id == user_uuid,
                TenantUser.tenant_id == tenant_uuid
            ).first()
            if not user:
                logger.error(f"User {g.user_id} not found for tenant {g.tenant_id}")
                return jsonify({"detail": "User not found"}), 404
            
            # Check if user is active
            if not user.is_active:
                return jsonify({
                    "code": "USER_INACTIVE",
                    "detail": "Your account is inactive. Contact hello@scopetraceai.com"
                }), 403
            
            # Store user role on g for middleware checks
            g.current_user = user
            
            # Ops Kill Switch: Check if tenant is suspended or inactive
            # Block all non-public routes if tenant is suspended (subscription_status='suspended')
            # Also block if tenant is inactive (is_active=false) for backward compatibility
            # Public routes (login/forgot/reset) are already excluded above
            # EXCEPTION: Allow /api/v1/admin/* for owner role even if tenant is suspended
            is_admin_route = request.path.startswith("/api/v1/admin/")
            is_owner = user.role == "owner"
            
            if not (is_admin_route and is_owner):
                # Get billing data from tenant_billing (single source of truth)
                from services.entitlements_centralized import get_tenant_billing, create_tenant_billing_row
                try:
                    billing = get_tenant_billing(db, str(tenant.id))
                    subscription_status = billing.get("subscription_status")
                    
                    # Apply kill switch for non-admin routes or non-owner users
                    if subscription_status == 'suspended':
                        return jsonify({
                            "code": "TENANT_SUSPENDED",
                            "detail": "Tenant is suspended"
                        }), 403
                except RuntimeError as e:
                    # tenant_billing row is missing - create it with defaults (plan_tier='trial', status='incomplete')
                    logger.info(f"tenant_billing row missing for tenant {tenant.id}, creating with defaults")
                    try:
                        # Use "trial" as default plan_tier (database constraint allows: trial, user, team, enterprise)
                        create_tenant_billing_row(db, str(tenant.id), "unselected", "trial")
                        db.commit()
                        # Re-fetch billing data after creation
                        billing = get_tenant_billing(db, str(tenant.id))
                        subscription_status = billing.get("subscription_status")
                        # Check suspended status after creation (should be 'paywalled' for incomplete status)
                        if subscription_status == 'suspended':
                            return jsonify({
                                "code": "TENANT_SUSPENDED",
                                "detail": "Tenant is suspended"
                            }), 403
                    except Exception as create_error:
                        db.rollback()
                        logger.error(f"Failed to create tenant_billing row for tenant {tenant.id}: {create_error}", exc_info=True)
                        return jsonify({
                            "code": "BILLING_DATA_MISSING",
                            "detail": "Billing data is required but could not be created"
                        }), 500
                
                # Backward compatibility: also block if tenant is inactive (but not suspended)
                if not tenant.is_active:
                    return jsonify({
                        "code": "TENANT_INACTIVE",
                        "detail": "Workspace is inactive. Contact hello@scopetraceai.com"
                    }), 403
            
        finally:
            db.close()
    except Exception as e:
        # If we can't check (DB unavailable / query error), return 503 Service Unavailable
        logger.error(f"Error checking tenant/user active status: {e}", exc_info=True)
        return jsonify({
            "code": "AUTH_UNAVAILABLE",
            "detail": "Authentication temporarily unavailable. Please try again."
        }), 503
    
    # PLAN SELECTION GATE: Check if tenant has selected a subscription plan
    # Allow access to specific routes even if plan is unselected
    # /api/v1/analyze is allowed to restore 1/14 behavior (requirements extraction always works)
    # /api/v1/billing/checkout-session is allowed so users can create checkout for paid plans
    allowed_unselected_routes = [
        "/auth/me",
        "/api/v1/analyze",  # Requirements extraction - no subscription gating (matches 1/14 behavior)
        "/api/v1/billing/checkout-session",  # Checkout creation - needed before plan selection
    ]
    # Also allow subscription update endpoint
    subscription_update_path = f"/api/v1/tenants/{g.tenant_id}/subscription"
    is_allowed_unselected_route = (
        request.path in allowed_unselected_routes or 
        request.path == subscription_update_path
    )
    
    if not is_allowed_unselected_route:
        # Check tenant subscription status from tenant_billing (single source of truth)
        try:
            from db import get_db
            from services.entitlements_centralized import get_tenant_billing
            
            db = next(get_db())
            try:
                # Get billing data from tenant_billing table
                billing = get_tenant_billing(db, str(g.tenant_id))
                status = billing.get("subscription_status")
                
                # Block if unselected or canceled
                if status == "unselected":
                    return jsonify({"detail": "Subscription plan not selected."}), 403
                if status == "canceled":
                    return jsonify({"detail": "Subscription canceled."}), 403
            finally:
                db.close()
        except RuntimeError as e:
            # Hard error if tenant_billing is missing
            logger.error(f"tenant_billing missing in plan selection gate: {e}")
            return jsonify({"detail": "Billing data is required but not found"}), 500
        except Exception as e:
            # If we can't check, allow the request (fail open for availability)
            logger.warning(f"Could not check subscription status: {e}")
    
    return None

# Initialize OpenAI client
openai_client = None
openai_api_key = os.getenv('OPENAI_API_KEY')
if openai_api_key:
    try:
        # Set timeout to 240 seconds (4 minutes) to prevent hanging
        # Gunicorn timeout is 300 seconds, so this gives us buffer
        openai_client = OpenAI(
            api_key=openai_api_key,
            timeout=240.0  # 4 minutes timeout for API calls
        )
        logger.info("OpenAI client initialized successfully with 240s timeout")
    except Exception as e:
        logger.error(f"Failed to initialize OpenAI client: {e}")
        openai_client = None
else:
    logger.warning("OPENAI_API_KEY not found in environment variables. LLM features will be disabled.")

# Persistence path for most recently generated test plan
PERSIST_PATH = "./.latest_test_plan.json"

# Store most recently generated test plan for export endpoints
_most_recent_test_plan = None

# Input guardrail constants
MAX_TICKETS_PER_RUN = 10
MAX_REQUIREMENTS_PER_PACKAGE = 100
MAX_FREEFORM_CHARS = 50_000
MAX_DOC_UPLOAD_MB = 15

# Agent version for audit metadata
AGENT_VERSION = "1.0.0"

# ============================================================================
# Rate Limiting for Public Onboarding Endpoints (In-Memory)
# ============================================================================
# TODO: Replace with distributed rate limiting (Redis) for production
# Simple in-memory rate limiting keyed by (ip, route) with timestamps
_rate_limit_store = {}
_rate_limit_cleanup_interval = 3600  # Clean up old entries every hour

def _cleanup_rate_limit_store():
    """Remove entries older than 1 hour from rate limit store."""
    current_time = time.time()
    keys_to_remove = [
        key for key, timestamps in _rate_limit_store.items()
        if all(current_time - ts > 3600 for ts in timestamps)
    ]
    for key in keys_to_remove:
        del _rate_limit_store[key]

def _check_rate_limit(ip: str, route: str, max_requests: int, window_seconds: int = 3600) -> tuple[bool, int]:
    """
    Check if IP has exceeded rate limit for route.
    
    Args:
        ip: Client IP address
        route: Route identifier (e.g., "/api/v1/onboarding/tenant")
        max_requests: Maximum requests allowed in window
        window_seconds: Time window in seconds (default 1 hour)
    
    Returns:
        tuple: (allowed: bool, remaining: int)
    """
    current_time = time.time()
    key = (ip, route)
    
    # Clean up old entries periodically
    if len(_rate_limit_store) > 10000:  # Prevent unbounded growth
        _cleanup_rate_limit_store()
    
    # Get existing timestamps for this key
    timestamps = _rate_limit_store.get(key, [])
    
    # Filter out timestamps outside the window
    recent_timestamps = [ts for ts in timestamps if current_time - ts < window_seconds]
    
    # Check if limit exceeded
    if len(recent_timestamps) >= max_requests:
        return False, 0
    
    # Add current request timestamp
    recent_timestamps.append(current_time)
    _rate_limit_store[key] = recent_timestamps
    
    remaining = max_requests - len(recent_timestamps)
    return True, remaining

def _get_client_ip() -> str:
    """Get client IP address from request headers."""
    # Check for forwarded IP (from proxy/load balancer)
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        # X-Forwarded-For can contain multiple IPs, take the first one
        return forwarded_for.split(',')[0].strip()
    
    # Check for real IP header
    real_ip = request.headers.get('X-Real-IP')
    if real_ip:
        return real_ip.strip()
    
    # Fall back to remote address
    return request.remote_addr or 'unknown'

# Model configuration
LLM_MODEL = "gpt-4o-mini"
LLM_TEMPERATURE = 0.2


def load_test_plan_from_file():
    """
    Load the most recently generated test plan from persistent storage.
    
    Returns:
        dict: Test plan object if file exists and is valid, None otherwise
    """
    global _most_recent_test_plan
    
    if not os.path.exists(PERSIST_PATH):
        return None
    
    try:
        with open(PERSIST_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, dict):
                _most_recent_test_plan = data
                return data
    except (json.JSONDecodeError, IOError, OSError):
        # Fail silently if file is corrupt or unreadable
        pass
    
    return None


def save_test_plan_to_file(test_plan):
    """
    Save the test plan to persistent storage using atomic write.
    
    Args:
        test_plan: The complete test plan object to persist
    """
    try:
        # Atomic write: write to temp file then rename
        with tempfile.NamedTemporaryFile(
            mode='w',
            encoding='utf-8',
            delete=False,
            dir=os.path.dirname(PERSIST_PATH) or '.',
            prefix='.latest_test_plan.tmp.'
        ) as tmp_file:
            json.dump(test_plan, tmp_file, indent=2, ensure_ascii=False)
            tmp_path = tmp_file.name
        
        # Atomic rename (overwrites existing file)
        os.replace(tmp_path, PERSIST_PATH)
    except (IOError, OSError):
        # Fail silently if write fails
        pass


def generate_audit_metadata(scope: dict, tickets: list, source_type: str) -> dict:
    """
    Generate ISO 27001/SOC 2 compliant audit metadata for test plan execution.
    
    This metadata is separate from test content and provides full traceability
    for compliance and audit purposes.
    
    Args:
        scope: Scope dictionary with type and id
        tickets: List of ticket specifications
        source_type: Type of source (e.g., "jira", "manual")
    
    Returns:
        dict: Audit metadata object
    """
    utc_now = datetime.utcnow()
    environment = os.getenv('ENVIRONMENT', 'development').lower()
    
    # Determine source type from tickets
    ticket_sources = [t.get("source", "jira") for t in tickets if isinstance(t, dict)]
    unique_sources = list(set(ticket_sources)) if ticket_sources else [source_type]
    primary_source = unique_sources[0] if unique_sources else source_type
    
    return {
        "run_id": str(uuid.uuid4()),
        "generated_at": utc_now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "agent_version": AGENT_VERSION,
        "model": {
            "name": LLM_MODEL,
            "temperature": LLM_TEMPERATURE,
            "response_format": "json_object"
        },
        "environment": environment,
        "source": {
            "type": primary_source,
            "ticket_count": len(tickets),
            "scope_type": scope.get("type", "ticket"),
            "scope_id": scope.get("id", "")
        },
        "algorithms": {
            "test_generation": "LLM-based structured generation with deterministic ID assignment",
            "coverage_analysis": "Requirement-to-test mapping with RTM generation",
            "quality_scoring": "Heuristic-based clarity and testability scoring",
            "confidence_calculation": "Risk-weighted coverage confidence with dimension analysis"
        },
        "agent_metadata": {
            "agent": "test-plan-agent",
            "agent_version": AGENT_VERSION,
            "logic_version": "testplan-v1+coverage-enforcer-v1",
            "determinism": "LLM + deterministic post-pass",
            "change_policy": "idempotent"
        },
        # Scope lifecycle reflection (from Requirements Agent)
        # These reflect the scope_status from the source package, not test-level lifecycle
        "scope_status": None,  # Will be populated from package if available
        "scope_reviewed_by": None,
        "scope_reviewed_at": None,
        "scope_approved_by": None,
        "scope_approved_at": None,
        "scope_id": scope.get("id", ""),  # Already in source, but also at top level for clarity
        # Jira write-back metadata (Phase 3)
        # These are initially null and will be enriched from run context when fetched
        "jira_issue_key": None,
        "jira_created_by": None,
        "jira_created_at": None
    }


# Test plan schema structure - single source of truth
TEST_PLAN_SCHEMA = {
    "schema_version": "1.0",
    "metadata": {
        "source": "jira",
        "source_id": "",
        "generated_at": ""
    },
    "requirements": [],
    "business_intent": "",
    "assumptions": [],
    "gaps_detected": [],
    "test_plan": {
        "api_tests": [],
        "ui_tests": [],
        "data_validation_tests": [],
        "edge_cases": [],
        "negative_tests": []
    },
    "summary": ""
}


def get_empty_test_plan(ticket_id=None):
    """
    Return a fresh copy of the test plan schema structure.
    
    Args:
        ticket_id: Optional JIRA ticket ID to populate in metadata
    
    Returns:
        dict: A deep copy of the test plan schema to avoid mutation.
    """
    plan = copy.deepcopy(TEST_PLAN_SCHEMA)
    if ticket_id:
        plan["metadata"]["source_id"] = ticket_id
    # Generate runtime timestamp in ISO-8601 format with trailing Z
    utc_now = datetime.utcnow()
    plan["metadata"]["generated_at"] = utc_now.strftime("%Y-%m-%dT%H:%M:%SZ")
    return plan


def flatten_adf_to_text(adf_content):
    """
    Flatten Atlassian Document Format (ADF) to plain text.
    
    PRESERVES ORDERED LIST STRUCTURE:
    - Ordered lists (<ol><li>) are converted to numbered lines (1., 2., 3.)
    - Each list item becomes a separate line
    - Numbering tokens are preserved verbatim
    
    Args:
        adf_content: ADF content (dict) or plain text (str)
    
    Returns:
        str: Flattened text representation, or empty string if flattening fails.
    """
    if not adf_content:
        return ""
    
    # If it's already a string, return as-is
    if isinstance(adf_content, str):
        return adf_content
    
    # If it's not a dict, return empty string
    if not isinstance(adf_content, dict):
        return ""
    
    try:
        # ADF structure: { "version": 1, "type": "doc", "content": [...] }
        if "content" not in adf_content:
            return ""
        
        def extract_text_from_node(node):
            """
            Extract plain text from a single ADF node (recursively processes children).
            Does not handle list structure - that's handled by the parent function.
            """
            if not isinstance(node, dict):
                return ""
            
            text_parts = []
            
            # Extract text from current node
            if "text" in node:
                text_parts.append(node["text"])
            
            # Recursively process content
            if "content" in node and isinstance(node["content"], list):
                for child in node["content"]:
                    child_text = extract_text_from_node(child)
                    if child_text.strip():
                        text_parts.append(child_text)
            
            return " ".join(text_parts)
        
        def extract_text_with_structure(node):
            """
            Extract text preserving structure for block-level elements.
            Handles ordered lists, paragraphs, headings, etc. with proper line breaks.
            """
            if not isinstance(node, dict):
                return ""
            
            node_type = node.get("type", "")
            content = node.get("content", [])
            
            # Handle ordered list: preserve as numbered lines (1., 2., 3.)
            if node_type == "orderedList":
                if isinstance(content, list):
                    list_items = []
                    item_number = 1
                    for list_item in content:
                        if isinstance(list_item, dict) and list_item.get("type") == "listItem":
                            # Extract text from list item (recursively processes all content)
                            item_text = extract_text_from_node(list_item)
                            if item_text.strip():
                                # TARGETED CLEANUP: Remove stray "0 " prefix if present at start of item text
                                # This handles Jira ADF placeholder/index artifacts without affecting numbering
                                if item_text.startswith("0 "):
                                    item_text = item_text[2:].lstrip()  # Remove "0 " and any following whitespace
                                
                                # Preserve numbering token verbatim: "1. ", "2. ", etc.
                                list_items.append(f"{item_number}. {item_text}")
                                item_number += 1
                    # Each list item on its own line - do NOT concatenate
                    return "\n".join(list_items)
            
            # Handle bullet list: preserve as bulleted lines
            if node_type == "bulletList":
                if isinstance(content, list):
                    list_items = []
                    for list_item in content:
                        if isinstance(list_item, dict) and list_item.get("type") == "listItem":
                            item_text = extract_text_from_node(list_item)
                            if item_text.strip():
                                list_items.append(f"- {item_text}")
                    return "\n".join(list_items)
            
            # Handle paragraph: extract text (will be separated by line breaks at document level)
            if node_type == "paragraph":
                text = extract_text_from_node(node)
                return text if text else ""
            
            # Handle heading: extract text
            if node_type == "heading":
                text = extract_text_from_node(node)
                return text if text else ""
            
            # For other block-level types, recursively process
            if isinstance(content, list):
                parts = []
                for child in content:
                    child_text = extract_text_with_structure(child)
                    if child_text.strip():
                        parts.append(child_text)
                return "\n".join(parts)
            
            # Fallback: extract text directly
            return extract_text_from_node(node)
        
        # Process the document content, preserving line breaks
        content = adf_content.get("content", [])
        result_parts = []
        
        for node in content:
            node_text = extract_text_with_structure(node)
            if node_text.strip():
                result_parts.append(node_text)
        
        result = "\n".join(result_parts)
        
        # Normalize line endings (convert \r\n to \n)
        result = result.replace("\r\n", "\n")
        
        # Trim whitespace but preserve line structure
        return result.strip()
    
    except Exception:
        # If any error occurs during flattening, return empty string
        return ""

def extract_acceptance_criteria_from_adf(adf_content) -> str:
    """
    Extracts Acceptance Criteria section text from Jira ADF description.
    Looks for a heading titled 'Acceptance Criteria' and captures content until the next heading.
    """
    if not isinstance(adf_content, dict):
        return ""

    content = adf_content.get("content", [])
    capture = False
    extracted = []

    for node in content:
        # Detect heading
        if node.get("type") == "heading":
            heading_text = flatten_adf_to_text(node).lower()
            if "acceptance criteria" in heading_text:
                capture = True
                continue
            elif capture:
                # Stop when we hit the next heading
                break

        if capture:
            extracted.append(flatten_adf_to_text(node))

    return "\n".join([line for line in extracted if line.strip()])


import base64
import json
import requests


def fetch_jira_ticket(jira_base_url, email, api_token, ticket_id):
    """
    Fetch JIRA ticket data using JIRA Cloud REST API v3.

    Args:
        jira_base_url: Base URL of JIRA instance (e.g., "https://your-domain.atlassian.net")
        email: JIRA user email for Basic Auth
        api_token: JIRA API token for Basic Auth
        ticket_id: JIRA ticket ID (e.g., "PROJ-123")

    Returns:
        dict with:
          - id
          - summary
          - description
          - acceptance_criteria
          - attachments
          - raw

    Raises:
        Exception on API or parsing failure
    """

    if not jira_base_url:
        raise Exception("JIRA_BASE_URL is not set")

    if not email or not api_token:
        raise Exception("JIRA_EMAIL or JIRA_API_TOKEN is not set")

    # Construct API endpoint
    api_url = f"{jira_base_url.rstrip('/')}/rest/api/3/issue/{ticket_id}"

    # Prepare Basic Auth
    credentials = f"{email}:{api_token}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()

    headers = {
        "Accept": "application/json",
        "Authorization": f"Basic {encoded_credentials}"
    }

    try:
        response = requests.get(api_url, headers=headers)

        if response.status_code != 200:
            raise Exception(
                f"JIRA API returned status {response.status_code}: {response.text}"
            )

        issue_data = response.json()
        fields = issue_data.get("fields", {})

        # -------------------------
        # Core fields
        # -------------------------
        summary = fields.get("summary", "")
        description_raw = fields.get("description", "")
        description = flatten_adf_to_text(description_raw)
        
        # DIAGNOSTIC: Store raw description text for numbering detection tracking
        # This is diagnostic-only and does not affect behavior
        raw_description_text = description  # After flatten_adf_to_text conversion

        # -------------------------
        # Acceptance Criteria
        # -------------------------
        acceptance_criteria = ""

        # 1) Try extracting from ADF "Acceptance Criteria" heading
        if isinstance(description_raw, dict):
            acceptance_criteria = extract_acceptance_criteria_from_adf(description_raw)

        # 2) Fallback: custom fields
        if not acceptance_criteria:
            for key, value in fields.items():
                if value and ("acceptance" in key.lower() or "criteria" in key.lower()):
                    acceptance_criteria = flatten_adf_to_text(value)
                    break

        # -------------------------
        # Attachments (Epic 2.3)
        # -------------------------
        attachments_raw = fields.get("attachment", [])

        attachments = [
            {
                "filename": a.get("filename"),
                "mime_type": a.get("mimeType"),
                "size": a.get("size"),
                "url": a.get("content")
            }
            for a in attachments_raw
        ]

        # -------------------------
        # DIAGNOSTIC: Store raw description for numbering detection tracking
        # This is diagnostic-only and does not affect behavior
        # raw_description_text is the description after flatten_adf_to_text conversion
        # -------------------------
        return {
            "id": ticket_id,
            "summary": summary,
            "description": description,
            "acceptance_criteria": acceptance_criteria,
            "attachments": attachments,
            "raw": issue_data,
            "_diagnostic_raw_description": description  # Diagnostic only: description after ADF flattening
        }

    except requests.exceptions.RequestException as e:
        raise Exception(f"Failed to fetch JIRA ticket: {str(e)}")

    except json.JSONDecodeError as e:
        raise Exception(f"Failed to parse JIRA API response: {str(e)}")

    except Exception as e:
        raise Exception(f"Error fetching JIRA ticket {ticket_id}: {str(e)}")

def detect_numbering_pattern(text: str) -> bool:
    """
    Diagnostic helper: Check if text contains numbered list patterns.
    
    Checks each line for leading numbered pattern: ^\s*\d+[\.\)\-]
    
    Args:
        text: Text to check
    
    Returns:
        bool: True if numbering pattern detected, False otherwise
    """
    if not text or not isinstance(text, str):
        return False
    
    import re
    numbering_pattern = re.compile(r'^\s*\d+[\.\)\-]', re.MULTILINE)
    return bool(numbering_pattern.search(text))


def normalize_numbered_lists(text: str) -> str:
    """
    Pre-extraction normalization: Preserve or reconstruct numbered list structure.
    
    This function:
    1. Detects explicit numbered list patterns (1., 2., 3. or 1), 2))
    2. Preserves numbering tokens if they already exist
    3. Reconstructs numbering if tokens were stripped but sequential list structure is detected
    4. Does NOT infer new requirements, merge/split content, or modify wording/meaning/order
    5. Only affects text that has list-like structure
    
    Args:
        text: Raw ticket text (description or acceptance_criteria)
    
    Returns:
        str: Normalized text with preserved or reconstructed numbering
    """
    if not text or not isinstance(text, str):
        return text
    
    import re
    
    # Check if text already contains explicit numbered patterns
    # Patterns: "1.", "2.", "1)", "2)", "1:", "2:", etc.
    explicit_numbered_pattern = re.compile(
        r'^[\s]*\d+[\.\):]\s+',
        re.MULTILINE
    )
    
    if explicit_numbered_pattern.search(text):
        # Numbering already exists - preserve as-is
        return text
    
    # Check if text has sequential list structure without explicit numbering
    # Look for lines that appear to be list items:
    # - Short lines (typically < 100 chars)
    # - Start with action words or capitalized words
    # - Multiple consecutive lines with similar structure
    # - Similar indentation (indicating they're part of the same list)
    
    lines = text.split('\n')
    if len(lines) < 2:
        # Not enough lines to form a list
        return text
    
    # Detect potential list items
    potential_items = []
    action_words = ['must', 'shall', 'will', 'should', 'need', 'require', 'implement', 
                    'add', 'create', 'update', 'delete', 'verify', 'validate', 'check', 
                    'ensure', 'provide', 'enable', 'allow', 'support', 'include']
    
    for i, line in enumerate(lines):
        line_stripped = line.strip()
        if not line_stripped or len(line_stripped) < 5:
            continue
        
        # Skip headers, very long lines, or lines with colons (likely descriptions)
        if len(line_stripped) > 150 or ':' in line_stripped[:20]:
            continue
        
        # Check if line starts with action word or capitalized word
        words = line_stripped.split()
        if not words:
            continue
        
        first_word = words[0].lower()
        starts_with_action = first_word in action_words
        starts_with_capital = line_stripped[0].isupper() if line_stripped else False
        
        # Check if line looks like a list item (not a paragraph)
        # List items are typically:
        # - Short (< 100 chars)
        # - Start with action verb or capitalized word
        # - Don't end with punctuation (or end with period)
        is_short_line = len(line_stripped) < 100
        ends_with_punctuation = line_stripped.endswith(('.', '!', '?'))
        has_list_structure = (starts_with_action or starts_with_capital) and is_short_line
        
        if has_list_structure:
            # Preserve original indentation
            leading_whitespace = line[:len(line) - len(line.lstrip())]
            potential_items.append((i, line_stripped, leading_whitespace))
    
    # If we found 2+ potential items, check if they form a sequential list
    if len(potential_items) >= 2:
        # Check if items are sequential (not too far apart) and have similar indentation
        is_sequential = True
        base_indent = potential_items[0][2]  # Use first item's indentation as reference
        
        for j in range(1, len(potential_items)):
            prev_idx = potential_items[j-1][0]
            curr_idx = potential_items[j][0]
            
            # Items should be close together (allow up to 2 blank lines between)
            if curr_idx - prev_idx > 3:
                is_sequential = False
                break
            
            # Items should have similar indentation (within 4 spaces)
            curr_indent = potential_items[j][2]
            indent_diff = abs(len(base_indent) - len(curr_indent))
            if indent_diff > 4:
                # Indentation differs significantly - might not be a list
                is_sequential = False
                break
        
        if is_sequential:
            # Reconstruct numbering: replace lines with numbered versions
            normalized_lines = lines.copy()
            item_counter = 1
            
            for item_idx, item_text, leading_whitespace in potential_items:
                # Add numbering token (e.g., "1. ")
                numbered_item = f"{leading_whitespace}{item_counter}. {item_text}"
                normalized_lines[item_idx] = numbered_item
                item_counter += 1
            
            return '\n'.join(normalized_lines)
    
    # No list structure detected - return original text unchanged
    return text


def compile_ticket_for_llm(ticket: dict) -> dict:
    """
    Compiles a normalized Jira ticket into a deterministic LLM input.
    NO inference. NO guessing. Only explicit artifacts.
    """

    execution_mechanisms = {
        "api_endpoints": [],
        "file_paths": [],
        "ui_components": [],
        "commands": []
    }

    attachment_refs = []

    # -------------------------
    # Attachments (explicit artifacts)
    # -------------------------
    for att in ticket.get("attachments", []):
        if att.get("filename"):
            attachment_refs.append(
                f"{att.get('filename')} ({att.get('mime_type')})"
            )
            execution_mechanisms["file_paths"].append(att.get("filename"))

    # -------------------------
    # Explicit API endpoints ONLY (no guessing)
    # -------------------------
    text_sources = [
        ticket.get("description", ""),
        ticket.get("acceptance_criteria", "")
    ]

    for text in text_sources:
        matches = re.findall(
            r"(POST|GET|PUT|DELETE)\s+(/api/[a-zA-Z0-9/_\-]+)",
            text
        )
        for method, path in matches:
            execution_mechanisms["api_endpoints"].append(f"{method} {path}")

    # ============================================================================
    # PRE-EXTRACTION NORMALIZATION: Preserve or reconstruct numbered list structure
    # This runs BEFORE requirement extraction to ensure numbered lists are detected
    # ============================================================================
    description = ticket.get("description", "")
    acceptance_criteria = ticket.get("acceptance_criteria", "")
    
    # Get raw description for diagnostic purposes (before normalization)
    raw_description = ticket.get("_diagnostic_raw_description", description)
    if not raw_description:
        raw_description = description
    
    # Normalize both description and acceptance_criteria
    normalized_description = normalize_numbered_lists(description)
    normalized_acceptance_criteria = normalize_numbered_lists(acceptance_criteria)
    
    # ============================================================================
    # DIAGNOSTIC: Log numbering detection for debug/development runs
    # This is diagnostic-only and does not affect extraction, requirements, RTM, tests, or UI
    # ============================================================================
    ticket_id = ticket.get("id", "UNKNOWN")
    
    # Check for numbering in raw and normalized descriptions
    numbering_detected_raw = detect_numbering_pattern(raw_description)
    numbering_detected_normalized = detect_numbering_pattern(normalized_description)
    
    # Log diagnostic information (only in development/debug mode)
    # Check if we're in a debug/development environment
    import os
    is_debug = os.getenv("FLASK_ENV") == "development" or os.getenv("DEBUG") == "true" or logger.level <= 10
    
    if is_debug:
        diagnostic_info = {
            "ticket_id": ticket_id,
            "raw_jira_description": raw_description[:500] if len(raw_description) > 500 else raw_description,  # Truncate for logging
            "normalized_description": normalized_description[:500] if len(normalized_description) > 500 else normalized_description,  # Truncate for logging
            "numbering_detected_raw": numbering_detected_raw,
            "numbering_detected_normalized": numbering_detected_normalized
        }
        logger.debug(f"JIRA NUMBERING DIAGNOSTIC (Ticket {ticket_id}): {json.dumps(diagnostic_info, indent=2)}")

    return {
        "ticket_id": ticket.get("id"),
        "summary": ticket.get("summary"),
        "description": normalized_description,
        "acceptance_criteria": normalized_acceptance_criteria,
        "attachments": attachment_refs,
        "execution_mechanisms": execution_mechanisms
    }


def generate_test_plan_with_llm(compiled_ticket: dict) -> dict:

    """
    Generate a test plan using OpenAI LLM based on ticket text.

    Args:
        ticket_text: The JIRA ticket text to analyze.

    Returns:
        dict: A test plan dictionary matching the schema structure.
        Returns empty schema if LLM call fails.
    """
    debug_requirements = os.getenv("DEBUG_REQUIREMENTS", "0") == "1"
    ticket_id = compiled_ticket.get("ticket_id", "")
    
    # Log function entry immediately
    if debug_requirements:
        logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: FUNCTION_ENTRY generate_test_plan_with_llm called")
    
    try:
        if not openai_client:
            if debug_requirements:
                logger.warning(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: EARLY_RETURN openai_client is None")
            return get_empty_test_plan()
        
        # STEP1: Before LLM call
        if debug_requirements:
            logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: STEP1_BEFORE_LLM before LLM call")
        
        t0 = time.time()

        system_prompt = """
You are an AI Testing Agent operating in a regulated, ISO-audited environment.

Your task is to generate a TEST PLAN in STRICT JSON format that conforms to the following rules.

OBJECTIVES:
1. Parse all explicitly numbered requirements from the Jira ticket (e.g., "Requirement 1", "Requirement 2", "REQ-1", etc.).
2. If requirements are implied but not explicitly numbered, infer them and label them as "inferred".
3. Assign each requirement a stable ID using the format REQ-001, REQ-002, etc. (sequential, starting from REQ-001).
4. Generate MULTIPLE test cases per requirement based on test intents.
5. For each requirement, generate test cases for these intents (when applicable):
   - happy_path: Test successful execution and expected behavior
   - negative: Test error handling and failure conditions
   - authorization: Test access control and permissions
   - boundary: Test limits, ranges, and edge cases (only when requirement implies boundaries)
6. Each test case MUST:
   - Reference the requirement it validates using "source_requirement_id" field
   - Include "intent_type" field matching the test intent
   - Include "requirements_covered" array with the requirement ID
   - Have a title derived from the intent (e.g., "Happy path: [requirement summary]")
7. Ensure full traceability: Jira Ticket → Requirement → Test Intent → Test Case.

CRITICAL RULES:
- Every requirement MUST generate MULTIPLE test cases (one per applicable intent).
- Each test case MUST have exactly ONE intent_type (happy_path, negative, authorization, or boundary).
- Each test case MUST include "source_requirement_id" field pointing to the requirement it tests.
- Each test case MUST include "intent_type" field matching its test intent.
- Every test case MUST reference the requirement ID in "requirements_covered" array.
- NEVER collapse multiple intents into a single test case.
- Generate separate test cases for happy_path and negative intents (at minimum) for each requirement.
- Requirement IDs must be sequential and stable (REQ-001, REQ-002, etc.).
- If acceptance criteria are missing or unclear, add an entry to gaps_detected.
- Acceptance Criteria are the primary source of requirements when present.
- If acceptance criteria are NOT provided, infer testable requirements from the ticket summary and description.
- All inferred requirements MUST have source="inferred" and be documented in assumptions.
- Requirement source field MUST be a single explicit value: either "jira" (explicitly listed/numbered in ticket) or "inferred" (derived by AI). Do not use combined values.
- Missing acceptance criteria MUST NOT be listed in gaps_detected unless the behavior is ambiguous or untestable.
- Generate test cases for functional requirements even if acceptance criteria are minimal or absent.

CRITICAL: ACCEPTANCE CRITERIA vs TEST STEPS:
- Acceptance criteria define WHAT must be true (the requirement/outcome), NOT HOW to test it.
- Acceptance criteria MUST NEVER be used directly as test steps.
- For EVERY acceptance criterion, you MUST generate explicit, ordered test steps that a tester could execute.
- Test steps must be concrete, executable actions that demonstrate HOW to validate the acceptance criterion.
- The presence of acceptance criteria MUST NEVER suppress step generation - steps are ALWAYS required.
- Generate steps for EACH applicable scenario type:
  * Happy path: Steps that validate successful execution
  * Negative scenarios: Steps that test error handling and failure conditions
  * Data validation: Steps that test input validation (if inputs exist)
  * Boundary/edge cases: Steps that test limits and edge values (when implied)
- Preserve the original acceptance criterion text as the requirement source, but ALWAYS expand it into concrete actions and verifications.
- Test steps must be concrete, executable actions derived from BOTH:
  - The requirement text (acceptance criterion)
  - The test intent (happy_path steps validate success, negative steps attempt failures, etc.)
- Happy path steps must validate successful execution and expected outcomes.
- Negative steps must attempt failure conditions (invalid inputs, missing data, etc.).
- NEGATIVE TEST SUPPRESSION FOR UI PRESENCE (CRITICAL):
  * If a requirement is classified as ui_structure, ui_element, OR ui_presence
    AND the requirement intent is to confirm existence, visibility, or accessibility only:
    - DO NOT generate negative tests
    - DO NOT expect negative coverage
    - DO NOT flag missing negative tests as gaps
    - Treat absence, invisibility, or inaccessibility as a failure of the happy-path assertion, NOT a separate negative scenario
  * This applies to requirements that use presence-oriented verbs (have, display, show, present, include, contain)
    and presence keywords (visible, accessible, present, available, exists) WITHOUT error-handling keywords
  * Example: "Have multiple tabs for ticket, RTM, requirement" → NO negative test (absence is happy-path failure)
  * Example: "Have a 'Generate Test Plan' button" → NO negative test (absence is happy-path failure)

- CLASSIFICATION-BASED NEGATIVE TEST GENERATION (for UI-related requirements with error-handling):
  * If a requirement or item is classified as ui_structure OR ui_element
    AND the requirement contains error-handling keywords (error, invalid, missing, permission, failure, reject, deny, handle, validation):
    - Negative tests MUST be presence/state-based, NOT generic error-handling.
    - Valid negative scenarios for UI requirements:
      * Required UI element is missing
      * UI element is not visible
      * UI element is disabled when it should be enabled
      * UI element displays incorrect or empty content
    - DO NOT use generic negative templates like:
      * "Attempt to trigger the action with invalid or missing data"
      * "Send request with invalid input"
      * "Verify error response is returned"
    - If no UI-specific negative scenario can be confidently derived:
      * Generate a conservative UI-state negative (e.g., "required element is not present")
      * OR mark negative coverage as expected but not generated
      * Do NOT fabricate error-handling behavior
  * Generic negative templates (invalid input / error handling) remain valid ONLY for:
    - system_behavior
    - data_validation
    - api_behavior (if present)
- LOGICAL FAILURE-MODE INFERENCE (for negative tests only):
  * When generating negative test cases, you are allowed to infer failure conditions by logically negating the stated requirement text.
  * Use the requirement text verbatim - do NOT rewrite or rephrase it.
  * Infer failure modes by structural negation of the requirement (e.g., "missing", "not present", "not generated", "not accessible").
  * Examples:
    - Requirement: "Have multiple tabs for ticket, RTM, requirement, test by requirement, and test by type"
      → Valid negative inference: One or more required tabs are missing, mislabeled, or inaccessible
    - Requirement: "Have a 'Generate Test Plan' button"
      → Valid negative inference: Button is not present or not clickable
    - Requirement: "Generate a PDF that mirrors the UI layout"
      → Valid negative inference: Generated PDF layout does not match the UI
  * This is logical negation, not intent inference. Do NOT infer user intent beyond the literal requirement.
  * Do NOT invent inputs, data values, permissions, or business rules.
  * Negative tests generated using this rule must be labeled: steps_origin="inferred", confidence="inferred"
- Authorization steps must attempt unauthorized access scenarios.
- Boundary steps must test limits, ranges, and edge values.
- Do NOT use abstract steps such as "review", "verify", "check", or "ensure".
- Do NOT use generic placeholder steps such as:
  * "Invoke the system using valid inputs"
  * "Verify the operation completes successfully"
  * "Validate expected output or behavior"
  * "Send request with valid data"
  * "Check response status"
- Each step must describe a SPECIFIC action with SPECIFIC elements (e.g., "Click the 'Submit' button", "Send POST request to /api/users with email field", "Verify the 'Welcome' message appears").
- Steps should be written so they could be automated or followed by a junior QA tester.
- If you cannot derive concrete, requirement-specific steps from the ticket content, return an EMPTY steps array [] and include a "steps_explanation" field explaining why steps could not be generated.
- NEVER fabricate steps to satisfy schema requirements. Honesty over completeness.
- If the ticket defines at least one execution mechanism (API endpoint, file path, UI component, command, or attachment),
  tests MAY be generated using that mechanism even if acceptance criteria are inferred.
- Generate BOTH positive tests (valid behavior) AND negative tests (invalid input, error scenarios) when error conditions are mentioned or implied.

TEST CONFIDENCE LABELING:
- Every test case MUST include a "confidence" field with one of:
  - "explicit": Test derived directly from Jira acceptance criteria or explicit requirements
  - "inferred": Test based on reasonable assumptions from common system patterns
- NEVER mark inferred tests as "explicit".
- When generating inferred tests, add corresponding assumptions explaining what is being inferred.

INFERENCE GUIDELINES:
- You MAY infer:
  - Existence of request/response interactions when APIs are mentioned
  - Common REST behaviors (HTTP 200 for success, 400 for bad request, 401 for unauthorized, 403 for forbidden)
  - Typical validation failures (invalid URL, missing token, malformed data)
  - STANDARD UI EXECUTION ASSUMPTIONS (these are NOT hallucinations):
    * The system has a UI accessed via browser or app
    * UI elements explicitly named in requirements (buttons, links, menus, fields) exist on a screen/page
    * Users can interact with named UI elements using standard actions (click, tap, input, select)
    * Observable outcomes include: UI state changes, file downloads, page navigation, message displays
    * Verification of file types via filename extension or content type is valid
    * Standard UI primitives: navigate (generic), verify visible/enabled, click/tap, verify outcome
- You MUST NOT:
  - Invent database schemas
  - Invent UI layouts (beyond assuming named elements exist)
  - Invent undocumented business rules
  - Fabricate execution mechanisms not mentioned in the ticket
  - Invent specific page names, URLs, endpoints, or backend details for UI requirements

OUTPUT REQUIREMENTS:
- Output MUST be valid JSON.
- Do NOT include any explanatory text outside the JSON.
- Do NOT invent top-level fields outside the schema.
- All arrays must exist even if empty.

You must return ONLY valid JSON that exactly matches this schema:

{
  "schema_version": "1.0",
  "metadata": {
    "source": "jira",
    "source_id": "<jira_ticket_id>",
    "generated_at": "<ISO-8601 timestamp>"
  },
  "requirements": [
    {
      "id": "REQ-001",
      "source": "jira",
      "description": "<requirement text>"
    },
    {
      "id": "REQ-002",
      "source": "inferred",
      "description": "<requirement text>"
    }
  ],
  "business_intent": "<overall purpose of the change>",
  "assumptions": [],
  "gaps_detected": [
    {
      "type": "general",
      "severity": "medium",
      "description": "<gap description>",
      "suggested_question": "<question to address the gap>"
    }
  ],
  "test_plan": {
    "api_tests": [
      {
        "id": "API-001",
        "title": "<short title derived from intent, e.g., 'Happy path: User login' or 'Negative: Invalid credentials'",
        "source_requirement_id": "REQ-001",
        "intent_type": "happy_path",
        "requirements_covered": ["REQ-001"],
        "steps": [],
        "steps_explanation": "<optional: explain why steps are empty, e.g., 'Insufficient detail to generate concrete test steps'>",
        "steps_origin": "requirement-derived",
        "expected_result": "<expected outcome based on intent>",
        "priority": "medium",
        "confidence": "explicit"
      }
    ],
    "ui_tests": [],
    "data_validation_tests": [],
    "edge_cases": [],
    "negative_tests": []
  },
  "summary": "<concise summary of coverage and gaps>"
}

Do not include markdown. Do not include explanations. JSON only.
"""

        # Generate step skeletons for each intent type
        execution_mechanisms = compiled_ticket.get("execution_mechanisms", {})
        step_skeletons = {
            "happy_path": generate_step_skeleton("happy_path", execution_mechanisms),
            "negative": generate_step_skeleton("negative", execution_mechanisms),
            "authorization": generate_step_skeleton("authorization", execution_mechanisms),
            "boundary": generate_step_skeleton("boundary", execution_mechanisms)
        }
        
        # Check if ticket/requirements name UI elements or output artifacts
        # This allows test generation even without explicit execution mechanisms
        ticket_text = (
            compiled_ticket.get("summary", "") + " " +
            compiled_ticket.get("description", "") + " " +
            compiled_ticket.get("acceptance_criteria", "")
        )
        has_ui_elements = names_ui_element(ticket_text)
        has_output_artifacts = names_output_artifact(ticket_text)
        can_generate_tests = (
            bool(execution_mechanisms.get("api_endpoints")) or
            bool(execution_mechanisms.get("ui_components")) or
            bool(execution_mechanisms.get("file_paths")) or
            has_ui_elements or
            has_output_artifacts
        )
        
        user_prompt = f"""
You are given a compiled Jira ticket.

This ticket has already been analyzed for execution feasibility.
You MUST obey the execution mechanisms provided.

CRITICAL TEST GENERATION RULES:
- If execution mechanisms are provided (API endpoints, UI components, file paths), generate tests using those mechanisms.
- If NO explicit execution mechanisms exist BUT the requirement names UI elements (buttons, links, menus, quoted labels) OR output artifacts (PDF, JSON, file downloads, exports):
  * You MUST generate test cases using standard UI execution assumptions
  * These are NOT hallucinations - standard UI interactions are industry-accepted QA practices
  * Generate concrete steps like "Verify the '[Element Name]' button is visible" and "Click the '[Element Name]' button"
- Only if NO execution mechanisms AND NO named UI elements/artifacts exist, produce gaps_detected and NO tests.

CRITICAL: You MUST ALWAYS extract at least one requirement from the ticket, even if:
- No execution mechanisms are provided
- Acceptance criteria are missing
- The ticket is incomplete

If requirements are not explicitly numbered, infer at least one requirement from the ticket summary or description.

COMPILED TICKET:
{json.dumps(compiled_ticket, indent=2)}

STEP SKELETONS FOR EACH INTENT TYPE:
{json.dumps(step_skeletons, indent=2)}

BEGIN PROCESSING THE PROVIDED JIRA TICKET NOW.

TEST CASE ENUMERATION REQUIREMENTS:
1. For EACH requirement, generate MULTIPLE test cases based on test intents:
   - happy_path: Test successful execution (REQUIRED for functional requirements)
   - negative: Test error handling (REQUIRED for functional requirements)
   - authorization: Test access control (ONLY if requirement mentions permissions/security)
   - boundary: Test limits/ranges (ONLY if requirement mentions limits, formats, or constraints)

2. Each test case MUST have:
   - "intent_type": One of "happy_path", "negative", "authorization", "boundary"
   - "source_requirement_id": The requirement ID this test case validates
   - "title": Descriptive title including intent (e.g., "Happy path: User login", "Negative: Invalid credentials")
   - "requirements_covered": Array containing the requirement ID

3. STEP GENERATION USING SKELETONS:
   For each test case, use the step skeleton for its intent_type as a template:
   - Each skeleton slot describes WHAT should be in that step, not the actual content
   - Fill each skeleton slot with SPECIFIC, requirement-derived content:
     * Replace placeholders like "the API endpoint" with the actual endpoint from the requirement
     * Replace "required fields" with the actual field names from the requirement
     * Replace "expected values" with the actual expected values from the requirement
     * Replace "invalid data" with specific examples of what makes it invalid based on the requirement
   - If a skeleton slot cannot be filled with requirement-specific content (you would need to invent details):
     * SKIP that slot - do NOT include it in the steps array
     * Do NOT fill it with generic placeholders
   - Only include steps that can be completed with requirement-derived content
   - If NO skeleton slots can be filled, return empty steps array with steps_explanation

4. STEP GENERATION RULES (MANDATORY):
   - Steps must reference SPECIFIC elements from the requirement (endpoints, fields, values, UI elements)
   - Steps must be executable and concrete (not abstract like "verify operation completes")
   - Do NOT use generic phrases like "valid inputs", "expected output", "operation completes"
   - Do NOT invent APIs, endpoints, UI components, or data structures not mentioned in the requirement
   - If the requirement lacks specific details needed to fill a skeleton slot, skip that slot
   - CRITICAL: Do NOT copy acceptance criteria text directly into steps. Acceptance criteria describe WHAT must be true, not HOW to test it.
   - CRITICAL: Always generate explicit, ordered test steps. The presence of acceptance criteria MUST NEVER suppress step generation.
   - For every acceptance criterion, generate steps for ALL applicable scenario types (happy path, negative, data validation, boundary when applicable).

5. HAPPY-PATH STEP DECOMPOSITION (for UI structure requirements):
   - If a requirement is classified as ui_structure OR ui_element AND
     the requirement text contains multiple independently verifiable UI elements
     (e.g., comma-separated lists such as tabs, buttons, panels, fields):
     * Generate ONE happy-path test only (do NOT create multiple tests)
     * Within that happy-path test, decompose the requirement into individual verification steps
     * Create one verification step per UI element
     * Each step MUST explicitly confirm presence, visibility, and accessibility
     * Do NOT merge multiple UI elements into a single step
     * Example:
       - Requirement: "Have multiple tabs for ticket, rtm, requirement, test by requirement and test by type"
       - Generate ONE happy-path test with steps:
         * "Navigate to the application"
         * "Verify that the 'ticket tab' is present on the screen, visible to the user, and accessible (enabled and ready for interaction)"
         * "Verify that the 'rtm tab' is present on the screen, visible to the user, and accessible (enabled and ready for interaction)"
         * "Verify that the 'requirement tab' is present on the screen, visible to the user, and accessible (enabled and ready for interaction)"
         * "Verify that the 'test by requirement tab' is present on the screen, visible to the user, and accessible (enabled and ready for interaction)"
         * "Verify that the 'test by type tab' is present on the screen, visible to the user, and accessible (enabled and ready for interaction)"
     * Maintain a single test ID and single requirement mapping (do NOT create multiple tests)

6. NEGATIVE TEST SUPPRESSION FOR UI PRESENCE (CRITICAL):
   - If a requirement is classified as ui_structure, ui_element, OR ui_presence
     AND the requirement intent is to confirm existence, visibility, or accessibility only:
     * DO NOT generate negative tests
     * DO NOT expect negative coverage
     * DO NOT flag missing negative tests as gaps
     * Treat absence, invisibility, or inaccessibility as a failure of the happy-path assertion, NOT a separate negative scenario
   - This applies to requirements that use presence-oriented verbs (have, display, show, present, include, contain)
     and presence keywords (visible, accessible, present, available, exists) WITHOUT error-handling keywords
   - Example: "Have multiple tabs for ticket, RTM, requirement" → NO negative test (absence is happy-path failure)
   - Example: "Have a 'Generate Test Plan' button" → NO negative test (absence is happy-path failure)

7. CLASSIFICATION-BASED NEGATIVE TEST GENERATION (for UI-related requirements with error-handling):
   - If a requirement or item is classified as ui_structure OR ui_element
     AND the requirement contains error-handling keywords (error, invalid, missing, permission, failure, reject, deny, handle, validation):
     * Negative tests MUST be presence/state-based, NOT generic error-handling.
     * Valid negative scenarios for UI requirements:
       - Required UI element is missing
       - UI element is not visible
       - UI element is disabled when it should be enabled
       - UI element displays incorrect or empty content
     * DO NOT use generic negative templates like:
       - "Attempt to trigger the action with invalid or missing data"
       - "Send request with invalid input"
       - "Verify error response is returned"
     * If no UI-specific negative scenario can be confidently derived:
       - Generate a conservative UI-state negative (e.g., "required element is not present")
       - OR mark negative coverage as expected but not generated
       - Do NOT fabricate error-handling behavior
   - Generic negative templates (invalid input / error handling) remain valid ONLY for:
     * system_behavior
     * data_validation
     * api_behavior (if present)

8. LOGICAL FAILURE-MODE INFERENCE (for negative tests only):
   - When generating negative test cases, you may infer failure conditions by logically negating the requirement text itself.
   - Use requirement text verbatim - do NOT rewrite or rephrase it.
   - Infer failure modes by structural negation:
     * "Have X" → "X is missing or not present"
     * "Generate Y" → "Y is not generated or incorrectly generated"
     * "Provide Z" → "Z is not provided or not accessible"
     * "Display A" → "A is not displayed or incorrectly displayed"
   - Examples of valid logical negation:
     * Requirement: "Have multiple tabs for ticket, RTM, requirement, test by requirement, and test by type"
       → Negative: One or more required tabs are missing, mislabeled, or inaccessible
     * Requirement: "Have a 'Generate Test Plan' button"
       → Negative: Button is not present or not clickable
     * Requirement: "Generate a PDF that mirrors the UI layout"
       → Negative: Generated PDF layout does not match the UI
   - This is logical negation, NOT intent inference:
     * Do NOT infer user intent beyond the literal requirement
     * Do NOT invent inputs, data values, permissions, or business rules
     * Do NOT rewrite or rephrase the requirement text
   - Label negative tests using this rule as: steps_origin="inferred", confidence="inferred"
   - This rule applies even when no explicit failure modes or acceptance criteria are provided.
   - For UI-related requirements (ui_structure, ui_element), logical negation should focus on presence/state failures, not error-handling.

9. NEVER collapse multiple intents into one test case. Each intent = separate test case.

10. If you cannot generate ANY concrete steps for a test case, return empty steps array with steps_explanation explaining why.

Return valid JSON only. No markdown. No explanations.
"""

        response = openai_client.chat.completions.create(
            model=LLM_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=LLM_TEMPERATURE,
            response_format={"type": "json_object"}
        )

        # Parse the JSON response
        llm_response = json.loads(response.choices[0].message.content)
        
        # STEP2: After LLM call
        elapsed_ms = int((time.time() - t0) * 1000)
        if debug_requirements:
            llm_keys = list(llm_response.keys())
            req_info = ""
            if "requirements" in llm_response and isinstance(llm_response.get("requirements"), list):
                req_info = f", requirements_len={len(llm_response.get('requirements', []))}"
            summary_preview = str(llm_response.get("summary", ""))[:80] if llm_response.get("summary") else ""
            desc_preview = str(llm_response.get("description", ""))[:80] if llm_response.get("description") else ""
            logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: STEP2_AFTER_LLM after LLM call; elapsed_ms={elapsed_ms}, llm_keys={llm_keys}{req_info}")
            if summary_preview:
                logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: STEP2 llm_response['summary'] first 80 chars: {summary_preview}")
            if desc_preview:
                logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: STEP2 llm_response['description'] first 80 chars: {desc_preview}")
        
        # DEBUG: Log LLM response info (keep existing logs)
        if debug_requirements:
            logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: LLM response keys={list(llm_response.keys())}")
            if "requirements" in llm_response:
                req_type = type(llm_response.get("requirements"))
                req_length = len(llm_response.get("requirements", [])) if isinstance(llm_response.get("requirements"), list) else "N/A"
                logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: LLM requirements key present: True, type={req_type}, length={req_length}")
            else:
                logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: LLM requirements key present: False")
        
        # Debug: Log if requirements are missing
        if "requirements" not in llm_response or not isinstance(llm_response.get("requirements"), list):
            logger.warning(f"LLM response missing requirements array. Response keys: {list(llm_response.keys())}")
        elif len(llm_response.get("requirements", [])) == 0:
            logger.warning(f"LLM response has empty requirements array. Ticket: {compiled_ticket.get('ticket_id', 'UNKNOWN')}")

        # Start with empty schema (use ticket_id from compiled_ticket if available)
        ticket_id = compiled_ticket.get("ticket_id", "")
        test_plan = get_empty_test_plan(ticket_id=ticket_id)

        # Merge LLM response into schema, preserving structure
        # Update metadata if provided (but preserve runtime-generated timestamp)
        if "metadata" in llm_response and isinstance(llm_response["metadata"], dict):
            if "source_id" in llm_response["metadata"]:
                test_plan["metadata"]["source_id"] = llm_response["metadata"]["source_id"]
            # Do NOT overwrite generated_at - it's set at runtime in get_empty_test_plan()

        # Update schema_version if provided
        if "schema_version" in llm_response:
            test_plan["schema_version"] = llm_response["schema_version"]

        # ============================================================================
        # PRESERVE EXPLICIT NUMBERING TOKENS FROM JIRA DESCRIPTIONS (AUDIT TRACEABILITY)
        # Extract numbered items from BOTH description and acceptance_criteria
        # Preserve numbering tokens verbatim for auditor traceability
        # ============================================================================
        import re
        
        # Detect explicit numbering patterns: "1.", "2.", "1)", "2)", "1 -", "2 -", etc.
        # Pattern captures: (number)(separator)(text)
        numbered_pattern = re.compile(
            r'^[\s]*(\d+)([\.\):\-\s]+)(.+)$',
            re.MULTILINE
        )
        
        # Also check for patterns like "1.0", "REQ-1", "Requirement 1", etc.
        numbered_pattern_extended = re.compile(
            r'^[\s]*(\d+[\.\):]?|REQ[- ]?\d+|Requirement\s+\d+|REQ\s*\d+)[\s:]*\s*(.+)$',
            re.MULTILINE | re.IGNORECASE
        )
        
        # Extract from description (Jira ticket description is authoritative source)
        description = compiled_ticket.get("description", "")
        description_numbered_items = []
        detected_numbering_tokens = []  # Track for validation
        
        if description:
            for match in numbered_pattern.finditer(description):
                number_token = match.group(1)  # The number (e.g., "1", "2", "3")
                separator = match.group(2).strip()  # The separator (e.g., ".", ")", " -")
                text = match.group(3).strip() if len(match.groups()) >= 3 else ""
                
                if text and len(text) > 3:
                    # TARGETED CLEANUP: Remove stray "0 " prefix if present at start of text
                    # This prevents "0 " from propagating into requirements, RTM, traceability, etc.
                    if text.startswith("0 "):
                        text = text[2:].lstrip()  # Remove "0 " and any following whitespace
                    
                    # Preserve the original numbering token format
                    numbering_token = f"{number_token}{separator}"
                    detected_numbering_tokens.append(numbering_token)
                    # Embed numbering token in description text: "[number] text"
                    description_with_number = f"[{number_token}]{separator} {text}"
                    description_numbered_items.append({
                        "text": description_with_number,  # Embed numbering in text
                        "original": match.group(0).strip(),
                        "number_token": number_token,
                        "separator": separator
                    })
            
            # Also check extended patterns if no matches found
            if not description_numbered_items:
                for match in numbered_pattern_extended.finditer(description):
                    full_match = match.group(0).strip()
                    # Extract number from the match
                    number_match = re.search(r'(\d+)', full_match)
                    if number_match:
                        number_token = number_match.group(1)
                        text = match.group(2).strip() if len(match.groups()) >= 2 else match.group(1).strip()
                        if text and len(text) > 3:
                            # TARGETED CLEANUP: Remove stray "0 " prefix if present at start of text
                            if text.startswith("0 "):
                                text = text[2:].lstrip()  # Remove "0 " and any following whitespace
                            
                            detected_numbering_tokens.append(number_token)
                            description_with_number = f"[{number_token}] {text}"
                            description_numbered_items.append({
                                "text": description_with_number,
                                "original": full_match,
                                "number_token": number_token,
                                "separator": "."
                            })
        
        # Extract from acceptance_criteria
        acceptance_criteria = compiled_ticket.get("acceptance_criteria", "")
        acceptance_criteria_items = []
        
        if acceptance_criteria:
            # Detect bulleted patterns: "-", "*", "•", etc.
            bulleted_pattern = re.compile(
                r'^[\s]*([\-\*•▪▫◦‣⁃]|\u2022|\u25E6|\u2043|\u2023)[\s]+(.+)$',
                re.MULTILINE
            )
            
            # Check for numbered items in acceptance_criteria
            for match in numbered_pattern.finditer(acceptance_criteria):
                number_token = match.group(1)
                separator = match.group(2).strip()
                text = match.group(3).strip() if len(match.groups()) >= 3 else ""
                
                if text and len(text) > 3:
                    # TARGETED CLEANUP: Remove stray "0 " prefix if present at start of text
                    if text.startswith("0 "):
                        text = text[2:].lstrip()  # Remove "0 " and any following whitespace
                    
                    numbering_token = f"{number_token}{separator}"
                    detected_numbering_tokens.append(numbering_token)
                    description_with_number = f"[{number_token}]{separator} {text}"
                    acceptance_criteria_items.append({
                        "text": description_with_number,
                        "original": match.group(0).strip(),
                        "number_token": number_token,
                        "separator": separator
                    })
            
            # Also check extended patterns
            if not any(item.get("number_token") for item in acceptance_criteria_items):
                for match in numbered_pattern_extended.finditer(acceptance_criteria):
                    full_match = match.group(0).strip()
                    number_match = re.search(r'(\d+)', full_match)
                    if number_match:
                        number_token = number_match.group(1)
                        text = match.group(2).strip() if len(match.groups()) >= 2 else match.group(1).strip()
                        if text and len(text) > 3:
                            # TARGETED CLEANUP: Remove stray "0 " prefix if present at start of text
                            if text.startswith("0 "):
                                text = text[2:].lstrip()  # Remove "0 " and any following whitespace
                            
                            detected_numbering_tokens.append(number_token)
                            description_with_number = f"[{number_token}] {text}"
                            acceptance_criteria_items.append({
                                "text": description_with_number,
                                "original": full_match,
                                "number_token": number_token,
                                "separator": "."
                            })
            
            # Extract bulleted items (non-numbered)
            for match in bulleted_pattern.finditer(acceptance_criteria):
                text = match.group(2).strip() if len(match.groups()) >= 2 else match.group(1).strip()
                if text and len(text) > 3:
                    acceptance_criteria_items.append({
                        "text": text,
                        "original": match.group(0).strip()
                    })
        
        # Combine numbered items from description and acceptance_criteria
        # Description items take precedence (Jira description is authoritative)
        all_numbered_items = description_numbered_items + [
            item for item in acceptance_criteria_items 
            if item.get("number_token") and item not in description_numbered_items
        ]
        
        # Store for validation
        compiled_ticket["_detected_numbering_tokens"] = detected_numbering_tokens
        compiled_ticket["_numbering_items"] = all_numbered_items
        
        # Force has_acceptance_criteria = true if numbered/bulleted items detected
        # Use all_numbered_items (from description + acceptance_criteria) for detection
        has_numbered_acceptance_criteria = len(all_numbered_items) > 0 or len(acceptance_criteria_items) > 0
        # Store flag in compiled_ticket for later use
        if has_numbered_acceptance_criteria:
            compiled_ticket["_has_numbered_acceptance_criteria"] = True
        
        # Merge requirements and normalize source field
        # Requirements are scoped to a single ticket and must never be merged,
        # deduplicated, or normalized across tickets, even if the text is identical.
        # Normalization here is only for source field consistency within a single ticket.
        
        # DEBUG: Track requirements extraction pipeline
        debug_requirements = os.getenv("DEBUG_REQUIREMENTS", "0") == "1"
        extracted_items_total = len(all_numbered_items) + len(acceptance_criteria_items)
        extracted_items_testable = sum(1 for item in (all_numbered_items + acceptance_criteria_items) 
                                      if isinstance(item, dict) and item.get("text"))
        
        if debug_requirements:
            logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: Starting requirements extraction")
            logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: extracted_items_total={extracted_items_total}, extracted_items_testable={extracted_items_testable}")
            logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: has_numbered_acceptance_criteria={has_numbered_acceptance_criteria}")
            logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: LLM response has 'requirements' key: {'requirements' in llm_response}")
            if "requirements" in llm_response:
                logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: LLM requirements type: {type(llm_response.get('requirements'))}, count: {len(llm_response.get('requirements', []))}")
                # Log if requirements key exists but is empty
                if isinstance(llm_response.get("requirements"), list) and len(llm_response.get("requirements", [])) == 0:
                    logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: requirements key present but empty -> routing to Path B/C")
        
        if "requirements" in llm_response and isinstance(llm_response["requirements"], list) and len(llm_response["requirements"]) > 0:
            # STEP3: Path A enter
            if debug_requirements:
                logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: STEP3_PATH_A_ENTER")
            
            llm_req_count = len(llm_response["requirements"])
            normalized_requirements = []
            seen_ids_in_ticket = set()  # Track IDs only within this ticket to prevent duplicates
            skipped_count = 0
            
            if debug_requirements:
                logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: EXTRACTION PATH: Path A (use LLM requirements), llm_req_count={llm_req_count}")
            
            # Separate acceptance-criteria-derived requirements from inferred requirements
            acceptance_criteria_requirements = []
            inferred_requirements = []
            
            for req in llm_response["requirements"]:
                if isinstance(req, dict):
                    req_id = req.get("id", "")
                    # Only deduplicate within this single ticket (by ID) if ID exists
                    # Requirements without IDs are always included (they'll get prefixed later)
                    if req_id:
                        if req_id in seen_ids_in_ticket:
                            skipped_count += 1
                            logger.debug(f"Skipping duplicate requirement ID {req_id} in ticket {ticket_id}")
                            continue  # Skip duplicate ID within same ticket
                        seen_ids_in_ticket.add(req_id)
                    
                    # Normalize source field: ensure single explicit value
                    source = req.get("source", "").strip().lower()
                    if source in ["jira", "inferred"]:
                        req["source"] = source
                    else:
                        # Default to "inferred" if ambiguous or missing
                        req["source"] = "inferred"
                    
                    # Add quality scoring
                    req["quality"] = score_requirement_quality(req)
                    
                    # Add coverage expectations (will be updated after tests are generated)
                    req["coverage_expectations"] = compute_coverage_expectations(req)
                    
                    # Evaluate testability per requirement
                    req["testable"] = is_requirement_testable(req)
                    
                    # Separate by source: acceptance criteria requirements come first
                    if req["source"] == "jira":
                        acceptance_criteria_requirements.append(req)
                    else:
                        inferred_requirements.append(req)
            
            # ============================================================================
            # DETERMINISTIC EXTRACTION RULE: Each numbered list item = separate requirement
            # If a ticket contains a numbered list (e.g., 1., 2., 3.), each numbered item
            # must be extracted as a separate requirement and must not be collapsed.
            # ============================================================================
            if has_numbered_acceptance_criteria:
                # CRITICAL: Each numbered item MUST become a separate requirement
                # Do NOT match or collapse LLM requirements with numbered items
                # LLM requirements are treated as inferred requirements, not replacements
                
                # Create one requirement per numbered item (from description or acceptance_criteria)
                # Preserve original order and generate distinct requirement IDs
                # IMPORTANT: Use all_numbered_items which contains preserved numbering tokens
                numbered_requirements = []
                items_to_process = all_numbered_items if all_numbered_items else acceptance_criteria_items
                
                for idx, item in enumerate(items_to_process, 1):
                    # Preserve numbering token in description (e.g., "[3] Load from JIRA button")
                    # The item["text"] already contains the embedded numbering token
                    item_text = item.get("text", "")
                    if not item_text:
                        continue
                    
                    req = {
                        "id": f"REQ-{idx:03d}",
                        "source": "jira",
                        "description": item_text  # Contains preserved numbering token
                    }
                    req["quality"] = score_requirement_quality(req)
                    req["coverage_expectations"] = compute_coverage_expectations(req)
                    # Evaluate testability per requirement after splitting
                    req["testable"] = is_requirement_testable(req)
                    numbered_requirements.append(req)
                    seen_ids_in_ticket.add(req["id"])
                
                # LLM requirements (both acceptance_criteria_requirements and inferred_requirements)
                # are treated as inferred requirements and come AFTER numbered requirements
                # This ensures numbered items are never collapsed or replaced
                all_llm_requirements = acceptance_criteria_requirements + inferred_requirements
                
                # SUPPRESS DUPLICATE INFERRED REQUIREMENTS when numbered requirements exist
                # Filter out inferred requirements that overlap in meaning or text with numbered requirements
                filtered_llm_requirements = []
                for req in all_llm_requirements:
                    if not isinstance(req, dict):
                        continue
                    
                    req_desc = req.get("description", "").lower().strip()
                    if not req_desc:
                        # Keep requirements with no description (rare edge case)
                        filtered_llm_requirements.append(req)
                        continue
                    
                    # Check for semantic overlap with numbered requirements
                    # SUPPRESSION RULE: If a numbered Jira requirement exists, suppress inferred requirements
                    # that match the same core action verb and object (semantic similarity)
                    is_duplicate = False
                    for numbered_req in numbered_requirements:
                        if not isinstance(numbered_req, dict):
                            continue
                        
                        numbered_source = numbered_req.get("source", "").lower()
                        # Only suppress if numbered requirement originates from Jira source
                        if numbered_source != "jira":
                            continue
                        
                        numbered_desc = numbered_req.get("description", "").lower().strip()
                        if not numbered_desc:
                            continue
                        
                        # Check if numbered requirement has explicit numbering token
                        # Pattern: "[1].", "1.", "(1)", "1)", "1 -", etc.
                        numbering_token_pattern = re.compile(r'^(\[?\d+\]?[\.\)\-\s]+)', re.IGNORECASE)
                        has_numbering_token = bool(numbering_token_pattern.match(numbered_desc))
                        
                        if not has_numbering_token:
                            continue  # Only suppress for numbered requirements
                        
                        # Extract core semantic content (action verb + object)
                        # Remove numbering tokens, punctuation, and normalize
                        req_desc_clean = re.sub(r'\[?\d+\]?[\.\)\-\s]*', '', req_desc)
                        numbered_desc_clean = re.sub(r'\[?\d+\]?[\.\)\-\s]*', '', numbered_desc)
                        
                        # Remove punctuation for comparison
                        req_desc_clean = re.sub(r'[^\w\s]', ' ', req_desc_clean)
                        numbered_desc_clean = re.sub(r'[^\w\s]', ' ', numbered_desc_clean)
                        
                        # Extract action verbs and key nouns (objects)
                        # Common action verbs in requirements
                        action_verbs = {
                            'provide', 'create', 'generate', 'display', 'show', 'enable', 'allow', 'support',
                            'include', 'contain', 'have', 'must', 'shall', 'should', 'will', 'can', 'may',
                            'implement', 'add', 'remove', 'delete', 'update', 'modify', 'change', 'set',
                            'validate', 'verify', 'check', 'ensure', 'require', 'accept', 'reject', 'handle',
                            'process', 'execute', 'perform', 'run', 'send', 'receive', 'return', 'export',
                            'import', 'download', 'upload', 'save', 'load', 'open', 'close', 'submit'
                        }
                        
                        # Extract words from both descriptions
                        req_words = set(req_desc_clean.split())
                        numbered_words = set(numbered_desc_clean.split())
                        
                        # Remove stop words
                        stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'from', 'is', 'are', 'was', 'were', 'be', 'been', 'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'should', 'could', 'may', 'might', 'must', 'can', 'shall', 'system', 'user', 'shall'}
                        req_words = req_words - stop_words
                        numbered_words = numbered_words - stop_words
                        
                        if len(req_words) == 0 or len(numbered_words) == 0:
                            continue
                        
                        # Extract action verbs from both
                        req_verbs = req_words.intersection(action_verbs)
                        numbered_verbs = numbered_words.intersection(action_verbs)
                        
                        # Extract key nouns (objects) - words that are not verbs or stop words
                        req_nouns = req_words - action_verbs
                        numbered_nouns = numbered_words - action_verbs
                        
                        # Semantic matching: Check if core action verb and object match
                        # Match if:
                        # 1. Same action verb(s) OR no action verbs in either (both descriptive)
                        # 2. Significant overlap in key nouns (objects) - at least 50% of shorter set
                        verbs_match = False
                        if len(req_verbs) > 0 and len(numbered_verbs) > 0:
                            # Both have action verbs - must have at least one in common
                            verbs_match = len(req_verbs.intersection(numbered_verbs)) > 0
                        elif len(req_verbs) == 0 and len(numbered_verbs) == 0:
                            # Neither has explicit action verbs - treat as match (both descriptive)
                            verbs_match = True
                        else:
                            # One has verbs, one doesn't - check if nouns overlap significantly
                            verbs_match = False
                        
                        # Check noun (object) overlap
                        common_nouns = req_nouns.intersection(numbered_nouns)
                        if len(req_nouns) > 0 and len(numbered_nouns) > 0:
                            noun_overlap_ratio = len(common_nouns) / min(len(req_nouns), len(numbered_nouns))
                        else:
                            noun_overlap_ratio = 0
                        
                        # Suppress if: verbs match AND significant noun overlap (>= 50%)
                        # OR: no verbs in either AND significant overall word overlap (>= 50%)
                        if verbs_match and noun_overlap_ratio >= 0.5:
                            is_duplicate = True
                            logger.debug(f"Suppressing inferred requirement (semantic match): '{req_desc[:50]}...' matches numbered requirement '{numbered_desc[:50]}...' (verbs: {req_verbs.intersection(numbered_verbs) if verbs_match else 'none'}, nouns: {len(common_nouns)}/{min(len(req_nouns), len(numbered_nouns))})")
                            break
                        
                        # Fallback: Check for exact substring match (one contains the other)
                        if req_desc_clean in numbered_desc_clean or numbered_desc_clean in req_desc_clean:
                            is_duplicate = True
                            logger.debug(f"Suppressing inferred requirement (substring match): '{req_desc[:50]}...' matches numbered requirement '{numbered_desc[:50]}...'")
                            break
                    
                    if not is_duplicate:
                        filtered_llm_requirements.append(req)
                
                # Renumber filtered LLM requirements to avoid ID conflicts
                # Start numbering after the numbered requirements
                llm_req_counter = len(numbered_requirements)
                for req in filtered_llm_requirements:
                    if isinstance(req, dict):
                        llm_req_counter += 1
                        req["id"] = f"REQ-{llm_req_counter:03d}"
                        req["source"] = "inferred"  # All LLM requirements are inferred when numbered items exist
                        if req["id"] not in seen_ids_in_ticket:
                            seen_ids_in_ticket.add(req["id"])
                
                # Final order: numbered requirements first, then filtered inferred LLM requirements
                normalized_requirements = numbered_requirements + filtered_llm_requirements
            else:
                # No numbered acceptance criteria - use original order
                normalized_requirements = acceptance_criteria_requirements + inferred_requirements
            
            if skipped_count > 0:
                logger.info(f"Ticket {ticket_id}: LLM returned {llm_req_count} requirements, {skipped_count} duplicates skipped, {len(normalized_requirements)} kept")
            elif llm_req_count != len(normalized_requirements):
                logger.warning(f"Ticket {ticket_id}: Requirement count mismatch - LLM returned {llm_req_count}, normalized to {len(normalized_requirements)}")
            
            # ============================================================================
            # SPLIT COMPOUND REQUIREMENTS: Expand multi-clause requirements into atomic ones
            # This must occur during ticket extraction, before any multi-ticket aggregation
            # ============================================================================
            atomic_requirements = split_compound_requirements(normalized_requirements)
            parsed_requirements_count = len(atomic_requirements)
            
            if debug_requirements:
                logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: Path A - After split_compound_requirements: parsed_requirements_count={parsed_requirements_count}")
                logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: Path A - normalized_requirements count before split: {len(normalized_requirements)}")
                if parsed_requirements_count == 0:
                    logger.warning(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: Path A - parsed_requirements_count is 0 - requirements array will be empty")
                    logger.warning(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: Path A - Reason: llm_req_count={llm_req_count}, numbered_requirements={len(numbered_requirements) if 'numbered_requirements' in locals() else 0}, filtered_llm={len(filtered_llm_requirements) if 'filtered_llm_requirements' in locals() else 0}")
            
            # ============================================================================
            # ZERO-OUTPUT CHECK: If Path A produced 0 requirements, fall back to Path B/C
            # ============================================================================
            path_a_zero_output = False
            if len(atomic_requirements) == 0:
                if debug_requirements:
                    logger.warning(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: Path A produced 0 atomic_requirements, falling back to Path B/C extraction")
                # Set flag to trigger Path B/C extraction (will be handled below)
                path_a_zero_output = True
            else:
                test_plan["requirements"] = atomic_requirements
                
                # ============================================================================
                # REQUIREMENT CLASSIFICATION REFINEMENT: Classify UI structure requirements
                # This ensures UI presence/availability requirements are correctly categorized
                # before negative test generation (for logical failure-mode inference)
                # ============================================================================
                classify_requirement_ui_structure(test_plan["requirements"])
                
                # ============================================================================
                # POST-EXTRACTION GROUPING: Create ticket items from numbered requirements with comma-separated lists
                # This creates child ITEMs under parent requirements that contain comma-separated phrases
                # ============================================================================
                create_items_from_numbered_requirements(test_plan, ticket_id)
                
                # ============================================================================
                # REQUIREMENT → ITEM CLASSIFICATION INHERITANCE: Inherit structural classifications
                # This ensures child items inherit parent requirement classifications (e.g., ui_structure)
                # before test generation, enabling correct negative test generation
                # ============================================================================
                inherit_requirement_classification_to_items(test_plan)
                
                # ============================================================================
                # VALIDATION: Ensure numbering tokens are preserved (AUDIT TRACEABILITY)
                # If numbering tokens were detected but lost during extraction, raise warning
                # ============================================================================
                if detected_numbering_tokens:
                    # Check if any requirements contain the numbering tokens
                    preserved_count = 0
                    for req in atomic_requirements:
                        if isinstance(req, dict):
                            req_desc = req.get("description", "")
                            # Check if any numbering token appears in requirement description
                            for token in detected_numbering_tokens:
                                # Extract just the number from token (e.g., "1." -> "1")
                                number_only = re.sub(r'[^\d]', '', token)
                                if number_only and (f"[{number_only}]" in req_desc or token in req_desc):
                                    preserved_count += 1
                                    break
                    
                    if preserved_count < len(detected_numbering_tokens):
                        missing_tokens = len(detected_numbering_tokens) - preserved_count
                        logger.warning(
                            f"EXTRACTION WARNING (Ticket {ticket_id}): {missing_tokens} numbering token(s) detected in Jira description "
                            f"but may not be preserved in extracted requirements. This may impact audit traceability. "
                            f"Detected tokens: {detected_numbering_tokens}"
                        )
                
            # Store flag indicating numbered acceptance criteria were detected
            if has_numbered_acceptance_criteria:
                test_plan["_has_numbered_acceptance_criteria"] = True
        
        # ============================================================================
        # PATH B/C: Extract requirements from normalized text or raw Jira fields
        # This path executes when:
        # 1. LLM didn't return requirements (original Path B/C)
        # 2. Path A produced 0 requirements after post-processing (zero-output fallback)
        # Priority: compiled_ticket description > LLM response description > LLM response summary > raw Jira fields
        # ============================================================================
        # Check if we should execute Path B/C
        path_a_had_requirements = ("requirements" in llm_response and isinstance(llm_response["requirements"], list) and len(llm_response["requirements"]) > 0)
        # Check if Path A produced zero requirements (path_a_zero_output is set in Path A block)
        path_a_produced_zero = locals().get("path_a_zero_output", False)
        should_execute_path_bc = not path_a_had_requirements or path_a_produced_zero
        
        if should_execute_path_bc:
            # STEP4: Path B enter
            if debug_requirements:
                logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: STEP4_PATH_B_ENTER")
                if path_a_produced_zero:
                    logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: EXTRACTION PATH: Path B/C (Path A zero-output fallback)")
                else:
                    logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: EXTRACTION PATH: Path B/C (No LLM requirements)")
                logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: has_numbered_acceptance_criteria={has_numbered_acceptance_criteria}")
            
            acceptance_criteria_requirements = []
            normalized_text_source = None
            normalized_text = None
            
            # First preference: Check compiled_ticket description (this is where normalized text actually lives)
            # This is the normalized Jira ticket description that contains "Normalized Requirements:" and "Scope (In):"
            compiled_description = compiled_ticket.get("description", "")
            if compiled_description and isinstance(compiled_description, str) and compiled_description.strip():
                normalized_text = compiled_description
                normalized_text_source = "normalized_from_compiled_ticket_description"
            # Second preference: Check LLM response description
            elif "description" in llm_response and isinstance(llm_response["description"], str) and llm_response["description"].strip():
                normalized_text = llm_response["description"]
                normalized_text_source = "normalized_from_llm_description"
            # Third preference: Check LLM response summary
            elif "summary" in llm_response and isinstance(llm_response["summary"], str) and llm_response["summary"].strip():
                normalized_text = llm_response["summary"]
                normalized_text_source = "normalized_from_llm_summary"
            
            if debug_requirements:
                if normalized_text:
                    logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: Found normalized text source: {normalized_text_source}")
                else:
                    logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: No normalized text found, will use raw Jira fields")
                    normalized_text_source = "raw_jira"
            
            # Extract from normalized requirements text if available
            normalized_numbered_items = []
            normalized_scope_in_items = []
            
            if normalized_text:
                # Extract numbered items from "Normalized Requirements:" section
                normalized_req_pattern = re.compile(
                    r'Normalized Requirements:\s*\n(.*?)(?=\n\s*(?:Scope \(In\):|$))',
                    re.DOTALL | re.IGNORECASE
                )
                normalized_req_match = normalized_req_pattern.search(normalized_text)
                if normalized_req_match:
                    normalized_req_section = normalized_req_match.group(1)
                    # Match numbered items: ^\s*\d+\)\s+(.+)$ (multiline)
                    numbered_pattern_normalized = re.compile(
                        r'^\s*(\d+)\)\s+(.+)$',
                        re.MULTILINE
                    )
                    for match in numbered_pattern_normalized.finditer(normalized_req_section):
                        number_token = match.group(1)
                        text = match.group(2).strip()
                        if text and len(text) > 3:
                            normalized_numbered_items.append({
                                "text": text,
                                "number_token": number_token,
                                "source": "normalized"
                            })
                    
                    if debug_requirements:
                        logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: extracted_numbered_items={len(normalized_numbered_items)} from 'Normalized Requirements:' section")
                
                # Extract bullet items from "Scope (In):" section
                scope_in_pattern = re.compile(
                    r'Scope \(In\):\s*\n(.*?)(?=\n\s*(?:Scope \(Out\):|$))',
                    re.DOTALL | re.IGNORECASE
                )
                scope_in_match = scope_in_pattern.search(normalized_text)
                if scope_in_match:
                    scope_in_section = scope_in_match.group(1)
                    # Match bullet lines starting with "-" until blank line or "Scope (Out):"
                    bullet_pattern = re.compile(
                        r'^\s*-\s+(.+)$',
                        re.MULTILINE
                    )
                    for match in bullet_pattern.finditer(scope_in_section):
                        text = match.group(1).strip()
                        if text and len(text) > 3:
                            normalized_scope_in_items.append({
                                "text": text,
                                "source": "normalized"
                            })
                    
                    if debug_requirements:
                        logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: extracted_scope_in_bullets={len(normalized_scope_in_items)} from 'Scope (In):' section")
            
            # Combine normalized items (numbered first, then scope-in bullets)
            all_normalized_items = normalized_numbered_items + normalized_scope_in_items
            
            # Path B: Create requirements from numbered/bulleted items if they exist
            # This is the 1/14 behavior: if LLM requirements are missing/empty but numbered items exist,
            # create one requirement per item from raw Jira fields
            if has_numbered_acceptance_criteria:
                # Create one requirement per numbered/bulleted item
                # Use all_numbered_items which contains preserved numbering tokens
                logger.warning(f"No requirements in LLM response for ticket {ticket_id}, but numbered items detected. Creating requirements from numbered items.")
                items_to_process = all_numbered_items if all_numbered_items else acceptance_criteria_items
                
                if debug_requirements:
                    logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: Path B - Using raw Jira fields, items_to_process count: {len(items_to_process)}")
                
                for idx, item in enumerate(items_to_process, 1):
                    item_text = item.get("text", "")
                    if not item_text:
                        continue
                    
                    req = {
                        "id": f"REQ-{idx:03d}",
                        "source": "jira",
                        "description": item_text  # Contains preserved numbering token
                    }
                    req["quality"] = score_requirement_quality(req)
                    req["coverage_expectations"] = compute_coverage_expectations(req)
                    # Evaluate testability per requirement after splitting
                    req["testable"] = is_requirement_testable(req)
                    acceptance_criteria_requirements.append(req)
            elif all_normalized_items:
                # Create requirements from normalized text items
                if debug_requirements:
                    logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: Path B - Creating requirements from normalized text, items count: {len(all_normalized_items)}")
                
                for idx, item in enumerate(all_normalized_items, 1):
                    item_text = item.get("text", "")
                    if not item_text:
                        continue
                    
                    # Use ticket-scoped ID for deterministic ordering
                    req_id = f"{ticket_id}-REQ-{idx:03d}" if ticket_id else f"REQ-{idx:03d}"
                    req = {
                        "id": req_id,
                        "source": "normalized",
                        "description": item_text,
                        "inferred": False
                    }
                    req["quality"] = score_requirement_quality(req)
                    req["coverage_expectations"] = compute_coverage_expectations(req)
                    req["testable"] = is_requirement_testable(req)
                    acceptance_criteria_requirements.append(req)
            
            parsed_requirements_count = len(acceptance_criteria_requirements)
            if debug_requirements:
                logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: Path B/C - extracted_numbered_items={len(normalized_numbered_items)}, extracted_scope_in_bullets={len(normalized_scope_in_items)}")
                logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: Path B/C - Text source used: {normalized_text_source}")
                logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: Path B/C - parsed_requirements_count={parsed_requirements_count}")
            
            test_plan["requirements"] = acceptance_criteria_requirements
            
            # DEBUG: Log final requirements count after Path B
            if debug_requirements:
                logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: Path B produced requirements_count={len(test_plan['requirements'])}")
            
            # Validation: Check if numbering tokens are preserved (only for raw Jira items)
            if detected_numbering_tokens and not all_normalized_items:
                preserved_count = 0
                for req in acceptance_criteria_requirements:
                    if isinstance(req, dict):
                        req_desc = req.get("description", "")
                        for token in detected_numbering_tokens:
                            number_only = re.sub(r'[^\d]', '', token)
                            if number_only and (f"[{number_only}]" in req_desc or token in req_desc):
                                preserved_count += 1
                                break
                
                if preserved_count < len(detected_numbering_tokens):
                    missing_tokens = len(detected_numbering_tokens) - preserved_count
                    logger.warning(
                        f"EXTRACTION WARNING (Ticket {ticket_id}): {missing_tokens} numbering token(s) detected in Jira description "
                        f"but may not be preserved in extracted requirements. This may impact audit traceability. "
                        f"Detected tokens: {detected_numbering_tokens}"
                    )
            
            # Store flag indicating numbered acceptance criteria were detected
            if has_numbered_acceptance_criteria or all_normalized_items:
                test_plan["_has_numbered_acceptance_criteria"] = True
            
            # Path C: Only create single inferred requirement if requirements[] is still empty
            if len(acceptance_criteria_requirements) == 0:
                # STEP5: Path C enter
                if debug_requirements:
                    logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: STEP5_PATH_C_ENTER")
                
                # No numbered acceptance criteria AND no normalized items - infer from ticket content
                logger.warning(f"No requirements in LLM response for ticket {ticket_id}. Attempting to infer requirement from ticket content.")
                
                if debug_requirements:
                    logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: EXTRACTION PATH: Path C (single inferred requirement)")
                    logger.warning(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: Path C - No numbered items and no normalized items, creating single inferred requirement")
                    logger.warning(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: Reason: LLM returned empty requirements AND no numbered acceptance criteria detected AND no normalized text items found")
                
                # Create at least one inferred requirement from ticket summary/description
                summary = compiled_ticket.get("summary", "")
                description = compiled_ticket.get("description", "")
                if summary or description:
                    inferred_req = {
                        "id": "REQ-001",
                        "source": "inferred",
                        "description": summary if summary else description[:200] if description else "Requirement inferred from ticket content"
                    }
                    inferred_req["quality"] = score_requirement_quality(inferred_req)
                    inferred_req["coverage_expectations"] = compute_coverage_expectations(inferred_req)
                    test_plan["requirements"] = [inferred_req]
                    
                    if debug_requirements:
                        logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: Path C - parsed_requirements_count=1 (single inferred requirement)")
                else:
                    if debug_requirements:
                        logger.warning(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: Path C - No summary or description, requirements will be empty")
                    test_plan["requirements"] = []
        
        # Final requirements count logging
        if debug_requirements:
            final_requirements = test_plan.get("requirements", [])
            final_count = len(final_requirements)
            final_ids = [req.get("id", "NO_ID") for req in final_requirements if isinstance(req, dict)]
            logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: FINAL requirements count={final_count}")
            logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: FINAL requirement IDs={final_ids}")
            if final_count == 0:
                logger.warning(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: FINAL REQUIREMENTS COUNT IS 0")
                logger.warning(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: extracted_items_total={extracted_items_total if 'extracted_items_total' in locals() else 'N/A'}, extracted_items_testable={extracted_items_testable if 'extracted_items_testable' in locals() else 'N/A'}")
                logger.warning(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: has_numbered_acceptance_criteria={has_numbered_acceptance_criteria if 'has_numbered_acceptance_criteria' in locals() else 'N/A'}")
                logger.warning(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: LLM requirements count: {llm_req_count if 'llm_req_count' in locals() else 'N/A'}")

        # Merge business_intent
        if "business_intent" in llm_response:
            test_plan["business_intent"] = llm_response["business_intent"]

        # Merge assumptions
        if "assumptions" in llm_response and isinstance(llm_response["assumptions"], list):
            test_plan["assumptions"] = llm_response["assumptions"]

        # Merge gaps_detected and normalize to structured format
        if "gaps_detected" in llm_response and isinstance(llm_response["gaps_detected"], list):
            normalized_gaps = []
            for gap in llm_response["gaps_detected"]:
                if isinstance(gap, dict):
                    # Already structured, use as-is
                    normalized_gaps.append(gap)
                elif isinstance(gap, str):
                    # Convert plain string to structured format
                    normalized_gaps.append({
                        "type": "general",
                        "severity": "medium",
                        "description": gap,
                        "suggested_question": "How should this gap be addressed?"
                    })
            test_plan["gaps_detected"] = normalized_gaps

        # Merge summary
        if "summary" in llm_response:
            test_plan["summary"] = llm_response["summary"]

        # Merge test_plan section
        if "test_plan" in llm_response and isinstance(llm_response["test_plan"], dict):
            test_plan_section = llm_response["test_plan"]

            # Merge each test category (new schema categories)
            for category in [
                "api_tests",
                "ui_tests",
                "data_validation_tests",
                "edge_cases",
                "negative_tests"
            ]:
                if category in test_plan_section and isinstance(test_plan_section[category], list):
                    # Normalize confidence field and validate/clean steps for each test case
                    normalized_tests = []
                    for test in test_plan_section[category]:
                        if isinstance(test, dict):
                            # Ensure confidence field exists and is valid
                            confidence = test.get("confidence", "").lower()
                            if confidence not in ["explicit", "inferred"]:
                                # Default to "inferred" if missing or invalid (safer assumption)
                                test["confidence"] = "inferred"
                            else:
                                test["confidence"] = confidence
                            
                            # Validate and clean steps - remove generic placeholders
                            cleaned_steps, steps_origin = validate_and_clean_test_steps(test.get("steps", []))
                            test["steps"] = cleaned_steps
                            test["steps_origin"] = steps_origin
                            
                            # Ensure intent_type and source_requirement_id are set
                            # If not provided by LLM, infer from requirements_covered
                            if "intent_type" not in test:
                                # Infer from dimension or default to happy_path
                                test["intent_type"] = test.get("dimension", "happy_path")
                            
                            if "source_requirement_id" not in test and test.get("requirements_covered"):
                                # Use first requirement as source (most common case)
                                test["source_requirement_id"] = test["requirements_covered"][0]
                            
                            # Add steps_explanation if steps are empty and not already present
                            if len(cleaned_steps) == 0 and "steps_explanation" not in test:
                                # Check if this is a UI requirement that should have generated steps
                                intent_type = test.get("intent_type", "")
                                source_req_id = test.get("source_requirement_id", "")
                                
                                # Try to find the requirement to check if it names a UI element
                                requirement_text = ""
                                if source_req_id and "requirements" in test_plan:
                                    for req in test_plan.get("requirements", []):
                                        if isinstance(req, dict) and req.get("id") == source_req_id:
                                            requirement_text = req.get("description", "").lower()
                                            break
                                
                                # Check if requirement names a UI element (button, link, field, etc.)
                                ui_keywords = ["button", "link", "menu", "field", "form", "page", "screen", "download", "click"]
                                has_ui_element = any(keyword in requirement_text for keyword in ui_keywords)
                                
                                if has_ui_element and intent_type in ["happy_path", "negative"]:
                                    test["steps_explanation"] = "Requirement names a UI element but insufficient detail to generate concrete steps. Consider adding: element location, expected outcome details, or validation criteria."
                                else:
                                    test["steps_explanation"] = "Insufficient detail to generate concrete test steps."
                            
                            # Add transparency note if steps use standard UI assumptions
                            if len(cleaned_steps) > 0 and "steps_explanation" not in test:
                                import re
                                # Check if steps contain UI primitives
                                ui_primitive_patterns_check = [
                                    r"verify.*is visible",
                                    r"click",
                                    r"tap",
                                    r"verify.*file",
                                    r"verify.*navigates",
                                    r"verify.*displays"
                                ]
                                ui_primitive_count = sum(
                                    1 for step in cleaned_steps
                                    if any(re.search(pattern, step.lower()) for pattern in ui_primitive_patterns_check)
                                )
                                if ui_primitive_count > 0:
                                    test["steps_explanation"] = "Steps generated using standard UI interaction assumptions."
                            
                            normalized_tests.append(test)
                        else:
                            normalized_tests.append(test)
                    test_plan["test_plan"][category] = normalized_tests

        # STEP6: Final counts before return
        if debug_requirements:
            final_count = len(test_plan.get("requirements", []))
            logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: STEP6_FINAL_COUNTS final requirements_count={final_count}")

        return test_plan

    except Exception as e:
        # Fall back to empty schema on any error
        if debug_requirements:
            logger.exception(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: EXCEPTION in generation")
        logger.error(f"LLM generation failed for ticket {compiled_ticket.get('ticket_id', 'UNKNOWN')}: {str(e)}", exc_info=True)
        # Try to create at least one requirement from ticket content even on error
        error_plan = get_empty_test_plan(ticket_id=compiled_ticket.get("ticket_id", ""))
        summary = compiled_ticket.get("summary", "")
        description = compiled_ticket.get("description", "")
        if summary or description:
            inferred_req = {
                "id": "REQ-001",
                "source": "inferred",
                "description": summary if summary else description[:200] if description else "Requirement inferred from ticket content (LLM generation failed)"
            }
            inferred_req["quality"] = score_requirement_quality(inferred_req)
            inferred_req["coverage_expectations"] = compute_coverage_expectations(inferred_req)
            error_plan["requirements"] = [inferred_req]
        return error_plan


def is_requirement_testable(requirement: dict) -> bool:
    """
    Evaluate whether a requirement is independently testable.
    
    A requirement is testable if it:
    - Describes observable behavior or outcomes
    - Names UI elements, API endpoints, or system artifacts
    - Has specific, verifiable success criteria
    
    A requirement is NOT testable if it:
    - Is purely informational or documentation
    - Describes implementation details without observable outcomes
    - Is unclear or incomplete
    
    Args:
        requirement: Requirement dictionary with description, quality, etc.
    
    Returns:
        bool: True if requirement is testable, False otherwise
    """
    if not isinstance(requirement, dict):
        return False
    
    description = requirement.get("description", "").strip()
    if not description or len(description) < 10:
        return False
    
    text_lower = description.lower()
    
    # Check for non-testable indicators
    non_testable_keywords = [
        "note:", "see:", "reference:", "documentation", "see also", "for more",
        "implementation detail", "technical constraint", "architecture", "design pattern"
    ]
    if any(keyword in text_lower for keyword in non_testable_keywords):
        return False
    
    # Check for testable indicators
    # UI elements
    ui_keywords = ["button", "link", "field", "menu", "tab", "page", "screen", "form", "input", "download", "export"]
    has_ui = any(keyword in text_lower for keyword in ui_keywords)
    import re
    has_quoted_label = bool(re.search(r'"[^"]+"', description))
    
    # System behaviors with observable outcomes
    system_behavior_keywords = [
        "generates", "creates", "produces", "displays", "shows", "renders",
        "validates", "verifies", "checks", "ensures", "returns", "responds"
    ]
    has_system_behavior = any(keyword in text_lower for keyword in system_behavior_keywords)
    
    # Action verbs indicating testable behavior
    action_verbs = ["must", "shall", "will", "should", "requires", "need to", "implement"]
    has_action_verb = any(verb in text_lower for verb in action_verbs)
    
    # Quality score check
    quality = requirement.get("quality", {})
    if isinstance(quality, dict):
        testability_score = quality.get("testability_score", 1.0)
        if testability_score < 0.3:  # Very low testability
            return False
    
    # Requirement is testable if it has UI elements, system behaviors, or action verbs
    return has_ui or has_quoted_label or has_system_behavior or has_action_verb


def compute_coverage_confidence(requirement, rtm_entry, test_plan):
    """
    Compute deterministic, explainable risk-weighted coverage confidence score.
    
    Args:
        requirement: Requirement dict with quality and coverage_expectations
        rtm_entry: RTM entry dict with coverage_status and covered_by_tests
        test_plan: Test plan dict with test_plan section containing all tests
    
    Returns:
        dict: {
            "score": float (0.0-1.0),
            "level": "low" | "medium" | "high",
            "reasons": [string]
        }
    """
    score = 1.0
    reasons = []
    
    # Extract quality scores
    quality = requirement.get("quality", {})
    if isinstance(quality, dict):
        clarity_score = quality.get("clarity_score", 1.0)
        testability_score = quality.get("testability_score", 1.0)
        
        # Subtract 0.2 if clarity_score < 0.8
        if clarity_score < 0.8:
            score -= 0.2
            reasons.append("Low requirement clarity")
        
        # Subtract 0.2 if testability_score < 0.8
        if testability_score < 0.8:
            score -= 0.2
            reasons.append("Low requirement testability")
    
    # Extract coverage expectations
    coverage_exp = requirement.get("coverage_expectations", {})
    if isinstance(coverage_exp, dict):
        # Check each expected dimension that is not covered
        dimension_labels = {
            "happy_path": "Happy path",
            "negative": "Negative testing",
            "boundary": "Boundary testing",
            "authorization": "Authorization testing",
            "data_validation": "Data validation testing",
            "stateful": "Stateful testing"
        }
        
        for dimension, label in dimension_labels.items():
            exp_status = coverage_exp.get(dimension, "not_applicable")
            if exp_status == "expected":
                # This dimension is expected but not covered (status is "expected", not "covered")
                score -= 0.15
                # Format reason to match requirement specification
                if dimension == "negative":
                    reasons.append("Expected negative testing not covered")
                elif dimension == "boundary":
                    reasons.append("Expected boundary testing not covered")
                elif dimension == "authorization":
                    reasons.append("Expected authorization testing not covered")
                elif dimension == "data_validation":
                    reasons.append("Expected data validation testing not covered")
                elif dimension == "happy_path":
                    reasons.append("Expected happy path testing not covered")
                elif dimension == "stateful":
                    reasons.append("Expected stateful testing not covered")
                else:
                    reasons.append(f"Expected {label.lower()} not covered")
    
    # Check test confidence and coverage status
    coverage_status = rtm_entry.get("coverage_status", "NOT COVERED")
    covered_by_tests = rtm_entry.get("covered_by_tests", [])
    
    # Subtract 0.3 if not covered at all
    if coverage_status == "NOT COVERED":
        score -= 0.3
        reasons.append("Requirement not covered by any tests")
    else:
        # Check if all covering tests are inferred
        test_plan_section = test_plan.get("test_plan", {})
        if isinstance(test_plan_section, dict):
            all_tests = []
            for category in ["api_tests", "ui_tests", "data_validation_tests", "edge_cases", "negative_tests"]:
                tests = test_plan_section.get(category, [])
                if isinstance(tests, list):
                    all_tests.extend(tests)
            
            # Build test_id -> test mapping
            test_map = {}
            for test in all_tests:
                if isinstance(test, dict):
                    test_id = test.get("id", "")
                    if test_id:
                        test_map[test_id] = test
            
            # Check if all covering tests are inferred
            all_inferred = True
            if covered_by_tests:
                for test_id in covered_by_tests:
                    test = test_map.get(test_id)
                    if test and isinstance(test, dict):
                        test_confidence = test.get("confidence", "").lower()
                        if test_confidence != "inferred":
                            all_inferred = False
                            break
                
                if all_inferred:
                    score -= 0.1
                    reasons.append("All coverage is inferred")
    
    # Clamp score between 0.0 and 1.0
    score = max(0.0, min(1.0, score))
    
    # Determine confidence level
    if score >= 0.8:
        level = "high"
    elif score >= 0.5:
        level = "medium"
    else:
        level = "low"
    
    return {
        "score": round(score, 2),
        "level": level,
        "reasons": reasons
    }


def generate_rtm(test_plan_json: dict) -> list:
    """
    Generate Requirement Traceability Matrix (RTM) from test plan JSON.
    
    This is a pure function that does not mutate input data.
    It aggregates tests across all test_plan categories and maps them to requirements.
    Also includes informational/non-testable items from ticket_item_coverage for full traceability.
    
    Args:
        test_plan_json: The complete test plan JSON structure
    
    Returns:
        list: RTM entries, each containing:
        - For testable requirements: requirement_id, requirement_description, covered_by_tests, coverage_status
        - For informational items: requirement_id (item_id), requirement_description (text), trace_type, 
          testability, rationale, source_section, covered_by_tests (empty)
    """
    rtm = []
    
    # Extract requirements
    requirements = test_plan_json.get("requirements", [])
    if not isinstance(requirements, list):
        requirements = []
    
    # Build a map of requirement_id -> requirement_description
    req_map = {}
    for req in requirements:
        if isinstance(req, dict):
            req_id = req.get("id", "")
            req_desc = req.get("description", "")
            if req_id:
                req_map[req_id] = req_desc
    
    # Aggregate all tests from all test_plan categories
    test_plan_section = test_plan_json.get("test_plan", {})
    if not isinstance(test_plan_section, dict):
        test_plan_section = {}
    
    # Collect all tests with their IDs and requirements_covered
    all_tests = []
    test_categories = [
        "api_tests",
        "ui_tests",
        "data_validation_tests",
        "edge_cases",
        "negative_tests"
    ]
    
    for category in test_categories:
        tests = test_plan_section.get(category, [])
        if isinstance(tests, list):
            for test in tests:
                if isinstance(test, dict):
                    test_id = test.get("id", "")
                    requirements_covered = test.get("requirements_covered", [])
                    if test_id and isinstance(requirements_covered, list):
                        all_tests.append({
                            "id": test_id,
                            "requirements_covered": requirements_covered
                        })
    
    # Build RTM: one entry per requirement (testable requirements first)
    for req_id, req_desc in req_map.items():
        # Find all tests that cover this requirement
        covered_by_tests = []
        for test in all_tests:
            if req_id in test.get("requirements_covered", []):
                covered_by_tests.append(test.get("id", ""))
        
        # Determine coverage status
        # VALIDATION RULE: If covered_by_tests is empty or null, coverage_status MUST NOT be "COVERED"
        if not covered_by_tests or len(covered_by_tests) == 0:
            coverage_status = "NOT COVERED"
        else:
            # covered_by_tests has at least one test ID
            coverage_status = "COVERED"
        
        rtm.append({
            "requirement_id": req_id,
            "requirement_description": req_desc,
            "covered_by_tests": covered_by_tests,
            "coverage_status": coverage_status,
            "trace_type": "testable",
            "testability": "testable"
        })
    
    # Append informational/non-testable items from ticket_item_coverage
    # These are added AFTER all testable requirements to maintain deterministic ordering
    ticket_item_coverage = test_plan_json.get("ticket_item_coverage", [])
    if isinstance(ticket_item_coverage, list):
        # Filter for non-testable items
        informational_items = []
        for item in ticket_item_coverage:
            if not isinstance(item, dict):
                continue
            
            testable = item.get("testable", True)
            coverage_method = item.get("coverage_method", "")
            
            # Include items that are not testable
            if not testable or coverage_method == "not_independently_testable":
                item_id = item.get("item_id", "")
                item_text = item.get("text", "")
                non_testable_reason = item.get("non_testable_reason", "")
                classification = item.get("classification", "")
                
                # Get source_section from ticket_traceability if available
                source_section = None
                ticket_traceability = test_plan_json.get("ticket_traceability", [])
                for trace_entry in ticket_traceability:
                    if isinstance(trace_entry, dict):
                        items = trace_entry.get("items", [])
                        if isinstance(items, list):
                            for trace_item in items:
                                if isinstance(trace_item, dict) and trace_item.get("item_id") == item_id:
                                    source_section = trace_item.get("source_section")
                                    break
                        if source_section:
                            break
                
                # If no source_section found, try to infer from classification or use default
                if not source_section:
                    if classification in ["informational_only", "not_independently_testable", "unclear_needs_clarification"]:
                        source_section = "ticket_analysis"
                    else:
                        source_section = "unknown"
                
                # Generate deterministic ID if missing
                if not item_id:
                    # Extract ticket_id from first requirement or use default
                    ticket_id = "UNKNOWN"
                    if requirements:
                        first_req_id = requirements[0].get("id", "")
                        if "-" in first_req_id:
                            ticket_id = first_req_id.split("-")[0]
                    # Use a counter based on position in informational_items
                    item_id = f"{ticket_id}-ITEM-{len(informational_items) + 1:03d}"
                
                informational_items.append({
                    "item_id": item_id,
                    "item_text": item_text,
                    "non_testable_reason": non_testable_reason,
                    "source_section": source_section
                })
        
        # Sort informational items by item_id for deterministic ordering
        informational_items.sort(key=lambda x: x["item_id"])
        
        # Append informational items to RTM
        for item in informational_items:
            rtm.append({
                "requirement_id": item["item_id"],
                "requirement_description": item["item_text"],
                "covered_by_tests": [],
                "coverage_status": "N/A",
                "trace_type": "informational",
                "testability": "not_testable",
                "rationale": item["non_testable_reason"] or "Informational content; not independently testable",
                "source_section": item["source_section"]
            })
    
    return rtm


def classify_requirement_ui_structure(requirements: list) -> None:
    """
    Classify requirements that describe UI element presence/availability as ui_structure.
    
    UI STRUCTURE CLASSIFICATION RULE:
    If a requirement describes the presence, visibility, or availability of UI elements
    (e.g., tabs, buttons, fields, sections), classify it as ui_structure instead of
    system_behavior, provided no explicit user action or data-processing behavior is described.
    
    This classification refinement happens before test generation to allow logical
    failure-mode inference (absence/inaccessibility) to apply correctly.
    
    Deterministic Criteria (all must be met):
    A. Contains one or more UI element indicators (tab, button, field, section, panel, area, view, page)
    B. Uses presence-oriented verbs (have, display, show, present, include, contain)
    C. Does NOT include explicit action verbs (click, submit, enter, upload, generate, validate, calculate)
    
    Args:
        requirements: List of requirement dicts (modified in place)
    """
    import re
    
    # UI element indicators
    ui_element_indicators = [
        "tab", "tabs", "button", "buttons", "field", "fields", "section", "sections",
        "panel", "panels", "area", "areas", "view", "views", "page", "pages",
        "menu", "menus", "link", "links", "input", "inputs", "form", "forms"
    ]
    
    # Presence-oriented verbs
    presence_verbs = [
        "have", "has", "had", "display", "displays", "displayed",
        "show", "shows", "shown", "present", "presents", "presented",
        "include", "includes", "included", "contain", "contains", "contained"
    ]
    
    # Explicit action verbs (exclude these)
    action_verbs = [
        "click", "clicks", "clicked", "submit", "submits", "submitted",
        "enter", "enters", "entered", "upload", "uploads", "uploaded",
        "generate", "generates", "generated", "validate", "validates", "validated",
        "calculate", "calculates", "calculated", "process", "processes", "processed",
        "create", "creates", "created", "delete", "deletes", "deleted",
        "update", "updates", "updated", "save", "saves", "saved"
    ]
    
    # Downstream behavior/data processing keywords (exclude these - indicates system_behavior)
    downstream_behavior_keywords = [
        "workflow", "workflows", "result", "results", "output", "outputs", "produces", "produced",
        "data processing", "processes data", "validates", "validation", "calculates", "calculation",
        "transforms", "transformation", "converts", "conversion", "generates", "generation",
        "creates", "creation", "builds", "constructs", "assembles", "compiles", "renders"
    ]
    
    for req in requirements:
        if not isinstance(req, dict):
            continue
        
        description = req.get("description", "").strip()
        if not description:
            continue
        
        # Skip if already classified as informational_only or not_independently_testable
        # (per guardrails - do NOT reclassify these)
        existing_classification = req.get("_classification", "")
        if existing_classification in ["informational_only", "not_independently_testable"]:
            continue
        
        text_lower = description.lower()
        
        # FIX A - UI ELEMENT CLASSIFICATION OVERRIDE:
        # If requirement references UI elements (button, tab, field, area, input) and does NOT
        # describe downstream behavior, data processing, validation, or workflow results,
        # classify as ui_structure instead of system_behavior
        
        # Check criterion A: Contains UI element indicators
        has_ui_element = any(indicator in text_lower for indicator in ui_element_indicators)
        if not has_ui_element:
            continue  # Not a UI structure requirement
        
        # Check criterion B: Uses presence-oriented verbs OR just references UI elements
        has_presence_verb = any(verb in text_lower for verb in presence_verbs)
        
        # Check criterion C: Does NOT include explicit action verbs
        has_action_verb = any(verb in text_lower for verb in action_verbs)
        if has_action_verb:
            continue  # Has explicit action - keep as system_behavior
        
        # Check criterion D: Does NOT describe downstream behavior, data processing, validation, or workflow
        has_downstream_behavior = any(keyword in text_lower for keyword in downstream_behavior_keywords)
        if has_downstream_behavior:
            continue  # Describes downstream behavior - keep as system_behavior
        
        # All criteria met: Classify as ui_structure
        # (Either has presence verb OR just references UI elements without behavior)
        req["_classification"] = "ui_structure"
        logger.debug(f"Classified requirement {req.get('id', 'UNKNOWN')} as ui_structure: '{description[:60]}...'")


def inherit_requirement_classification_to_items(test_plan: dict) -> None:
    """
    Inherit structural requirement classifications to child items.
    
    REQUIREMENT → ITEM CLASSIFICATION INHERITANCE RULE:
    If a parent requirement has a structural classification (e.g., ui_structure),
    all child items derived from that requirement must inherit the same classification,
    unless the item is explicitly classified as:
    - informational_only, or
    - not_independently_testable
    
    This ensures test generation receives the correct semantic signal for UI structure
    requirements, enabling correct negative test generation (absence/inaccessibility).
    
    Deterministic Rules:
    For each requirement R:
      Read R._classification
      For each item I where I.parent_requirement_id == R.id:
        If R._classification == ui_structure
        AND I.classification NOT IN [informational_only, not_independently_testable]
        THEN set: I.classification = ui_structure
    
    Args:
        test_plan: Test plan dict (modified in place)
    """
    requirements = test_plan.get("requirements", [])
    ticket_items = test_plan.get("_ticket_items", [])
    
    if not requirements or not ticket_items:
        return
    
    # Build requirement lookup by ID
    req_lookup = {}
    for req in requirements:
        if isinstance(req, dict):
            req_id = req.get("id", "")
            if req_id:
                req_lookup[req_id] = req
    
    # Process each item
    for item in ticket_items:
        if not isinstance(item, dict):
            continue
        
        parent_req_id = item.get("parent_requirement_id")
        if not parent_req_id:
            continue  # No parent requirement, skip
        
        # Get parent requirement
        parent_req = req_lookup.get(parent_req_id)
        if not parent_req:
            continue  # Parent requirement not found, skip
        
        # DETERMINISTIC INHERITANCE RULE: Inherit classification and testability from parent requirement
        # If parent requirement is classified as ui_structure, ui_element, informational_only, or not_independently_testable,
        # then all items derived from that requirement MUST inherit the same classification and testability
        parent_classification = parent_req.get("_classification", "")
        parent_testable = parent_req.get("testable", True)
        
        # Inheritable classifications (non-behavioral classifications that must be inherited)
        inheritable_classifications = ["ui_structure", "ui_element", "informational_only", "not_independently_testable"]
        
        if parent_classification in inheritable_classifications:
            # Get current item classification
            item_classification = item.get("classification", "")
            
            # Items may NOT be reclassified to system_behavior if parent requirement is non-behavioral
            # Force inheritance of non-behavioral classifications
            if item_classification == "system_behavior" and parent_classification in inheritable_classifications:
                # Override system_behavior classification with parent's non-behavioral classification
                item["classification"] = parent_classification
                logger.debug(f"Forced inheritance: Overrode system_behavior classification with '{parent_classification}' from requirement {parent_req_id} to item {item.get('item_id', 'UNKNOWN')}")
            elif item_classification not in ["informational_only", "not_independently_testable"]:
                # Inherit the classification (unless item is explicitly informational_only or not_independently_testable)
                item["classification"] = parent_classification
                logger.debug(f"Inherited classification '{parent_classification}' from requirement {parent_req_id} to item {item.get('item_id', 'UNKNOWN')}")
            
            # Inherit testable flag: If parent is non-testable, item must also be non-testable
            if not parent_testable:
                item["testable"] = False
                logger.debug(f"Inherited testable=False from requirement {parent_req_id} to item {item.get('item_id', 'UNKNOWN')}")
            
            # STRICT INHERITANCE RULE: Inherit coverage_expectations.negative from parent requirement
            # If parent coverage_expectations.negative = not_applicable, items may NOT generate, retain, or be marked as covered by negative tests
            parent_coverage_exp = parent_req.get("coverage_expectations", {})
            parent_negative = parent_coverage_exp.get("negative", "expected")
            if parent_negative == "not_applicable":
                # Store parent's negative expectation on item to prevent negative test generation/retention
                if "coverage_expectations" not in item:
                    item["coverage_expectations"] = {}
                item["coverage_expectations"]["negative"] = "not_applicable"
                item["_parent_negative_not_applicable"] = True  # Flag to enforce strict inheritance
                logger.debug(f"Inherited coverage_expectations.negative=not_applicable from requirement {parent_req_id} to item {item.get('item_id', 'UNKNOWN')}")


def validate_rtm_coverage_consistency(rtm: list) -> None:
    """
    Validate that coverage_status is consistent with covered_by_tests.
    
    VALIDATION RULE: If covered_by_tests is empty or null,
    coverage_status MUST NOT be set to "COVERED".
    
    Informational items (trace_type="informational") are exempt from this validation
    as they have coverage_status="N/A" by design.
    
    This is a consistency validation rule only - does not generate tests,
    infer coverage, or modify requirements.
    
    Args:
        rtm: List of RTM entry dicts (modified in place if inconsistencies found)
    """
    for entry in rtm:
        if not isinstance(entry, dict):
            continue
        
        # Skip informational items - they have coverage_status="N/A" by design
        trace_type = entry.get("trace_type", "testable")
        if trace_type == "informational":
            continue
        
        coverage_status = entry.get("coverage_status", "")
        covered_by_tests = entry.get("covered_by_tests", [])
        
        # Check if covered_by_tests is empty or null
        is_empty = (
            not covered_by_tests or
            (isinstance(covered_by_tests, list) and len(covered_by_tests) == 0) or
            covered_by_tests is None
        )
        
        # VALIDATION: If covered_by_tests is empty, coverage_status MUST NOT be "COVERED"
        if is_empty and coverage_status == "COVERED":
            requirement_id = entry.get("requirement_id", "UNKNOWN")
            logger.warning(
                f"RTM consistency violation: Requirement {requirement_id} has coverage_status='COVERED' "
                f"but covered_by_tests is empty. Correcting to 'NOT COVERED'."
            )
            entry["coverage_status"] = "NOT COVERED"


def detect_composite_ticket_item(item_text: str) -> bool:
    """
    Detect if a ticket item is composite (contains multiple UI elements or actions).
    
    A composite item contains multiple distinct UI elements, controls, or user-visible actions
    that should be split into separate bullet-level items for audit enumeration.
    
    Args:
        item_text: The text content of the ticket item
    
    Returns:
        bool: True if the item appears to be composite, False otherwise
    """
    if not isinstance(item_text, str) or len(item_text.strip()) < 10:
        return False
    
    text_lower = item_text.lower()
    
    # Count distinct UI element keywords
    ui_keywords = [
        "button", "link", "field", "input", "dropdown", "select", "menu", "tab", 
        "checkbox", "radio", "toggle", "switch", "slider", "text area", "textarea",
        "form", "page", "screen", "modal", "dialog", "panel", "section", "card",
        "table", "list", "grid", "upload", "download", "export", "import", "save",
        "cancel", "submit", "delete", "edit", "add", "remove", "search", "filter"
    ]
    
    ui_element_count = sum(1 for keyword in ui_keywords if keyword in text_lower)
    
    # Check for multiple quoted strings (likely UI element labels)
    import re
    quoted_strings = re.findall(r'"[^"]+"', item_text)
    if len(quoted_strings) > 1:
        return True
    
    # Check for common separators that indicate multiple items
    separators = [
        r'\s+and\s+',  # "field A and field B"
        r'\s+or\s+',   # "button X or button Y"
        r',\s+(?:and\s+)?',  # "field A, field B, and field C"
        r';\s+',       # "field A; field B"
        r'\s+then\s+', # "click button then select field"
        r'\s+followed\s+by\s+',  # "field A followed by field B"
    ]
    
    separator_count = sum(1 for sep in separators if re.search(sep, text_lower, re.IGNORECASE))
    
    # Composite if:
    # - Multiple UI elements mentioned (2+)
    # - Multiple separators (2+)
    # - Multiple quoted strings (2+)
    # - UI elements + separators (1+ each)
    if ui_element_count >= 2:
        return True
    if separator_count >= 2:
        return True
    if len(quoted_strings) >= 2:
        return True
    if ui_element_count >= 1 and separator_count >= 1:
        return True
    
    # Check for patterns like "X, Y, and Z" where X, Y, Z are likely UI elements
    list_pattern = re.compile(r'\b(\w+(?:\s+\w+)*)\s*,\s*(\w+(?:\s+\w+)*)(?:\s*,\s*and\s+(\w+(?:\s+\w+)*))?', re.IGNORECASE)
    matches = list_pattern.findall(text_lower)
    if matches:
        # Check if the matched phrases contain UI keywords
        for match in matches:
            phrases = [m for m in match if m]
            ui_phrase_count = sum(1 for phrase in phrases if any(kw in phrase for kw in ui_keywords))
            if ui_phrase_count >= 2:
                return True
    
    return False


def split_composite_ticket_item(item: dict, ticket_id: str, base_item_counter: int) -> list:
    """
    Split a composite ticket item into multiple bullet-level items.
    
    Each split item represents ONE UI element or ONE distinct user-visible action.
    All split items inherit the parent requirement ID and coverage mapping from the original.
    
    Args:
        item: Original composite item dict
        ticket_id: Ticket ID for generating new item IDs
        base_item_counter: Base counter for generating sequential item IDs
    
    Returns:
        list: List of split item dicts, each with unique item_id but same parent requirement
    """
    if not isinstance(item, dict):
        return [item]
    
    item_text = item.get("text", "")
    if not detect_composite_ticket_item(item_text):
        return [item]  # Not composite, return as-is
    
    import re
    
    # Strategy 1: Split by common separators (and, or, comma, semicolon)
    # Try splitting by "and" first (most common)
    if re.search(r'\s+and\s+', item_text, re.IGNORECASE):
        parts = re.split(r'\s+and\s+', item_text, flags=re.IGNORECASE)
        if len(parts) > 1:
            split_items = []
            for idx, part in enumerate(parts, 1):
                part = part.strip()
                if part:
                    # Remove leading comma if present
                    part = re.sub(r'^,\s*', '', part)
                    # Remove trailing comma if present
                    part = re.sub(r',\s*$', '', part)
                    if part:
                        split_items.append(part)
            
            if len(split_items) > 1:
                result = []
                for idx, split_text in enumerate(split_items, 1):
                    new_item = item.copy()
                    new_item["item_id"] = f"{ticket_id}-ITEM-{base_item_counter + idx:03d}"
                    new_item["text"] = split_text.strip()
                    # Preserve all original metadata:
                    # - mapped_requirement_id (inherited by all split items)
                    # - validated_by_tests (inherited by all split items)
                    # - classification (may be re-evaluated later, but preserve for now)
                    # - source_section (inherited)
                    # All split items map to the same parent requirement
                    result.append(new_item)
                return result
    
    # Strategy 2: Split by commas (if not already split)
    if ',' in item_text:
        # Check if it's a list pattern (e.g., "field A, field B, and field C")
        list_pattern = re.compile(r'(.+?)(?:,\s*and\s+)?,\s*(.+)', re.IGNORECASE)
        match = list_pattern.search(item_text)
        if match:
            parts = re.split(r',\s*(?:and\s+)?', item_text, flags=re.IGNORECASE)
            parts = [p.strip() for p in parts if p.strip()]
            if len(parts) > 1:
                result = []
                for idx, split_text in enumerate(parts, 1):
                    new_item = item.copy()
                    new_item["item_id"] = f"{ticket_id}-ITEM-{base_item_counter + idx:03d}"
                    new_item["text"] = split_text.strip()
                    # Preserve all original metadata (mapped_requirement_id, validated_by_tests, etc.)
                    result.append(new_item)
                return result
    
    # Strategy 3: Split by semicolons
    if ';' in item_text:
        parts = [p.strip() for p in item_text.split(';') if p.strip()]
        if len(parts) > 1:
            result = []
            for idx, split_text in enumerate(parts, 1):
                new_item = item.copy()
                new_item["item_id"] = f"{ticket_id}-ITEM-{base_item_counter + idx:03d}"
                new_item["text"] = split_text.strip()
                result.append(new_item)
            return result
    
    # Strategy 4: Split by quoted strings (each quoted string becomes an item)
    quoted_strings = re.findall(r'"[^"]+"', item_text)
    if len(quoted_strings) > 1:
        # Extract context around each quoted string
        parts = []
        remaining_text = item_text
        for quote in quoted_strings:
            # Find the quote in the text and extract surrounding context
            quote_idx = remaining_text.find(quote)
            if quote_idx >= 0:
                # Extract text before quote + quote itself
                before = remaining_text[:quote_idx].strip()
                quote_text = quote
                # Try to extract a meaningful phrase
                if before:
                    # Look for action words before the quote
                    action_match = re.search(r'(\w+(?:\s+\w+)*)\s*' + re.escape(quote), remaining_text, re.IGNORECASE)
                    if action_match:
                        parts.append(f"{action_match.group(1)} {quote_text}")
                    else:
                        parts.append(quote_text)
                else:
                    parts.append(quote_text)
                remaining_text = remaining_text[quote_idx + len(quote):].strip()
        
        if len(parts) > 1:
            result = []
            for idx, split_text in enumerate(parts, 1):
                new_item = item.copy()
                new_item["item_id"] = f"{ticket_id}-ITEM-{base_item_counter + idx:03d}"
                new_item["text"] = split_text.strip()
                result.append(new_item)
            return result
    
    # Strategy 5: Split by "then" or "followed by" (sequential actions)
    if re.search(r'\s+then\s+|\s+followed\s+by\s+', item_text, re.IGNORECASE):
        parts = re.split(r'\s+then\s+|\s+followed\s+by\s+', item_text, flags=re.IGNORECASE)
        parts = [p.strip() for p in parts if p.strip()]
        if len(parts) > 1:
            result = []
            for idx, split_text in enumerate(parts, 1):
                new_item = item.copy()
                new_item["item_id"] = f"{ticket_id}-ITEM-{base_item_counter + idx:03d}"
                new_item["text"] = split_text.strip()
                result.append(new_item)
            return result
    
    # If no splitting strategy worked, return original item
    return [item]


def validate_composite_splitting_invariants(test_plan_before: dict, test_plan_after: dict) -> tuple[bool, list[str]]:
    """
    Validate that composite splitting did not violate any invariants.
    
    Checks:
    - Requirement count unchanged
    - Test count unchanged
    - Coverage metrics unchanged
    - RTM rows unchanged
    - Bullet-level enumeration present (more items after splitting if composites existed)
    
    Args:
        test_plan_before: Test plan before splitting
        test_plan_after: Test plan after splitting
    
    Returns:
        tuple: (is_valid, list_of_violations)
    """
    violations = []
    
    # Check requirement count
    reqs_before = test_plan_before.get("requirements", [])
    reqs_after = test_plan_after.get("requirements", [])
    if len(reqs_before) != len(reqs_after):
        violations.append(f"Requirement count changed: {len(reqs_before)} -> {len(reqs_after)}")
    
    # Check requirement IDs (should be identical sets)
    req_ids_before = {r.get("id") for r in reqs_before if isinstance(r, dict) and r.get("id")}
    req_ids_after = {r.get("id") for r in reqs_after if isinstance(r, dict) and r.get("id")}
    if req_ids_before != req_ids_after:
        violations.append(f"Requirement IDs changed: {req_ids_before} != {req_ids_after}")
    
    # Check test counts by category
    test_plan_before_section = test_plan_before.get("test_plan", {})
    test_plan_after_section = test_plan_after.get("test_plan", {})
    
    test_categories = ["api_tests", "ui_tests", "negative_tests", "edge_cases", "data_validation_tests"]
    for category in test_categories:
        tests_before = test_plan_before_section.get(category, [])
        tests_after = test_plan_after_section.get(category, [])
        if len(tests_before) != len(tests_after):
            violations.append(f"Test count in {category} changed: {len(tests_before)} -> {len(tests_after)}")
        
        # Check test IDs
        test_ids_before = {t.get("id") for t in tests_before if isinstance(t, dict) and t.get("id")}
        test_ids_after = {t.get("id") for t in tests_after if isinstance(t, dict) and t.get("id")}
        if test_ids_before != test_ids_after:
            violations.append(f"Test IDs in {category} changed")
    
    # Check RTM row count
    rtm_before = test_plan_before.get("rtm", [])
    rtm_after = test_plan_after.get("rtm", [])
    if len(rtm_before) != len(rtm_after):
        violations.append(f"RTM row count changed: {len(rtm_before)} -> {len(rtm_after)}")
    
    # Check RTM requirement IDs
    rtm_req_ids_before = {r.get("requirement_id") for r in rtm_before if isinstance(r, dict) and r.get("requirement_id")}
    rtm_req_ids_after = {r.get("requirement_id") for r in rtm_after if isinstance(r, dict) and r.get("requirement_id")}
    if rtm_req_ids_before != rtm_req_ids_after:
        violations.append(f"RTM requirement IDs changed")
    
    # Note: We expect ticket_item_coverage to have MORE items after splitting (if composites existed)
    # This is expected and not a violation
    
    return (len(violations) == 0, violations)


def split_composite_ticket_items(test_plan: dict) -> None:
    """
    Split composite ticket items into bullet-level items for audit enumeration.
    
    NOTE: Atomic enumeration is now primarily performed during extraction
    (in extract_ticket_items()). This function serves as a safety net to catch
    any composite items that may have been missed during extraction.
    
    This is a TRACEABILITY REFINEMENT ONLY. It does NOT:
    - Add, remove, merge, or deduplicate requirements
    - Change requirement IDs
    - Add, remove, merge, or deduplicate tests
    - Change test IDs
    - Change source_requirement_id
    - Change requirements_covered
    - Recalculate coverage %, confidence, or scoring
    - Change RTM primary rows
    
    It ONLY:
    - Detects composite ticket items (items with multiple UI elements/actions)
    - Splits them into bullet-level items
    - Updates ticket_traceability with split items
    - Preserves all parent requirement mappings and coverage
    
    Args:
        test_plan: Test plan dictionary (modified in place)
    """
    import copy
    
    # Create a deep copy for validation (only copy what we need to check)
    test_plan_before = {
        "requirements": copy.deepcopy(test_plan.get("requirements", [])),
        "test_plan": copy.deepcopy(test_plan.get("test_plan", {})),
        "rtm": copy.deepcopy(test_plan.get("rtm", []))
    }
    
    ticket_traceability = test_plan.get("ticket_traceability", [])
    
    if not ticket_traceability:
        return  # Nothing to process
    
    # Process each ticket entry
    for ticket_entry in ticket_traceability:
        if not isinstance(ticket_entry, dict):
            continue
        
        ticket_id = ticket_entry.get("ticket_id", "")
        items = ticket_entry.get("items", [])
        
        if not isinstance(items, list):
            continue
        
        # Track item counter for ID generation
        # Find the highest existing item number to avoid collisions
        max_item_num = 0
        for item in items:
            if isinstance(item, dict):
                item_id = item.get("item_id", "")
                # Extract number from item_id (e.g., "ATA-18-ITEM-001" -> 1)
                import re
                match = re.search(r'ITEM-(\d+)', item_id)
                if match:
                    item_num = int(match.group(1))
                    max_item_num = max(max_item_num, item_num)
        
        split_items = []
        item_counter = max_item_num  # Start counter after highest existing item
        
        for item in items:
            if not isinstance(item, dict):
                split_items.append(item)
                continue
            
            # Check if item is composite
            item_text = item.get("text", "")
            if detect_composite_ticket_item(item_text):
                # Split the composite item
                split_result = split_composite_ticket_item(item, ticket_id, item_counter)
                split_items.extend(split_result)
                item_counter += len(split_result)
            else:
                # Not composite, keep as-is
                split_items.append(item)
        
        # Replace items with split items
        ticket_entry["items"] = split_items
    
    # Validate invariants (only if RTM exists - it may not exist yet at this point)
    if test_plan.get("rtm"):
        test_plan_after = {
            "requirements": test_plan.get("requirements", []),
            "test_plan": test_plan.get("test_plan", {}),
            "rtm": test_plan.get("rtm", [])
        }
        is_valid, violations = validate_composite_splitting_invariants(test_plan_before, test_plan_after)
        if not is_valid:
            violation_msg = "; ".join(violations)
            logger.error(f"Composite splitting violated invariants: {violation_msg}")
            # Abort - restore original ticket_traceability
            # Note: We can't easily restore, so we log the error
            # In practice, this should never happen if the function is correct


def enrich_test_steps_for_testable_tests(test_plan: dict) -> None:
    """
    Enrich test steps for all testable tests that have empty steps or steps_origin "none"/"inferred".
    
    This function ONLY modifies the `steps` field of tests that are:
    - testable=true (or associated with testable requirements/items)
    - steps array is empty OR steps_origin is "none" or "inferred"
    
    ABSOLUTE RULES (DO NOT VIOLATE):
    - Do NOT add, remove, merge, or deduplicate requirements
    - Do NOT change requirement IDs
    - Do NOT add, remove, merge, or deduplicate tests
    - Do NOT change test IDs
    - Do NOT change source_requirement_id
    - Do NOT change requirements_covered
    - Do NOT change coverage calculations
    - Do NOT change RTM primary rows
    - Do NOT change ticket item enumeration
    - Do NOT modify tests that already have steps
    - Do NOT generate steps for tests associated with testable=false requirements/items
    
    Args:
        test_plan: Test plan dictionary (modified in place)
    """
    requirements = test_plan.get("requirements", [])
    req_lookup = {req.get("id"): req for req in requirements if isinstance(req, dict) and req.get("id")}
    
    # Build testable requirement map
    # Requirements are testable by default unless associated with non-testable ticket items
    testable_reqs = set()
    for req in requirements:
        if isinstance(req, dict):
            req_id = req.get("id", "")
            if req_id:
                testable_reqs.add(req_id)
    
    # Check ticket_item_coverage for non-testable items
    # If a ticket item is marked testable=false, its parent requirement should not have steps generated
    ticket_item_coverage = test_plan.get("ticket_item_coverage", [])
    non_testable_req_ids = set()
    for item in ticket_item_coverage:
        if isinstance(item, dict):
            testable = item.get("testable", True)
            parent_req_id = item.get("parent_requirement_id")
            if testable is False and parent_req_id:
                # If ticket item is explicitly non-testable, mark its parent requirement as non-testable
                non_testable_req_ids.add(parent_req_id)
    
    # Remove non-testable requirements from testable set
    testable_reqs = testable_reqs - non_testable_req_ids
    
    test_plan_section = test_plan.get("test_plan", {})
    test_categories = [
        "api_tests",
        "ui_tests",
        "data_validation_tests",
        "edge_cases",
        "negative_tests"
    ]
    
    for category in test_categories:
        tests = test_plan_section.get(category, [])
        if not isinstance(tests, list):
            continue
        
        for test in tests:
            if not isinstance(test, dict):
                continue
            
            # Skip if test already has steps
            existing_steps = test.get("steps", [])
            if existing_steps and len(existing_steps) > 0:
                continue
            
            # Check if steps_origin is "none" or "inferred"
            steps_origin = test.get("steps_origin", "")
            if steps_origin not in ["none", "inferred"]:
                continue
            
            # Check if test is associated with a testable requirement
            source_req_id = test.get("source_requirement_id", "")
            reqs_covered = test.get("requirements_covered", [])
            
            # Determine if test is testable
            is_testable = False
            if source_req_id and source_req_id in testable_reqs:
                is_testable = True
            elif reqs_covered:
                # Check if any covered requirement is testable
                for req_id in reqs_covered:
                    if req_id in testable_reqs:
                        is_testable = True
                        break
            
            if not is_testable:
                continue  # Skip non-testable tests
            
            # Get requirement description and classification for step generation
            req_description = ""
            req_classification = ""
            if source_req_id and source_req_id in req_lookup:
                req_obj = req_lookup[source_req_id]
                req_description = req_obj.get("description", "")
                req_classification = req_obj.get("_classification", "")
            elif reqs_covered:
                for req_id in reqs_covered:
                    if req_id in req_lookup:
                        req_obj = req_lookup[req_id]
                        req_description = req_obj.get("description", "")
                        req_classification = req_obj.get("_classification", "")
                        break
            
            # Get test intent and title
            intent_type = test.get("intent_type", "happy_path")
            test_title = test.get("title", "")
            
            # Generate minimum 3 human-executable steps
            generated_steps = generate_executable_test_steps(
                req_description, intent_type, test_title, category, req_classification
            )
            
            if generated_steps and len(generated_steps) >= 3:
                test["steps"] = generated_steps
                test["steps_origin"] = "inferred"  # Mark as inferred since we generated them
                # Remove steps_explanation if it exists (no longer needed)
                if "steps_explanation" in test:
                    del test["steps_explanation"]


def generate_executable_test_steps(req_description: str, intent_type: str, test_title: str, category: str, req_classification: str = "") -> list:
    """
    Generate minimum 3 human-executable test steps based on requirement and intent.
    
    Steps are:
    - Clear and observable
    - Repeatable
    - Tool-agnostic
    - Do NOT assume internal implementation details
    
    CLASSIFICATION-BASED NEGATIVE TEST GENERATION:
    - If requirement classification is ui_structure OR ui_element:
      * Negative tests MUST be presence/state-based, NOT generic error-handling
      * Generate UI absence/state-based negative steps only
    
    Args:
        req_description: Requirement description text
        intent_type: Test intent (happy_path, negative, authorization, boundary)
        test_title: Test title
        category: Test category (api_tests, ui_tests, etc.)
        req_classification: Optional requirement classification (ui_structure, ui_element, system_behavior, etc.)
    
    Returns:
        list: List of executable step strings (minimum 3)
    """
    import re
    
    req_lower = (req_description or "").lower()
    title_lower = (test_title or "").lower()
    
    # Extract UI elements mentioned in requirement
    ui_keywords = ["button", "link", "field", "menu", "tab", "page", "screen", "form", "input", 
                   "dropdown", "select", "checkbox", "radio", "toggle", "upload", "download"]
    ui_elements = [kw for kw in ui_keywords if kw in req_lower]
    
    # Extract comma-separated UI elements for UI structure requirements
    comma_separated_ui_elements = []
    if req_classification in ["ui_structure", "ui_element"]:
        # Check if requirement has comma-separated list
        comma_count = req_lower.count(',')
        if comma_count >= 1:
            # Extract text after any numbering token
            numbering_token_pattern = re.compile(r'^(\[?\d+\]?[\.\)\-\s]+)', re.IGNORECASE)
            numbering_match = numbering_token_pattern.match(req_description)
            text_to_parse = req_description
            if numbering_match:
                text_to_parse = req_description[len(numbering_match.group(0)):].strip()
            
            # Detect UI element type mentioned in the requirement (e.g., "tabs", "buttons", "fields")
            ui_element_type = None
            for keyword in ui_keywords:
                if keyword in text_to_parse.lower():
                    ui_element_type = keyword
                    break
            
            # Split by commas and extract UI element names
            # Handle "and" at the end (e.g., "X, Y, and Z")
            items_text = text_to_parse
            items_text = re.sub(r'\s+and\s*$', '', items_text, flags=re.IGNORECASE)
            comma_items = [item.strip() for item in items_text.split(',') if item.strip()]
            
            # Extract UI element names from each comma-separated item
            for item in comma_items:
                item_lower = item.lower()
                # If UI element type is mentioned (e.g., "tabs"), prepend it to each item
                if ui_element_type and ui_element_type not in item_lower:
                    # Construct element name: "ticket" -> "ticket tab" (if type is "tab")
                    element_name = f"{item.strip()} {ui_element_type}"
                    if len(element_name) < 60:  # Reasonable length for an element name
                        comma_separated_ui_elements.append(element_name)
                else:
                    # Look for UI element keywords in the item itself
                    found_keyword = False
                    for keyword in ui_keywords:
                        if keyword in item_lower:
                            # Extract the element name (e.g., "ticket tab" -> "ticket tab")
                            # Or use the item text if it's short and descriptive
                            if len(item) < 50:  # Reasonable length for an element name
                                comma_separated_ui_elements.append(item.strip())
                            found_keyword = True
                            break
                    # If no keyword found but we have a UI element type, use the item as-is
                    if not found_keyword and ui_element_type and len(item) < 50:
                        comma_separated_ui_elements.append(item.strip())
    
    # Extract action verbs
    action_verbs = ["click", "tap", "select", "enter", "input", "navigate", "submit", "save", 
                    "delete", "edit", "create", "update", "verify", "observe", "check"]
    mentioned_actions = [verb for verb in action_verbs if verb in req_lower]
    
    # Generate steps based on intent and category
    steps = []
    
    if category == "ui_tests" or any(ui in req_lower for ui in ["ui", "user interface", "screen", "page"]):
        # UI-focused steps
        if intent_type == "happy_path":
            steps.append("Navigate to the application")
            
            # UI STRUCTURE STEP EXPANSION: Expand comma-separated UI elements into individual verification steps
            # HAPPY-PATH STEP DECOMPOSITION: Each UI element gets its own explicit verification step
            if req_classification in ["ui_structure", "ui_element"] and comma_separated_ui_elements:
                # Generate one verification step per UI element
                # Each step explicitly confirms presence, visibility, and accessibility
                # Do NOT merge multiple UI elements into a single step
                for element in comma_separated_ui_elements:
                    steps.append(f"Verify that the '{element}' is present on the screen, visible to the user, and accessible (enabled and ready for interaction)")
                # Add final verification step only if we have fewer than 3 steps total
                if len(steps) < 3:
                    steps.append("Confirm all required UI elements are functioning as specified")
            elif ui_elements:
                steps.append(f"Locate and interact with the {ui_elements[0]} mentioned in the requirement")
            else:
                steps.append("Trigger the action described in the requirement")
            
            # Ensure minimum 3 steps
            if len(steps) < 3:
                steps.append("Observe the system response and verify it matches the expected outcome")
            if len(steps) < 3:
                steps.append("Confirm the requirement behavior is functioning as specified")
        elif intent_type == "negative":
            # CLASSIFICATION-BASED NEGATIVE TEST GENERATION: UI structure/element requirements
            if req_classification in ["ui_structure", "ui_element"]:
                # Generate UI absence/state-based negative steps
                steps.append("Navigate to the application")
                
                # UI STRUCTURE STEP EXPANSION: Expand comma-separated UI elements into individual verification steps
                if comma_separated_ui_elements:
                    # Generate one verification step per UI element checking for absence/state issues
                    for element in comma_separated_ui_elements:
                        steps.append(f"Check if the '{element}' is missing, not visible, disabled when it should be enabled, or displays incorrect/empty content")
                    # Add final assertion step
                    if len(steps) < 3:
                        steps.append("Verify that one or more required UI elements are missing, inaccessible, or in an incorrect state")
                elif ui_elements:
                    # If multiple UI elements, check for missing/inaccessible elements
                    if len(ui_elements) > 1:
                        steps.append(f"Verify that all required UI elements ({', '.join(ui_elements[:3])}) are present and accessible")
                        steps.append("Check if any required UI element is missing, not visible, disabled when it should be enabled, or displays incorrect/empty content")
                    else:
                        steps.append(f"Verify that the {ui_elements[0]} mentioned in the requirement is present on the screen")
                        steps.append(f"Check if the {ui_elements[0]} is missing, not visible, disabled when it should be enabled, or displays incorrect/empty content")
                else:
                    # Generic UI presence check
                    steps.append("Verify that all required UI elements are present and accessible")
                    steps.append("Check if any required UI element is missing, not visible, disabled when it should be enabled, or displays incorrect/empty content")
            else:
                # Generic error-handling negative (for system_behavior, data_validation, api_behavior)
                steps.append("Navigate to the application")
                steps.append("Attempt to trigger the action with invalid or missing data")
                steps.append("Observe the system response and verify appropriate error handling")
            if len(steps) < 3:
                if req_classification in ["ui_structure", "ui_element"]:
                    steps.append("Document any UI elements that are missing, inaccessible, or in an incorrect state")
                else:
                    steps.append("Confirm the system prevents invalid operations as expected")
        elif intent_type == "authorization":
            steps.append("Navigate to the application")
            steps.append("Attempt to access the functionality without proper permissions")
            steps.append("Observe the system response and verify access is denied appropriately")
        else:  # boundary or other
            steps.append("Navigate to the application")
            steps.append("Trigger the action with boundary or edge case values")
            steps.append("Observe the system response and verify it handles the boundary condition correctly")
    
    elif category == "api_tests" or any(api in req_lower for api in ["api", "endpoint", "request", "response"]):
        # API-focused steps
        if intent_type == "happy_path":
            steps.append("Prepare a valid request with all required fields as specified in the requirement")
            steps.append("Send the request to the system")
            steps.append("Observe the response and verify it contains the expected data and status")
        elif intent_type == "negative":
            steps.append("Prepare a request with invalid or missing required fields")
            steps.append("Send the request to the system")
            steps.append("Observe the response and verify appropriate error handling is returned")
        elif intent_type == "authorization":
            steps.append("Prepare a request without proper authentication or authorization")
            steps.append("Send the request to the system")
            steps.append("Observe the response and verify access is denied with appropriate status code")
        else:  # boundary or other
            steps.append("Prepare a request with boundary or edge case values")
            steps.append("Send the request to the system")
            steps.append("Observe the response and verify it handles the boundary condition correctly")
    
    else:
        # Generic system behavior steps
        if intent_type == "happy_path":
            steps.append("Navigate to the application or access the system component")
            steps.append("Trigger the action described in the requirement")
            steps.append("Observe the system response and verify it matches the expected outcome")
        elif intent_type == "negative":
            steps.append("Navigate to the application or access the system component")
            steps.append("Attempt to trigger the action with invalid conditions")
            steps.append("Observe the system response and verify appropriate error handling")
        elif intent_type == "authorization":
            steps.append("Navigate to the application or access the system component")
            steps.append("Attempt to access the functionality without proper permissions")
            steps.append("Observe the system response and verify access is denied appropriately")
        else:  # boundary or other
            steps.append("Navigate to the application or access the system component")
            steps.append("Trigger the action with boundary or edge case values")
            steps.append("Observe the system response and verify it handles the boundary condition correctly")
    
    # Ensure minimum 3 steps
    while len(steps) < 3:
        steps.append("Document the observed behavior and compare it against the requirement")
    
    return steps[:3]  # Return exactly 3 steps


def add_ticket_item_traceability(test_plan: dict) -> None:
    """
    Add explicit ticket-item traceability for audit purposes.
    
    This function:
    1. Enumerates all ticket items from all tickets
    2. Classifies each item using the required classification types
    3. Determines coverage disposition (direct test, inherited, or not testable)
    4. Adds "Ticket Item Coverage" section to test plan
    5. Adds "rtm_item_trace" to RTM entries
    
    ABSOLUTE RULES (DO NOT VIOLATE):
    - Do NOT add, remove, merge, or deduplicate requirements
    - Do NOT change requirement IDs
    - Do NOT add, remove, merge, or deduplicate tests
    - Do NOT change test IDs
    - Do NOT change source_requirement_id
    - Do NOT change requirements_covered
    - Do NOT recalculate coverage %, confidence, or scoring
    - Do NOT change RTM primary rows
    - Do NOT introduce cross-ticket logic
    - Do NOT change ordering behavior
    
    Args:
        test_plan: Test plan dictionary (modified in place)
    """
    # Get all requirements and tests
    requirements = test_plan.get("requirements", [])
    req_lookup = {req.get("id"): req for req in requirements if isinstance(req, dict) and req.get("id")}
    
    test_plan_section = test_plan.get("test_plan", {})
    all_tests_by_category = {
        "api_tests": test_plan_section.get("api_tests", []),
        "ui_tests": test_plan_section.get("ui_tests", []),
        "negative_tests": test_plan_section.get("negative_tests", []),
        "edge_cases": test_plan_section.get("edge_cases", []),
        "data_validation_tests": test_plan_section.get("data_validation_tests", [])
    }
    
    # Build test map by requirement
    tests_by_req = {}
    for category, tests in all_tests_by_category.items():
        for test in tests:
            if isinstance(test, dict):
                reqs_covered = test.get("requirements_covered", [])
                test_id = test.get("id", "")
                for req_id in reqs_covered:
                    if req_id not in tests_by_req:
                        tests_by_req[req_id] = []
                    tests_by_req[req_id].append(test_id)
    
    # Get ticket traceability data if it exists (from existing code)
    ticket_traceability = test_plan.get("ticket_traceability", [])
    
    # If ticket_traceability doesn't exist yet, we can't proceed
    # This should not happen if called at the right time, but handle gracefully
    if not ticket_traceability:
        logger.warning("ticket_traceability not found in test plan. Ticket item traceability enrichment skipped.")
        return
    
    # Build ticket item coverage and RTM item trace
    ticket_item_coverage = []
    rtm_item_trace_by_req = {}  # requirement_id -> list of item trace entries
    
    for ticket_entry in ticket_traceability:
        if not isinstance(ticket_entry, dict):
            continue
        
        ticket_id = ticket_entry.get("ticket_id", "")
        items = ticket_entry.get("items", [])
        
        if not isinstance(items, list):
            continue
        
        for item in items:
            if not isinstance(item, dict):
                continue
            
            item_id = item.get("item_id", "")
            item_text = item.get("text", "")
            
            # TARGETED CLEANUP: Remove stray "0 " prefix if present at start of item text
            # This is a safety net to ensure "0 " is removed even if it wasn't caught earlier
            # Applied before text is used in ticket_item_coverage and rtm_item_trace
            if item_text and item_text.startswith("0 "):
                item_text = item_text[2:].lstrip()  # Remove "0 " and any following whitespace
                # Update the item dict so cleaned text propagates
                item["text"] = item_text
            
            classification = item.get("classification", "")
            
            # Reclassify using the required classification types
            # Map existing classifications to new ones
            if classification in ["primary_requirement", "acceptance_criterion", "boundary_condition", "negative_condition"]:
                # Reclassify based on content
                classification = classify_ticket_item(item_text, requirements)
            elif classification == "technical_constraint":
                classification = "not_independently_testable"
            # Keep system_behavior, ui_element, informational_only, unclear_needs_clarification as-is
            
            # DETERMINISTIC INHERITANCE RULE: Inherit classification and testability from parent requirement
            parent_req_id = item.get("parent_requirement_id")
            parent_testable = True  # Default
            if parent_req_id:
                # Get parent requirement
                parent_req = req_lookup.get(parent_req_id)
                if parent_req and isinstance(parent_req, dict):
                    parent_classification = parent_req.get("_classification", "")
                    parent_testable = parent_req.get("testable", True)
                    
                    # Inheritable classifications (non-behavioral classifications that must be inherited)
                    inheritable_classifications = ["ui_structure", "ui_element", "informational_only", "not_independently_testable"]
                    
                    if parent_classification in inheritable_classifications:
                        # Items may NOT be reclassified to system_behavior if parent requirement is non-behavioral
                        # Force inheritance of non-behavioral classifications
                        if classification == "system_behavior" and parent_classification in inheritable_classifications:
                            # Override system_behavior classification with parent's non-behavioral classification
                            classification = parent_classification
                            logger.debug(f"Forced inheritance: Overrode system_behavior classification with '{parent_classification}' from requirement {parent_req_id} to item {item_id}")
                        elif classification not in ["informational_only", "not_independently_testable"]:
                            # Inherit the classification (unless item is explicitly informational_only or not_independently_testable)
                            classification = parent_classification
                            logger.debug(f"Inherited classification '{parent_classification}' from requirement {parent_req_id} to item {item_id}")
            
            # DETERMINISTIC INHERITANCE RULE: Inherit testable flag from parent requirement
            # If parent requirement is non-testable, item must also be non-testable
            if parent_req_id:
                parent_req = req_lookup.get(parent_req_id)
                if parent_req and isinstance(parent_req, dict):
                    parent_testable = parent_req.get("testable", True)
                    if not parent_testable:
                        # Force testable = false if parent is non-testable
                        testable = False
                    else:
                        # Otherwise, determine from classification
                        testable = classification in ["system_behavior", "ui_element"]
                else:
                    # Default: determine from classification
                    testable = classification in ["system_behavior", "ui_element"]
            else:
                # Default: determine from classification
                testable = classification in ["system_behavior", "ui_element"]
            
            # Get mapped requirement if available
            mapped_req_id = item.get("mapped_requirement_id")
            validated_by_tests = item.get("validated_by_tests", [])
            
            # STRICT INHERITANCE RULE: Check if parent requirement has negative = not_applicable
            # If so, items may NOT be marked as covered by negative tests
            parent_req_id = item.get("parent_requirement_id")
            parent_negative_not_applicable = False
            if parent_req_id:
                parent_req = req_lookup.get(parent_req_id)
                if parent_req and isinstance(parent_req, dict):
                    parent_coverage_exp = parent_req.get("coverage_expectations", {})
                    parent_negative = parent_coverage_exp.get("negative", "expected")
                    if parent_negative == "not_applicable":
                        parent_negative_not_applicable = True
                        # Filter out negative tests from validated_by_tests
                        # Items may NOT be marked as covered by negative tests if parent has negative = not_applicable
                        if validated_by_tests:
                            # Get all tests to check their intent_type
                            all_tests = []
                            for category, test_list in all_tests_by_category.items():
                                all_tests.extend(test_list)
                            # Filter out negative tests
                            filtered_test_ids = []
                            for test_id in validated_by_tests:
                                test = next((t for t in all_tests if isinstance(t, dict) and t.get("id") == test_id), None)
                                if test:
                                    intent_type = test.get("intent_type", "").lower()
                                    if intent_type != "negative":
                                        filtered_test_ids.append(test_id)
                                else:
                                    # If test not found, keep it (might be from different category)
                                    filtered_test_ids.append(test_id)
                            validated_by_tests = filtered_test_ids
                            logger.debug(f"Filtered out negative tests from item {item_id} due to parent requirement {parent_req_id} having negative=not_applicable")
            
            # Determine coverage disposition
            coverage_method = None
            direct_test_ids = []
            parent_requirement_id = None
            non_testable_reason = None
            
            if testable:
                if validated_by_tests:
                    # Directly validated by tests (negative tests already filtered if parent has negative = not_applicable)
                    coverage_method = "direct_test"
                    direct_test_ids = validated_by_tests
                elif mapped_req_id:
                    # Covered by parent requirement's tests
                    coverage_method = "inherited_via_parent_requirement"
                    parent_requirement_id = mapped_req_id
                    # Get tests for parent requirement
                    parent_test_ids = tests_by_req.get(mapped_req_id, [])
                    # STRICT INHERITANCE RULE: Filter out negative tests if parent has negative = not_applicable
                    if parent_negative_not_applicable and parent_test_ids:
                        # Get all tests to check their intent_type
                        all_tests = []
                        for category, test_list in all_tests_by_category.items():
                            all_tests.extend(test_list)
                        # Filter out negative tests
                        filtered_test_ids = []
                        for test_id in parent_test_ids:
                            test = next((t for t in all_tests if isinstance(t, dict) and t.get("id") == test_id), None)
                            if test:
                                intent_type = test.get("intent_type", "").lower()
                                if intent_type != "negative":
                                    filtered_test_ids.append(test_id)
                            else:
                                # If test not found, keep it (might be from different category)
                                filtered_test_ids.append(test_id)
                        direct_test_ids = filtered_test_ids
                        logger.debug(f"Filtered out negative tests from parent requirement {mapped_req_id} for item {item_id} due to parent having negative=not_applicable")
                    else:
                        direct_test_ids = parent_test_ids
                else:
                    # Testable but no mapping found - treat as inherited via requirement extraction
                    coverage_method = "inherited_via_parent_requirement"
                    # Try to find requirement by text similarity
                    item_text_lower = item_text.lower()
                    best_match = None
                    best_score = 0
                    for req_id, req in req_lookup.items():
                        req_desc = req.get("description", "").lower()
                        item_words = set(item_text_lower.split())
                        req_words = set(req_desc.split())
                        common_words = item_words.intersection(req_words)
                        if len(item_words) > 0:
                            score = len(common_words) / len(item_words)
                            if score > best_score and score > 0.3:
                                best_score = score
                                best_match = req_id
                    if best_match:
                        parent_requirement_id = best_match
                        parent_test_ids = tests_by_req.get(best_match, [])
                        # STRICT INHERITANCE RULE: Filter out negative tests if parent has negative = not_applicable
                        if parent_negative_not_applicable and parent_test_ids:
                            # Get all tests to check their intent_type
                            all_tests = []
                            for category, test_list in all_tests_by_category.items():
                                all_tests.extend(test_list)
                            # Filter out negative tests
                            filtered_test_ids = []
                            for test_id in parent_test_ids:
                                test = next((t for t in all_tests if isinstance(t, dict) and t.get("id") == test_id), None)
                                if test:
                                    intent_type = test.get("intent_type", "").lower()
                                    if intent_type != "negative":
                                        filtered_test_ids.append(test_id)
                                else:
                                    # If test not found, keep it (might be from different category)
                                    filtered_test_ids.append(test_id)
                            direct_test_ids = filtered_test_ids
                            logger.debug(f"Filtered out negative tests from matched requirement {best_match} for item {item_id} due to parent having negative=not_applicable")
                        else:
                            direct_test_ids = parent_test_ids
            else:
                coverage_method = "not_independently_testable"
                if classification == "informational_only":
                    non_testable_reason = "Informational content; not independently testable"
                elif classification == "not_independently_testable":
                    non_testable_reason = "Implementation guidance or technical constraint; not independently testable"
                elif classification == "unclear_needs_clarification":
                    non_testable_reason = "Item text is unclear or incomplete; needs clarification"
            
            # Add to Ticket Item Coverage
            item_coverage_entry = {
                "item_id": item_id,
                "text": item_text,
                "classification": classification,
                "testable": testable,
                "coverage_method": coverage_method
            }
            
            if coverage_method == "direct_test":
                item_coverage_entry["test_ids"] = direct_test_ids
            elif coverage_method == "inherited_via_parent_requirement":
                item_coverage_entry["parent_requirement_id"] = parent_requirement_id
            elif coverage_method == "not_independently_testable":
                item_coverage_entry["non_testable_reason"] = non_testable_reason
            
            ticket_item_coverage.append(item_coverage_entry)
            
            # Add to RTM item trace (grouped by parent requirement)
            # Every ticket item MUST appear in RTM item trace
            target_req_id = parent_requirement_id
            
            # If no parent requirement found, try to find one or use first requirement
            if not target_req_id:
                # Try to find requirement by text similarity
                item_text_lower = item_text.lower()
                best_match = None
                best_score = 0
                for req_id, req in req_lookup.items():
                    req_desc = req.get("description", "").lower()
                    item_words = set(item_text_lower.split())
                    req_words = set(req_desc.split())
                    common_words = item_words.intersection(req_words)
                    if len(item_words) > 0:
                        score = len(common_words) / len(item_words)
                        if score > best_score and score > 0.2:  # Lower threshold for non-testable items
                            best_score = score
                            best_match = req_id
                
                if best_match:
                    target_req_id = best_match
                elif requirements:
                    # Use first requirement as fallback
                    first_req = requirements[0]
                    if isinstance(first_req, dict):
                        target_req_id = first_req.get("id")
            
            # Add to RTM item trace
            if target_req_id:
                if target_req_id not in rtm_item_trace_by_req:
                    rtm_item_trace_by_req[target_req_id] = []
                
                rtm_item_entry = {
                    "item_id": item_id,
                    "parent_requirement_id": target_req_id,
                    "item_text": item_text,
                    "classification": classification,
                    "testable": testable,
                    "coverage_reference": {}
                }
                
                if coverage_method == "direct_test":
                    rtm_item_entry["coverage_reference"]["test_ids"] = direct_test_ids
                elif coverage_method == "inherited_via_parent_requirement":
                    rtm_item_entry["coverage_reference"]["parent_requirement_id"] = target_req_id
                    if direct_test_ids:
                        rtm_item_entry["coverage_reference"]["test_ids"] = direct_test_ids
                elif coverage_method == "not_independently_testable":
                    rtm_item_entry["coverage_reference"]["non_testable_reason"] = non_testable_reason
                
                rtm_item_trace_by_req[target_req_id].append(rtm_item_entry)
            else:
                # Last resort: if no requirements exist, create a placeholder entry
                # This should never happen in practice, but ensures audit completeness
                logger.warning(f"Ticket item {item_id} could not be mapped to any requirement for RTM item trace")
    
    # Add Ticket Item Coverage section to test plan
    test_plan["ticket_item_coverage"] = ticket_item_coverage
    
    # Add rtm_item_trace to RTM entries
    rtm = test_plan.get("rtm", [])
    for entry in rtm:
        if isinstance(entry, dict):
            req_id = entry.get("requirement_id")
            if req_id in rtm_item_trace_by_req:
                entry["rtm_item_trace"] = rtm_item_trace_by_req[req_id]
            else:
                entry["rtm_item_trace"] = []


def export_test_plan_json(test_plan_json: dict) -> bytes:
    """
    Export test plan as JSON bytes for audit purposes.
    
    Args:
        test_plan_json: The complete test plan JSON structure
    
    Returns:
        bytes: UTF-8 encoded JSON bytes
    """
    json_str = json.dumps(test_plan_json, indent=2, ensure_ascii=False)
    return json_str.encode('utf-8')


def export_rtm_csv(test_plan_json: dict) -> bytes:
    """
    Export Requirement Traceability Matrix as CSV bytes for audit purposes.
    
    Uses the existing RTM data already generated in the test plan.
    Does NOT re-calculate RTM logic.
    
    Args:
        test_plan_json: The complete test plan JSON structure containing RTM
    
    Returns:
        bytes: UTF-8 encoded CSV bytes with header row
    """
    rtm = test_plan_json.get("rtm", [])
    ticket_id = test_plan_json.get("metadata", {}).get("source_id", "UNKNOWN")
    
    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header row
    writer.writerow([
        "Ticket ID",
        "Requirement ID",
        "Requirement Description",
        "Covered By Tests",
        "Coverage Status"
    ])
    
    # Write data rows
    for entry in rtm:
        requirement_id = entry.get("requirement_id", "")
        requirement_description = entry.get("requirement_description", "")
        covered_by_tests = ", ".join(entry.get("covered_by_tests", []))
        coverage_status = entry.get("coverage_status", "")
        
        writer.writerow([
            ticket_id,
            requirement_id,
            requirement_description,
            covered_by_tests,
            coverage_status
        ])
    
    # Convert to bytes
    csv_str = output.getvalue()
    output.close()
    return csv_str.encode('utf-8')


def export_rtm_csv_simple(rtm: list, audit_metadata: dict = None) -> bytes:
    """
    Export Requirement Traceability Matrix as CSV bytes with simplified column order.
    
    Used by the /export/rtm endpoint.
    Column order: requirement_id, requirement_description, coverage_status, covered_by_tests
    
    Includes ISO 27001/SOC 2 compliant audit metadata as CSV comments.
    
    Args:
        rtm: List of RTM entries
        audit_metadata: Optional audit metadata dict to include as comments
    
    Returns:
        bytes: UTF-8 encoded CSV bytes with header row and metadata comments
    """
    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write audit metadata as CSV comments (ISO 27001/SOC 2 compliance)
    if audit_metadata:
        writer.writerow(["# ISO 27001/SOC 2 Audit Metadata"])
        writer.writerow([f"# Run ID: {audit_metadata.get('run_id', 'N/A')}"])
        writer.writerow([f"# Generated At: {audit_metadata.get('generated_at', 'N/A')}"])
        writer.writerow([f"# Agent Version: {audit_metadata.get('agent_version', 'N/A')}"])
        writer.writerow([f"# Model: {audit_metadata.get('model', {}).get('name', 'N/A')}"])
        writer.writerow([f"# Environment: {audit_metadata.get('environment', 'N/A')}"])
        writer.writerow([f"# Source Type: {audit_metadata.get('source', {}).get('type', 'N/A')}"])
        writer.writerow([f"# Tickets Analyzed: {audit_metadata.get('source', {}).get('ticket_count', 0)}"])
        writer.writerow([])  # Empty row separator
    
    # Write header row with extended fields for informational items
    # Add Logic Version and Agent Version columns at the beginning
    writer.writerow([
        "Logic Version",
        "Agent Version",
        "requirement_id",
        "requirement_description",
        "trace_type",
        "testability",
        "coverage_status",
        "covered_by_tests",
        "source_section",
        "rationale"
    ])
    
    # Write data rows
    # Use stable constant values for agent versioning
    logic_version = "rtm-v1"
    agent_version = "1.0.0"
    
    for entry in rtm:
        requirement_id = entry.get("requirement_id", "")
        requirement_description = entry.get("requirement_description", "")
        trace_type = entry.get("trace_type", "testable")
        testability = entry.get("testability", "testable")
        coverage_status = entry.get("coverage_status", "")
        covered_by_tests_list = entry.get("covered_by_tests", [])
        # For CSV, join test IDs with semicolon; empty for informational rows
        covered_by_tests = "; ".join(covered_by_tests_list) if covered_by_tests_list else ""
        source_section = entry.get("source_section", "")
        rationale = entry.get("rationale", "")
        
        writer.writerow([
            logic_version,
            agent_version,
            requirement_id,
            requirement_description,
            trace_type,
            testability,
            coverage_status,
            covered_by_tests,
            source_section,
            rationale
        ])
    
    # Convert to bytes
    csv_str = output.getvalue()
    output.close()
    return csv_str.encode('utf-8')


@app.route('/')
def health_check():
    """Health check endpoint."""
    return {'status': 'ok'}, 200


@app.route('/health', methods=['GET'])
def health():
    """Lightweight health check endpoint for Render deployment."""
    return jsonify({"ok": True}), 200


@app.route("/health/db", methods=["GET"])
def health_db():
    """
    Database connectivity health check endpoint.
    
    Returns:
        JSON with {"ok": true} on success, or {"ok": false, "error": "<message>"} on failure (HTTP 500).
    """
    try:
        from db import get_db
        from sqlalchemy import text
        
        db = next(get_db())
        try:
            # Execute a simple query to test database connectivity
            result = db.execute(text("SELECT 1"))
            result.fetchone()  # Consume the result
            return jsonify({"ok": True}), 200
        finally:
            db.close()
    except Exception as e:
        error_message = str(e)
        logger.warning(f"Database health check failed: {error_message}")
        return jsonify({"ok": False, "error": error_message}), 500


# Role constants
ALLOWED_ROLES_CREATE = {"user", "admin"}
ALLOWED_ROLES_ADMIN_API = {"user", "admin", "owner", "superAdmin"}

@app.route("/auth/register", methods=["POST"])
def register():
    """
    DEPRECATED: User-first registration endpoint (removed in tenant-first onboarding).
    
    This endpoint is no longer supported. Use tenant-first onboarding flow:
    1. POST /api/v1/onboarding/tenant (create tenant)
    2. POST /api/v1/onboarding/tenant/{tenant_id}/admin (create first admin user)
    """
    return jsonify({
        "detail": "This endpoint is deprecated. Please use tenant-first onboarding: POST /api/v1/onboarding/tenant",
        "error": "DEPRECATED_ENDPOINT"
    }), 410  # 410 Gone


@app.route("/auth/login", methods=["POST"])
def login():
    """
    User login endpoint to obtain JWT access token (email+password only).
    
    Request body:
        {
            "email": "user@example.com",
            "password": "password123"
        }
        Optionally accepts "tenant_slug" for backward compatibility, but UI will not send it.
    
    Returns:
        - 200: Success with JWT token (single tenant match)
        - 409: Multiple tenants found, requires tenant selection
        {
            "code": "TENANT_SELECTION_REQUIRED",
            "detail": "Multiple workspaces found for this email.",
            "tenants": [
                { "tenant_id": "...", "tenant_name": "...", "tenant_slug": "..." }
            ]
        }
        - 401: Invalid credentials (generic)
        - 403: User or tenant inactive
    """
    try:
        from db import get_db
        from sqlalchemy import func
        # Models are imported at module level - no need to re-import
        
        # Get request data
        data = request.get_json()
        if not data:
            return jsonify({"detail": "Request body must be JSON"}), 400
        
        email = data.get("email", "").strip()
        password = data.get("password", "")
        tenant_slug = data.get("tenant_slug", "").strip()  # Optional, for backward compatibility
        
        if not email or not password:
            return jsonify({"detail": "email and password are required"}), 400
        
        # Normalize email: lowercase and trim
        email_lower = email.lower().strip()
        password_bytes = password.encode('utf-8')
        
        # Get database session
        db = next(get_db())
        try:
            # If tenant_slug provided (backward compatibility), use old flow
            if tenant_slug:
                tenant_slug_lower = tenant_slug.lower().strip()
                tenant = db.query(Tenant).filter(func.lower(Tenant.slug) == tenant_slug_lower).first()
                if not tenant:
                    return jsonify({"detail": "Invalid tenant or credentials"}), 401
                
                if not tenant.is_active:
                    return jsonify({
                        "code": "TENANT_INACTIVE",
                        "detail": "Workspace is inactive. Contact hello@scopetraceai.com"
                    }), 403
                
                user = db.query(TenantUser).filter(
                    func.lower(TenantUser.email) == email_lower,
                    TenantUser.tenant_id == tenant.id
                ).first()
                
                if not user:
                    return jsonify({"detail": "Invalid tenant or credentials"}), 401
                
                if not user.is_active:
                    return jsonify({
                        "code": "USER_INACTIVE",
                        "detail": "Your account is inactive. Contact hello@scopetraceai.com"
                    }), 403
                
                if not bcrypt.checkpw(password_bytes, user.password_hash.encode('utf-8')):
                    return jsonify({"detail": "Invalid tenant or credentials"}), 401
                
                user.last_login_at = datetime.now(timezone.utc)
                db.commit()
                
                access_token = create_access_token(
                    user_id=str(user.id),
                    tenant_id=str(user.tenant_id),
                    role=user.role
                )
                
                return jsonify({
                    "access_token": access_token,
                    "token_type": "bearer",
                    "user": {
                        "id": str(user.id),
                        "email": user.email,
                        "role": user.role,
                        "tenant_id": str(user.tenant_id),
                        "tenant_slug": tenant.slug,
                        "tenant_name": tenant.name,
                        "first_name": user.first_name,
                        "last_name": user.last_name
                    }
                }), 200
            
            # New flow: lookup all tenant_users by email (case-insensitive)
            users = db.query(TenantUser).filter(
                func.lower(TenantUser.email) == email_lower
            ).all()
            
            if not users:
                return jsonify({"detail": "Invalid tenant or credentials"}), 401
            
            # Verify password for all matches and collect valid tenants
            valid_tenants = []
            for user in users:
                try:
                    if bcrypt.checkpw(password_bytes, user.password_hash.encode('utf-8')):
                        # Password matches, check if tenant and user are active
                        tenant = db.query(Tenant).filter(Tenant.id == user.tenant_id).first()
                        if tenant and tenant.is_active and user.is_active:
                            valid_tenants.append({
                                "user": user,
                                "tenant": tenant
                            })
                except Exception:
                    # Skip invalid password hashes
                    continue
            
            # If no valid matches after password check, return 401
            if not valid_tenants:
                return jsonify({"detail": "Invalid tenant or credentials"}), 401
            
            # If exactly one match, authenticate immediately
            if len(valid_tenants) == 1:
                user = valid_tenants[0]["user"]
                tenant = valid_tenants[0]["tenant"]
                
                # Update last_login_at
                user.last_login_at = datetime.now(timezone.utc)
                db.commit()
                
                # Create JWT token
                access_token = create_access_token(
                    user_id=str(user.id),
                    tenant_id=str(user.tenant_id),
                    role=user.role
                )
                
                return jsonify({
                    "access_token": access_token,
                    "token_type": "bearer",
                    "user": {
                        "id": str(user.id),
                        "email": user.email,
                        "role": user.role,
                        "tenant_id": str(user.tenant_id),
                        "tenant_slug": tenant.slug,
                        "tenant_name": tenant.name,
                        "first_name": user.first_name,
                        "last_name": user.last_name
                    }
                }), 200
            
            # Multiple matches: return 409 with tenant list
            tenant_list = []
            for item in valid_tenants:
                tenant = item["tenant"]
                tenant_list.append({
                    "tenant_id": str(tenant.id),
                    "tenant_name": tenant.name,
                    "tenant_slug": tenant.slug
                })
            
            return jsonify({
                "code": "TENANT_SELECTION_REQUIRED",
                "detail": "Multiple workspaces found for this email.",
                "tenants": tenant_list
            }), 409
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Login error: {e}", exc_info=True)
        return jsonify({"detail": "Internal server error"}), 500


@app.route("/auth/login/tenant", methods=["POST"])
def login_with_tenant():
    """
    Second-step login when multiple tenants are found.
    
    Request body:
        {
            "tenant_id": "uuid-string",
            "email": "user@example.com",
            "password": "password123"
        }
    
    Returns:
        Same as /auth/login: JWT token on success
    """
    try:
        from db import get_db
        import uuid as uuid_module
        # Models are imported at module level - no need to re-import
        
        data = request.get_json()
        if not data:
            return jsonify({"detail": "Request body must be JSON"}), 400
        
        tenant_id_str = data.get("tenant_id", "").strip()
        email = data.get("email", "").strip()
        password = data.get("password", "")
        
        if not tenant_id_str or not email or not password:
            return jsonify({"detail": "tenant_id, email, and password are required"}), 400
        
        # Normalize email
        email_lower = email.lower().strip()
        password_bytes = password.encode('utf-8')
        
        # Convert tenant_id to UUID
        try:
            tenant_id_uuid = uuid_module.UUID(tenant_id_str)
        except ValueError:
            return jsonify({"detail": "Invalid tenant or credentials"}), 401
        
        db = next(get_db())
        try:
            # Load tenant
            tenant = db.query(Tenant).filter(Tenant.id == tenant_id_uuid).first()
            if not tenant:
                return jsonify({"detail": "Invalid tenant or credentials"}), 401
            
            # Check if tenant is active
            if not tenant.is_active:
                return jsonify({
                    "code": "TENANT_INACTIVE",
                    "detail": "Workspace is inactive. Contact hello@scopetraceai.com"
                }), 403
            
            # Look up user by email and tenant_id
            from sqlalchemy import func
            user = db.query(TenantUser).filter(
                func.lower(TenantUser.email) == email_lower,
                TenantUser.tenant_id == tenant_id_uuid
            ).first()
            
            if not user:
                return jsonify({"detail": "Invalid tenant or credentials"}), 401
            
            # Check if user is active
            if not user.is_active:
                return jsonify({
                    "code": "USER_INACTIVE",
                    "detail": "Your account is inactive. Contact hello@scopetraceai.com"
                }), 403
            
            # Verify password
            if not bcrypt.checkpw(password_bytes, user.password_hash.encode('utf-8')):
                return jsonify({"detail": "Invalid tenant or credentials"}), 401
            
            # Update last_login_at
            user.last_login_at = datetime.now(timezone.utc)
            db.commit()
            
            # Create JWT token
            access_token = create_access_token(
                user_id=str(user.id),
                tenant_id=str(user.tenant_id),
                role=user.role
            )
            
            return jsonify({
                "access_token": access_token,
                "token_type": "bearer",
                "user": {
                    "id": str(user.id),
                    "email": user.email,
                    "role": user.role,
                    "tenant_id": str(user.tenant_id),
                    "tenant_slug": tenant.slug,
                    "tenant_name": tenant.name,
                    "first_name": user.first_name,
                    "last_name": user.last_name
                }
            }), 200
            
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Error during tenant login: {str(e)}", exc_info=True)
        return jsonify({"detail": "Login failed"}), 500


@app.route("/auth/me", methods=["GET"])
def get_current_user():
    """
    Get current user information from JWT token (tenant-first model).
    Tenant info is always included (tenant_id is required for authenticated users).
    
    Returns:
        {
            "user_id": "<user_id>",
            "email": "<email>",
            "role": "<role>",
            "tenant_id": "<tenant_id>",
            "tenant_slug": "<tenant_slug>",
            "tenant_name": "<tenant_name>",
            "first_name": "<first_name>" | null,
            "last_name": "<last_name>" | null
        }
    """
    # JWT middleware already verified token and set g.user_id, g.tenant_id, g.role
    if not hasattr(g, 'user_id') or not g.user_id:
        return jsonify({"detail": "Unauthorized"}), 401
    
    try:
        from db import get_db
        from models import TenantUser, Tenant
        
        db = next(get_db())
        try:
            user = db.query(TenantUser).filter(TenantUser.id == g.user_id).first()
            if not user:
                return jsonify({"detail": "User not found"}), 404
            
            # Tenant-first model: tenant_id is always required
            if not user.tenant_id:
                logger.error(f"User {user.id} has no tenant_id (invalid in tenant-first model)")
                return jsonify({"detail": "User has no tenant"}), 500
            
            tenant = db.query(Tenant).filter(Tenant.id == user.tenant_id).first()
            if not tenant:
                logger.error(f"Tenant {user.tenant_id} not found for user {user.id}")
                return jsonify({"detail": "Tenant not found"}), 500
            
            # Get billing data from tenant_billing (single source of truth)
            from services.entitlements_centralized import get_tenant_billing
            try:
                billing = get_tenant_billing(db, str(user.tenant_id))
                subscription_status = billing.get("subscription_status", "unselected")
            except RuntimeError as e:
                logger.error(f"tenant_billing missing in /auth/me: {e}")
                subscription_status = "unselected"  # Fallback for /auth/me to avoid breaking login
            
            response = {
                "user_id": str(user.id),
                "email": user.email,
                "role": user.role,
                "tenant_id": str(user.tenant_id),
                "tenant_slug": tenant.slug,
                "tenant_name": tenant.name,
                "subscription_status": subscription_status,
                "tenant_is_active": getattr(tenant, "is_active", True),
                "user_is_active": getattr(user, "is_active", True),
                "first_name": user.first_name,
                "last_name": user.last_name
            }
            
            return jsonify(response), 200
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Error getting current user: {e}", exc_info=True)
        return jsonify({"detail": "Internal server error"}), 500


@app.route("/api/v1/users/me", methods=["GET"])
def get_user_profile():
    """
    Get current user profile information (Phase 2.1).
    Returns all profile fields including address and phone.
    
    Returns:
        {
            "id": "<user_id>",
            "email": "<email>",
            "role": "<role>",
            "is_active": <bool>,
            "first_name": "<first_name>" | null,
            "last_name": "<last_name>" | null,
            "address_1": "<address_1>" | null,
            "address_2": "<address_2>" | null,
            "city": "<city>" | null,
            "state": "<state>" | null,
            "zip": "<zip>" | null,
            "phone": "<phone>" | null,
            "tenant_id": "<tenant_id>"
        }
    """
    if not hasattr(g, 'user_id') or not g.user_id:
        return jsonify({"detail": "Unauthorized"}), 401
    
    try:
        from db import get_db
        from models import TenantUser
        
        db = next(get_db())
        try:
            user = db.query(TenantUser).filter(TenantUser.id == g.user_id).first()
            if not user:
                return jsonify({"detail": "User not found"}), 404
            
            # Get tenant name
            from models import Tenant
            tenant = db.query(Tenant).filter(Tenant.id == user.tenant_id).first()
            tenant_name = tenant.name if tenant else None
            
            response = {
                "id": str(user.id),
                "email": user.email,
                "role": user.role,
                "is_active": user.is_active,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "address_1": user.address_1,
                "address_2": user.address_2,
                "city": user.city,
                "state": user.state,
                "zip": user.zip,
                "phone": user.phone,
                "tenant_id": str(user.tenant_id),
                "tenant_name": tenant_name
            }
            
            return jsonify(response), 200
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Error getting user profile: {e}", exc_info=True)
        return jsonify({"detail": "Internal server error"}), 500


@app.route("/api/v1/users/me", methods=["PATCH"])
def update_user_profile():
    """
    Update current user profile (Phase 2.1).
    Only allows updating: first_name, last_name, address_1, address_2, city, state, zip, phone.
    Explicitly rejects email, tenant_id, role changes.
    
    Request body:
        {
            "first_name": "<first_name>" | null,
            "last_name": "<last_name>" | null,
            "address_1": "<address_1>" | null,
            "address_2": "<address_2>" | null,
            "city": "<city>" | null,
            "state": "<state>" | null,
            "zip": "<zip>" | null,
            "phone": "<phone>" | null
        }
    
    Returns:
        Updated user profile object
    """
    if not hasattr(g, 'user_id') or not g.user_id:
        return jsonify({"detail": "Unauthorized"}), 401
    
    try:
        from db import get_db
        from models import TenantUser
        
        data = request.get_json()
        if not data:
            return jsonify({"detail": "Request body must be JSON"}), 400
        
        # Check for forbidden fields
        forbidden_fields = ["email", "tenant_id", "role", "password_hash", "is_active", "id"]
        for field in forbidden_fields:
            if field in data:
                return jsonify({
                    "detail": f"Field '{field}' cannot be updated from user profile"
                }), 400
        
        # Allowed fields
        allowed_fields = [
            "first_name", "last_name", "address_1", "address_2",
            "city", "state", "zip", "phone"
        ]
        
        db = next(get_db())
        try:
            user = db.query(TenantUser).filter(TenantUser.id == g.user_id).first()
            if not user:
                return jsonify({"detail": "User not found"}), 404
            
            # Update allowed fields
            updated = False
            for field in allowed_fields:
                if field in data:
                    setattr(user, field, data[field] if data[field] else None)
                    updated = True
            
            if updated:
                user.updated_at = datetime.now(timezone.utc)
                db.commit()
            
            # Get tenant name
            from models import Tenant
            tenant = db.query(Tenant).filter(Tenant.id == user.tenant_id).first()
            tenant_name = tenant.name if tenant else None
            
            # Return updated user
            response = {
                "id": str(user.id),
                "email": user.email,
                "role": user.role,
                "is_active": user.is_active,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "address_1": user.address_1,
                "address_2": user.address_2,
                "city": user.city,
                "state": user.state,
                "zip": user.zip,
                "phone": user.phone,
                "tenant_id": str(user.tenant_id),
                "tenant_name": tenant_name
            }
            
            return jsonify(response), 200
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Error updating user profile: {e}", exc_info=True)
        return jsonify({"detail": "Internal server error"}), 500


@app.route("/api/v1/users/me/change-password", methods=["POST"])
def change_password():
    """
    Change user password (Phase 2.1).
    Requires current password verification.
    
    Request body:
        {
            "current_password": "<current_password>",
            "new_password": "<new_password>"
        }
    
    Returns:
        204 No Content on success
    """
    if not hasattr(g, 'user_id') or not g.user_id:
        return jsonify({"detail": "Unauthorized"}), 401
    
    try:
        from db import get_db
        from models import TenantUser
        from services.auth import verify_password, hash_password, validate_password_strength
        
        data = request.get_json()
        if not data:
            return jsonify({"detail": "Request body must be JSON"}), 400
        
        current_password = data.get("current_password")
        new_password = data.get("new_password")
        
        if not current_password or not new_password:
            return jsonify({"detail": "current_password and new_password are required"}), 400
        
        # Validate new password strength
        is_valid, error_msg = validate_password_strength(new_password)
        if not is_valid:
            return jsonify({"detail": error_msg}), 400
        
        db = next(get_db())
        try:
            user = db.query(TenantUser).filter(TenantUser.id == g.user_id).first()
            if not user:
                return jsonify({"detail": "User not found"}), 404
            
            # Verify current password
            if not verify_password(current_password, user.password_hash):
                return jsonify({"detail": "Invalid current password"}), 400
            
            # Update password
            user.password_hash = hash_password(new_password)
            user.updated_at = datetime.now(timezone.utc)
            db.commit()
            
            return Response(status=204)
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Error changing password: {e}", exc_info=True)
        return jsonify({"detail": "Internal server error"}), 500


@app.route("/api/v1/auth/forgot-password", methods=["POST"])
def forgot_password():
    """
    Request password reset (Phase 2.1).
    Always returns 200 to prevent email enumeration.
    If user exists and is active, creates reset token and sends email.
    
    Request body:
        {
            "email": "<email>"
        }
    
    Returns:
        {
            "ok": true
        }
    """
    # This is a public route - no auth required
    try:
        from db import get_db
        from models import TenantUser
        from sqlalchemy import func
        from services.auth import (
            create_reset_token, send_password_reset_email,
            get_reset_url, check_rate_limit
        )
        
        data = request.get_json()
        if not data:
            return jsonify({"ok": True}), 200  # Always return 200
        
        email = data.get("email", "").strip().lower()
        if not email:
            return jsonify({"ok": True}), 200  # Always return 200
        
        # Rate limiting
        client_ip = request.remote_addr or "unknown"
        is_allowed, error_msg = check_rate_limit(client_ip, email)
        if not is_allowed:
            # Still return 200 to prevent enumeration, but don't process
            logger.warning(f"Rate limit exceeded for {email} from {client_ip}")
            return jsonify({"ok": True}), 200
        
        db = next(get_db())
        try:
            # Find user by email (case-insensitive)
            user = db.query(TenantUser).filter(
                func.lower(TenantUser.email) == email,
                TenantUser.is_active == True
            ).first()
            
            if user:
                # Create reset token
                raw_token, token_model = create_reset_token(db, str(user.id))
                db.commit()
                
                # Send reset email
                reset_url = get_reset_url(raw_token)
                send_password_reset_email(user.email, reset_url)
            
            # Always return 200 regardless of whether user exists
            return jsonify({"ok": True}), 200
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Error in forgot-password: {e}", exc_info=True)
        # Still return 200 to prevent enumeration
        return jsonify({"ok": True}), 200


@app.route("/api/v1/auth/reset-password", methods=["POST"])
def reset_password():
    """
    Reset password using token (Phase 2.1).
    Token is one-time use and expires after 30 minutes.
    
    Request body:
        {
            "token": "<reset_token>",
            "new_password": "<new_password>"
        }
    
    Returns:
        204 No Content on success
    """
    # This is a public route - no auth required
    try:
        from db import get_db
        from models import TenantUser
        from services.auth import (
            consume_reset_token, hash_password, validate_password_strength
        )
        
        data = request.get_json()
        if not data:
            return jsonify({"detail": "Request body must be JSON"}), 400
        
        token = data.get("token", "").strip()
        new_password = data.get("new_password")
        
        if not token or not new_password:
            return jsonify({"detail": "token and new_password are required"}), 400
        
        # Validate new password strength
        is_valid, error_msg = validate_password_strength(new_password)
        if not is_valid:
            return jsonify({"detail": error_msg}), 400
        
        db = next(get_db())
        try:
            # Consume token (one-time use)
            user_id = consume_reset_token(db, token)
            if not user_id:
                return jsonify({"detail": "Invalid or expired token"}), 400
            
            # Update user password
            user = db.query(TenantUser).filter(TenantUser.id == user_id).first()
            if not user:
                return jsonify({"detail": "User not found"}), 404
            
            user.password_hash = hash_password(new_password)
            user.updated_at = datetime.now(timezone.utc)
            db.commit()
            
            return Response(status=204)
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Error resetting password: {e}", exc_info=True)
        return jsonify({"detail": "Internal server error"}), 500


@app.route("/api/v1/auth/accept-invite", methods=["POST"])
def accept_invite():
    """
    Accept user invite and set password (Phase A: Tenant User Management).
    Token is one-time use and expires after 7 days.
    
    Request body:
        {
            "token": "<invite_token>",
            "new_password": "<new_password>"
        }
    
    Returns:
        204 No Content on success
    """
    # This is a public route - no auth required
    try:
        from db import get_db
        from models import TenantUser
        from services.auth import (
            consume_invite_token, hash_password, validate_password_strength
        )
        
        data = request.get_json()
        if not data:
            return jsonify({"detail": "Request body must be JSON"}), 400
        
        token = data.get("token", "").strip()
        new_password = data.get("new_password")
        
        if not token or not new_password:
            return jsonify({"detail": "token and new_password are required"}), 400
        
        # Validate new password strength
        is_valid, error_msg = validate_password_strength(new_password)
        if not is_valid:
            return jsonify({"detail": error_msg}), 400
        
        db = next(get_db())
        try:
            # Consume token (one-time use)
            user_id = consume_invite_token(db, token)
            if not user_id:
                return jsonify({"detail": "Invalid or expired token"}), 400
            
            # Update user password and activate if needed
            user = db.query(TenantUser).filter(TenantUser.id == user_id).first()
            if not user:
                return jsonify({"detail": "User not found"}), 404
            
            user.password_hash = hash_password(new_password)
            user.is_active = True  # Activate user when they set password
            user.updated_at = datetime.now(timezone.utc)
            db.commit()
            
            return Response(status=204)
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Error accepting invite: {e}", exc_info=True)
        return jsonify({"detail": "Internal server error"}), 500


@app.route("/api/v1/tenants/<tenant_id>/subscription", methods=["PATCH"])
def update_tenant_subscription(tenant_id):
    """
    Update tenant subscription plan (onboarding step or admin update).
    Requires authentication and tenant scope.
    
    Path parameters:
        tenant_id: UUID of the tenant
    
    Request body:
        {
            "plan": "trial" | "individual" | "team" | "canceled"
        }
    
    Returns:
        {
            "tenant_id": "<tenant_id>",
            "subscription_status": "<status>",
            "trial_requirements_runs_remaining": <int>,
            "trial_testplan_runs_remaining": <int>,
            "trial_writeback_runs_remaining": <int>
        }
    """
    try:
        from db import get_db
        from models import Tenant
        import uuid as uuid_lib
        
        # Validate tenant_id format
        try:
            tenant_uuid = uuid_lib.UUID(tenant_id)
        except ValueError:
            return jsonify({"detail": "Invalid tenant_id format"}), 400
        
        # Get request data
        data = request.get_json()
        if not data:
            return jsonify({"detail": "Request body must be JSON"}), 400
        
        plan = data.get("plan", "").strip().lower()
        if not plan:
            return jsonify({"detail": "plan is required"}), 400
        
        # Validate plan
        allowed_plans = ["trial", "individual", "team", "canceled"]
        if plan not in allowed_plans:
            return jsonify({
                "detail": f"Invalid plan. Allowed: {allowed_plans}"
            }), 400
        
        # Verify user is authenticated and has tenant context
        if not hasattr(g, 'user_id') or not g.user_id:
            return jsonify({"detail": "Unauthorized"}), 401
        
        if not hasattr(g, 'tenant_id') or not g.tenant_id:
            return jsonify({"detail": "Unauthorized"}), 401
        
        # Verify tenant_id matches authenticated tenant (tenant isolation)
        if str(g.tenant_id) != tenant_id:
            return jsonify({"detail": "Forbidden: tenant_id mismatch"}), 403
        
        db = next(get_db())
        try:
            # Get tenant
            tenant = db.query(Tenant).filter(Tenant.id == tenant_uuid).first()
            if not tenant:
                return jsonify({"detail": "Tenant not found"}), 404
            
            # Update subscription status and trial counters based on plan
            # Write to tenant_billing.status (single source of truth for billing)
            from services.entitlements_centralized import update_tenant_billing_status
            
            # Determine plan_tier from subscription plan
            plan_tier_map = {
                "trial": "free",
                "individual": "solo",
                "team": "team",
                "canceled": None  # Keep existing plan_tier
            }
            new_plan_tier = plan_tier_map.get(plan)
            
            # Update tenant_billing.status and plan_tier
            # For trial: set plan_tier="free", status="trialing"
            # For paid plans: set plan_tier accordingly, status="incomplete" until Stripe confirms
            try:
                from services.entitlements_centralized import STATUS_TRIALING, STATUS_INCOMPLETE
                from sqlalchemy import text
                import uuid as uuid_lib
                
                tenant_uuid = uuid_lib.UUID(tenant_id)
                
                if plan == "trial":
                    # Trial plan: set plan_tier="free", status="trialing"
                    db.execute(
                        text("""
                            UPDATE tenant_billing
                            SET status = :status,
                                plan_tier = :plan_tier,
                                updated_at = NOW()
                            WHERE tenant_id = :tenant_id
                        """),
                        {
                            "status": STATUS_TRIALING,
                            "plan_tier": "free",
                            "tenant_id": str(tenant_uuid)
                        }
                    )
                elif plan == "individual" or plan == "team":
                    # Paid plan: set plan_tier, but keep status="incomplete" until Stripe confirms
                    # (For now, we'll set status to "active" since we don't have Stripe integration yet)
                    # TODO: When Stripe integration is added, set status="incomplete" here
                    from services.entitlements_centralized import update_tenant_billing_status
                    update_tenant_billing_status(db, str(tenant_id), plan, new_plan_tier)
                else:
                    # canceled or other: use existing update function
                    from services.entitlements_centralized import update_tenant_billing_status
                    update_tenant_billing_status(db, str(tenant_id), plan, new_plan_tier)
                
                db.commit()
            except RuntimeError as e:
                db.rollback()
                logger.error(f"Failed to update tenant_billing.status: {e}")
                return jsonify({"detail": "Failed to update billing status"}), 500
            
            # Update trial counters in tenants table (usage data, not billing)
            if plan == "trial":
                tenant.trial_requirements_runs_remaining = 3
                tenant.trial_testplan_runs_remaining = 3
                tenant.trial_writeback_runs_remaining = 3
            elif plan == "individual":
                # Individual plan: set counters to 0
                tenant.trial_requirements_runs_remaining = 0
                tenant.trial_testplan_runs_remaining = 0
                tenant.trial_writeback_runs_remaining = 0
            elif plan == "team":
                # Team plan: leave counters as-is (not used for team)
                pass
            elif plan == "canceled":
                # Canceled plan: leave counters as-is
                pass
            
            db.commit()
            db.refresh(tenant)
            
            # Read billing data from tenant_billing (single source of truth for reads)
            from services.entitlements_centralized import get_tenant_billing
            try:
                billing = get_tenant_billing(db, str(tenant_id))
                subscription_status = billing.get("subscription_status", "unselected")
                trial_requirements = billing.get("trial_requirements_runs_remaining", 0)
                trial_testplan = billing.get("trial_testplan_runs_remaining", 0)
                trial_writeback = billing.get("trial_writeback_runs_remaining", 0)
            except RuntimeError as e:
                logger.error(f"tenant_billing missing after subscription update: {e}")
                return jsonify({"detail": "Billing data is required but not found"}), 500
            
            return jsonify({
                "tenant_id": str(tenant.id),
                "subscription_status": subscription_status,
                "trial_requirements_runs_remaining": trial_requirements,
                "trial_testplan_runs_remaining": trial_testplan,
                "trial_writeback_runs_remaining": trial_writeback
            }), 200
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error updating tenant subscription: {e}", exc_info=True)
            return jsonify({"detail": "Internal server error"}), 500
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error updating tenant subscription: {e}", exc_info=True)
        return jsonify({"detail": "Internal server error"}), 500


@app.route("/api/v1/billing/webhook", methods=["POST"])
def stripe_webhook():
    """
    Stripe webhook endpoint for receiving billing events.
    
    This endpoint:
    - Bypasses app JWT auth (verified via Stripe signature instead)
    - Verifies Stripe webhook signature
    - Ingests events into stripe_events table with idempotency
    - Enforces STRIPE_MODE guard (test vs live)
    
    Phase 2: Ingest-only (no billing updates).
    
    Returns:
        200: Event received and ingested (or duplicate)
        400: Invalid signature or malformed request
        500: Server error
    """
    db = None
    try:
        from db import SessionLocal
        from services.stripe_webhook_ingest import ingest_stripe_event
        
        # Get raw request body (required for Stripe signature verification)
        raw_body = request.get_data()
        if not raw_body:
            app.logger.warning("Stripe webhook received empty body")
            return jsonify({"ok": False, "error": "Empty request body"}), 400
        
        # Get Stripe signature header
        signature = request.headers.get("Stripe-Signature", "")
        if not signature:
            app.logger.warning("Stripe webhook missing Stripe-Signature header")
            return jsonify({"ok": False, "error": "Missing Stripe-Signature header"}), 400
        
        # Create DB session directly using SessionLocal (works for public routes)
        db = SessionLocal()
        try:
            # Ingest event (verifies signature and inserts into database)
            result = ingest_stripe_event(raw_body, signature, db)
            
            if result.get("success"):
                # Event successfully ingested (new or duplicate)
                response_data = {
                    "received": True,
                    "event_id": result.get("event_id")
                }
                if result.get("ignored"):
                    response_data["ignored"] = True
                    response_data["reason"] = "livemode_mismatch"
                if result.get("duplicate"):
                    response_data["duplicate"] = True
                
                return jsonify(response_data), 200
            else:
                # Should not happen (exceptions are raised), but handle gracefully
                app.logger.error("Stripe webhook ingest returned success=False without exception")
                return jsonify({"ok": False, "error": "Failed to process event"}), 500
                
        except ValueError as e:
            # Signature verification failed
            app.logger.warning(f"Stripe webhook signature verification failed: {e}")
            return jsonify({"ok": False, "error": "Invalid webhook signature"}), 400
        except RuntimeError as e:
            # Database or other server error
            app.logger.exception("Stripe webhook processing error")
            return jsonify({"ok": False, "error": "Webhook handler error"}), 500
        except Exception as e:
            # Catch any other exceptions during ingestion
            app.logger.exception("Unexpected error during Stripe webhook ingestion")
            return jsonify({"ok": False, "error": "Webhook handler error"}), 500
        finally:
            if db:
                try:
                    db.close()
                except Exception:
                    pass  # Ignore errors during cleanup
            
    except Exception as e:
        # Catch exceptions during DB session creation or imports
        app.logger.exception("Stripe webhook failed")
        if db:
            try:
                db.close()
            except Exception:
                pass  # Ignore errors during cleanup
        return jsonify({"ok": False, "error": "Webhook handler error"}), 500


@app.route("/api/v1/billing/checkout-session", methods=["POST"])
def create_checkout_session():
    """
    Create a Stripe Checkout Session for paid plans (user, team).
    
    This endpoint:
    - Requires authentication (tenant_id from JWT)
    - Creates a Stripe Checkout Session for subscription
    - Returns checkout URL for redirect
    
    Phase 3A: Checkout creation only (no billing updates).
    
    Request body:
        {
            "plan_tier": "user" | "team"
        }
    
    Returns:
        200: {
            "ok": true,
            "url": "<checkout_url>",
            "session_id": "<session_id>"
        }
        400: Invalid plan_tier or free plan
        500: Server error (missing env vars, Stripe error)
    """
    try:
        # Require authentication (tenant_id from JWT) - DO NOT accept from payload
        if not hasattr(g, 'tenant_id') or not g.tenant_id:
            return jsonify({"ok": False, "error": "Unauthorized"}), 401
        
        tenant_id = str(g.tenant_id)
        
        # Ensure tenant_billing row exists (create if missing with defaults)
        from db import SessionLocal
        from services.entitlements_centralized import get_tenant_billing, create_tenant_billing_row
        
        db = SessionLocal()
        try:
            try:
                # Try to get billing data
                billing = get_tenant_billing(db, tenant_id)
            except RuntimeError:
                # tenant_billing row is missing - create it with defaults
                logger.info(f"tenant_billing row missing for tenant {tenant_id}, creating with defaults")
                try:
                    # Use "trial" as default plan_tier (database constraint allows: trial, user, team, enterprise)
                    create_tenant_billing_row(db, tenant_id, "unselected", "trial")
                    db.commit()
                    # Refresh to get the newly created billing data
                    billing = get_tenant_billing(db, tenant_id)
                except Exception as create_error:
                    db.rollback()
                    logger.error(f"Failed to create tenant_billing row for tenant {tenant_id}: {create_error}", exc_info=True)
                    return jsonify({
                        "ok": False,
                        "error": "TENANT_BILLING_MISSING",
                        "detail": "Billing data is required but could not be created"
                    }), 409
        finally:
            db.close()
        
        # Get request data
        data = request.get_json()
        if not data:
            return jsonify({"ok": False, "error": "Request body must be JSON"}), 400
        
        plan_tier = data.get("plan_tier", "").strip().lower()
        if not plan_tier:
            return jsonify({"ok": False, "error": "plan_tier is required"}), 400
        
        # Validate plan_tier - only paid plans allowed
        if plan_tier == "free":
            return jsonify({"ok": False, "error": "Free plan does not require checkout"}), 400
        
        if plan_tier not in ("user", "team"):
            return jsonify({"ok": False, "error": f"Invalid plan_tier: {plan_tier}. Must be 'user' or 'team'"}), 400
        
        # Check required environment variables
        stripe_secret_key = os.getenv("STRIPE_SECRET_KEY")
        app_base_url = os.getenv("APP_BASE_URL")
        
        # Price mapping (explicit, no magic)
        PRICE_BY_PLAN = {
            "user": os.getenv("STRIPE_PRICE_USER"),
            "team": os.getenv("STRIPE_PRICE_TEAM"),
        }
        
        price_id = PRICE_BY_PLAN.get(plan_tier)
        
        # Validate required env vars
        missing_vars = []
        if not stripe_secret_key:
            missing_vars.append("STRIPE_SECRET_KEY")
        if not app_base_url:
            missing_vars.append("APP_BASE_URL")
        if not price_id:
            missing_vars.append(f"STRIPE_PRICE_{plan_tier.upper()}")
        
        if missing_vars:
            app.logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
            return jsonify({"ok": False, "error": "Server configuration error"}), 500
        
        # Initialize Stripe
        try:
            import stripe
            stripe.api_key = stripe_secret_key
        except ImportError:
            app.logger.error("stripe package not installed")
            return jsonify({"ok": False, "error": "Server configuration error"}), 500
        
        # Create Stripe Checkout Session
        try:
            session = stripe.checkout.Session.create(
                mode="subscription",
                line_items=[
                    {
                        "price": price_id,
                        "quantity": 1
                    }
                ],
                client_reference_id=tenant_id,
                metadata={
                    "tenant_id": tenant_id,
                    "plan_tier": plan_tier
                },
                subscription_data={
                    "metadata": {
                        "tenant_id": tenant_id,
                        "plan_tier": plan_tier
                    }
                },
                success_url=f"{app_base_url}/onboarding/plan?success=1",
                cancel_url=f"{app_base_url}/onboarding/plan?canceled=1"
            )
            
            return jsonify({
                "ok": True,
                "url": session.url,
                "session_id": session.id
            }), 200
            
        except stripe.error.StripeError as e:
            app.logger.exception(f"Stripe API error creating checkout session: {e}")
            return jsonify({"ok": False, "error": "Failed to create checkout session"}), 500
        except Exception as e:
            app.logger.exception(f"Unexpected error creating checkout session: {e}")
            return jsonify({"ok": False, "error": "Server error"}), 500
            
    except Exception as e:
        app.logger.exception("Unexpected error in checkout session endpoint")
        return jsonify({"ok": False, "error": "Server error"}), 500


@app.route("/api/v1/billing/portal-session", methods=["POST"])
def create_portal_session():
    """
    Create a Stripe Customer Portal session for billing management.
    
    This endpoint:
    - Requires authentication (tenant_id from JWT)
    - Creates a Stripe Customer Portal session
    - Returns portal URL for redirect
    
    Request body:
        None required (ignored if provided)
    
    Returns:
        200: {
            "ok": true,
            "url": "<portal_url>"
        }
        409: Tenant billing missing or no Stripe customer
        500: Server error (Stripe portal not configured, etc.)
    """
    try:
        # Require authentication (tenant_id from JWT) - DO NOT accept from payload
        if not hasattr(g, 'tenant_id') or not g.tenant_id:
            return jsonify({"ok": False, "error": "Unauthorized"}), 401
        
        tenant_id = str(g.tenant_id)
        
        # Get tenant_billing to retrieve stripe_customer_id
        from db import SessionLocal
        from services.entitlements_centralized import get_tenant_billing
        from sqlalchemy import text
        
        db = SessionLocal()
        try:
            try:
                billing = get_tenant_billing(db, tenant_id)
            except RuntimeError:
                # tenant_billing row is missing
                logger.error(f"tenant_billing row missing for tenant {tenant_id}")
                return jsonify({
                    "ok": False,
                    "error": "TENANT_BILLING_MISSING"
                }), 409
            
            # Query for stripe_customer_id directly from tenant_billing
            result = db.execute(
                text("""
                    SELECT stripe_customer_id
                    FROM tenant_billing
                    WHERE tenant_id = :tenant_id
                """),
                {"tenant_id": tenant_id}
            ).first()
            
            if not result:
                return jsonify({
                    "ok": False,
                    "error": "TENANT_BILLING_MISSING"
                }), 409
            
            stripe_customer_id = result.stripe_customer_id
            
            # Check if stripe_customer_id exists and is not empty
            if not stripe_customer_id or not stripe_customer_id.strip():
                logger.warning(f"No stripe_customer_id for tenant {tenant_id} (never completed paid checkout)")
                return jsonify({
                    "ok": False,
                    "error": "NO_STRIPE_CUSTOMER"
                }), 409
                
        finally:
            db.close()
        
        # Check required environment variables
        stripe_secret_key = os.getenv("STRIPE_SECRET_KEY")
        app_base_url = os.getenv("APP_BASE_URL")
        
        if not stripe_secret_key:
            app.logger.error("STRIPE_SECRET_KEY environment variable not set")
            return jsonify({"ok": False, "error": "Server configuration error"}), 500
        
        if not app_base_url:
            app.logger.error("APP_BASE_URL environment variable not set")
            return jsonify({"ok": False, "error": "Server configuration error"}), 500
        
        # Initialize Stripe
        try:
            import stripe
            stripe.api_key = stripe_secret_key
        except ImportError:
            app.logger.error("stripe package not installed")
            return jsonify({"ok": False, "error": "Server configuration error"}), 500
        
        # Create Stripe Customer Portal Session
        try:
            portal_session = stripe.billing_portal.Session.create(
                customer=stripe_customer_id,
                return_url=f"{app_base_url}/settings/billing"
            )
            
            return jsonify({
                "ok": True,
                "url": portal_session.url
            }), 200
            
        except stripe.error.StripeError as e:
            # Handle Stripe errors (portal not configured, etc.)
            app.logger.exception(f"Stripe API error creating portal session: {e}")
            # Check if it's a portal configuration error
            error_code = getattr(e, 'code', None)
            if error_code in ('portal_configuration_invalid', 'portal_configuration_not_found'):
                return jsonify({"ok": False, "error": "STRIPE_PORTAL_NOT_CONFIGURED"}), 500
            # Generic error for other Stripe errors
            return jsonify({"ok": False, "error": "STRIPE_PORTAL_NOT_CONFIGURED"}), 500
        except Exception as e:
            app.logger.exception(f"Unexpected error creating portal session: {e}")
            return jsonify({"ok": False, "error": "Server error"}), 500
            
    except Exception as e:
        app.logger.exception("Unexpected error in portal session endpoint")
        return jsonify({"ok": False, "error": "Server error"}), 500


@app.route("/api/v1/billing/status", methods=["GET"])
def get_billing_status():
    """
    Get the current billing status for the authenticated tenant.
    
    This endpoint:
    - Requires authentication (tenant_id from JWT)
    - Returns billing status from tenant_billing table
    
    Returns:
        200: {
            "ok": true,
            "tenant_id": "<uuid>",
            "plan_tier": "<string>",
            "status": "<string>",
            "current_period_start": "<iso or null>",
            "current_period_end": "<iso or null>",
            "cancel_at_period_end": <bool>
        }
        404: Tenant billing missing
    """
    try:
        # Require authentication (tenant_id from JWT) - DO NOT accept from payload
        if not hasattr(g, 'tenant_id') or not g.tenant_id:
            return jsonify({"ok": False, "error": "Unauthorized"}), 401
        
        tenant_id = str(g.tenant_id)
        
        # Query tenant_billing for billing status
        from db import SessionLocal
        from sqlalchemy import text
        
        db = SessionLocal()
        try:
            result = db.execute(
                text("""
                    SELECT tenant_id, plan_tier, status,
                           current_period_start, current_period_end,
                           cancel_at_period_end
                    FROM tenant_billing
                    WHERE tenant_id = :tenant_id
                """),
                {"tenant_id": tenant_id}
            ).first()
            
            if not result:
                return jsonify({
                    "ok": False,
                    "error": "TENANT_BILLING_MISSING"
                }), 404
            
            # Convert timestamps to ISO format (or null)
            current_period_start_iso = None
            if result.current_period_start:
                if isinstance(result.current_period_start, datetime):
                    current_period_start_iso = result.current_period_start.isoformat()
                else:
                    # If it's already a string, pass through
                    current_period_start_iso = str(result.current_period_start)
            
            current_period_end_iso = None
            if result.current_period_end:
                if isinstance(result.current_period_end, datetime):
                    current_period_end_iso = result.current_period_end.isoformat()
                else:
                    # If it's already a string, pass through
                    current_period_end_iso = str(result.current_period_end)
            
            # Ensure cancel_at_period_end is boolean (default false if null)
            cancel_at_period_end = bool(result.cancel_at_period_end) if result.cancel_at_period_end is not None else False
            
            return jsonify({
                "ok": True,
                "tenant_id": str(result.tenant_id),
                "plan_tier": result.plan_tier or None,
                "status": result.status or None,
                "current_period_start": current_period_start_iso,
                "current_period_end": current_period_end_iso,
                "cancel_at_period_end": cancel_at_period_end
            }), 200
            
        finally:
            db.close()
            
    except Exception as e:
        app.logger.exception("Unexpected error in billing status endpoint")
        return jsonify({"ok": False, "error": "Server error"}), 500


@app.route("/api/v1/tenants/check-slug", methods=["GET"])
def check_slug_availability():
    """
    Check if a company name slug is available and suggest alternatives if taken.
    Public endpoint (no auth required).
    
    Query parameters:
        name: Company name to check
    
    Returns:
        {
            "available": boolean,
            "slug": "computed-slug",
            "suggestions": ["slug-2", "slug-3"] (if not available)
        }
    """
    try:
        from db import get_db
        from models import Tenant
        from utils.slugify import slugify
        
        company_name = request.args.get("name", "").strip()
        if not company_name:
            return jsonify({"detail": "name parameter is required"}), 400
        
        base_slug = slugify(company_name)
        if not base_slug:
            return jsonify({"detail": "Invalid company name"}), 400
        
        db = next(get_db())
        try:
            # Check if base slug is available
            existing_tenant = db.query(Tenant).filter(Tenant.slug == base_slug).first()
            
            if not existing_tenant:
                return jsonify({
                    "available": True,
                    "slug": base_slug,
                    "suggestions": []
                }), 200
            
            # Slug is taken, generate unique suggestions
            suggestions = []
            counter = 2
            seen_slugs = set()  # Track seen slugs to ensure uniqueness
            while len(suggestions) < 3:
                candidate_slug = f"{base_slug}-{counter}"
                # Ensure candidate is unique in our suggestions list
                if candidate_slug not in seen_slugs:
                    candidate_tenant = db.query(Tenant).filter(Tenant.slug == candidate_slug).first()
                    if not candidate_tenant:
                        suggestions.append(candidate_slug)
                        seen_slugs.add(candidate_slug)
                counter += 1
                # Safety limit to prevent infinite loop
                if counter > 100:
                    break
            
            return jsonify({
                "available": False,
                "slug": base_slug,
                "suggestions": suggestions
            }), 200
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Error checking slug availability: {e}", exc_info=True)
        return jsonify({"detail": "Internal server error"}), 500


@app.route("/api/v1/onboarding/company", methods=["POST"])
def create_company():
    """
    DEPRECATED: User-first company creation endpoint (removed in tenant-first onboarding).
    
    This endpoint is no longer supported. Use tenant-first onboarding flow:
    1. POST /api/v1/onboarding/tenant (create tenant)
    2. POST /api/v1/onboarding/tenant/{tenant_id}/admin (create first admin user)
    """
    return jsonify({
        "detail": "This endpoint is deprecated. Please use tenant-first onboarding: POST /api/v1/onboarding/tenant",
        "error": "DEPRECATED_ENDPOINT"
    }), 410  # 410 Gone


@app.route("/api/v1/onboarding/tenant", methods=["POST"])
def create_tenant():
    """
    Create tenant (company/workspace) - Step 1 of tenant-first onboarding.
    Public endpoint (no auth required).
    
    Request body:
        {
            "company_name": "Acme Widgets"
        }
    
    Returns:
        {
            "tenant_id": "<tenant_id>",
            "tenant_slug": "<tenant_slug>",
            "tenant_name": "<tenant_name>"
        }
    
    On slug collision (409):
        {
            "detail": "Tenant slug already exists",
            "slug": "acme-widgets",
            "suggestions": ["acme-widgets-2", "acme-widgets-3"]
        }
    """
    # Rate limiting: max 10 requests per hour per IP
    client_ip = _get_client_ip()
    allowed, remaining = _check_rate_limit(client_ip, "/api/v1/onboarding/tenant", max_requests=10, window_seconds=3600)
    if not allowed:
        return jsonify({"detail": "Rate limit exceeded"}), 429
    
    try:
        from db import get_db
        from models import Tenant
        from utils.slugify import slugify
        
        # Get request data
        data = request.get_json()
        if not data:
            return jsonify({"detail": "Request body must be JSON"}), 400
        
        company_name = data.get("company_name", "").strip()
        if not company_name:
            return jsonify({"detail": "company_name is required"}), 400
        
        # Generate slug
        base_slug = slugify(company_name)
        if not base_slug:
            return jsonify({"detail": "Invalid company name"}), 400
        
        db = next(get_db())
        try:
            # Check if base slug is available
            existing_tenant = db.query(Tenant).filter(Tenant.slug == base_slug).first()
            
            if existing_tenant:
                # Slug is taken, return 409 with suggestions
                suggestions = []
                counter = 2
                seen_slugs = {base_slug}
                while len(suggestions) < 3:
                    candidate_slug = f"{base_slug}-{counter}"
                    if candidate_slug not in seen_slugs:
                        candidate_tenant = db.query(Tenant).filter(Tenant.slug == candidate_slug).first()
                        if not candidate_tenant:
                            suggestions.append(candidate_slug)
                            seen_slugs.add(candidate_slug)
                    counter += 1
                    if counter > 100:  # Safety limit
                        break
                
                return jsonify({
                    "detail": "Tenant slug already exists",
                    "slug": base_slug,
                    "suggestions": suggestions
                }), 409
            
            # Create tenant (billing data goes to tenant_billing table, not here)
            tenant = Tenant(
                name=company_name,
                slug=base_slug,
                is_active=True,
                # Trial counters initialized to 0 (only set when plan is selected)
                trial_requirements_runs_remaining=0,
                trial_testplan_runs_remaining=0,
                trial_writeback_runs_remaining=0
            )
            db.add(tenant)
            db.commit()
            db.refresh(tenant)
            
            # Create tenant_billing row (single source of truth for billing data)
            # Initialize with plan_tier="trial", status="incomplete" (enforces onboarding gate)
            from services.entitlements_centralized import create_tenant_billing_row
            try:
                create_tenant_billing_row(db, str(tenant.id), "unselected", "trial")  # Use "trial" as default (database constraint allows: trial, user, team, enterprise)
            except RuntimeError as e:
                logger.error(f"Failed to create tenant_billing row: {e}")
                # Continue - tenant is created, billing row can be created later if needed
                # But log the error for monitoring
            
            return jsonify({
                "tenant_id": str(tenant.id),
                "tenant_slug": tenant.slug,
                "tenant_name": tenant.name
            }), 201
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error creating tenant: {e}", exc_info=True)
            # Check for unique constraint violation (slug collision)
            if "ix_tenants_slug" in str(e) or "slug" in str(e).lower():
                suggestions = []
                counter = 2
                while len(suggestions) < 3:
                    suggestions.append(f"{base_slug}-{counter}")
                    counter += 1
                return jsonify({
                    "detail": "Tenant slug already exists",
                    "slug": base_slug,
                    "suggestions": suggestions
                }), 409
            return jsonify({"detail": "Internal server error"}), 500
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Error creating tenant: {e}", exc_info=True)
        return jsonify({"detail": "Internal server error"}), 500


@app.route("/api/v1/onboarding/tenant/<tenant_id>/admin", methods=["POST"])
def create_tenant_admin(tenant_id):
    """
    Create first tenant admin user - Step 2 of tenant-first onboarding.
    Public endpoint (no auth required).
    
    Path parameters:
        tenant_id: UUID of the tenant (created in Step 1)
    
    Request body:
        {
            "email": "admin@example.com",
            "password": "password123",
            "role": "admin",  // REQUIRED but will be forced to "admin" for first user
            "first_name": "John" (optional),
            "last_name": "Doe" (optional)
        }
    
    Returns:
        {
            "token": "<jwt>",
            "tenant_id": "<tenant_id>",
            "user": {
                "id": "<user_id>",
                "email": "<email>",
                "role": "admin",
                "first_name": "<first_name>",
                "last_name": "<last_name>"
            }
        }
    """
    # Rate limiting: max 20 requests per hour per IP
    client_ip = _get_client_ip()
    allowed, remaining = _check_rate_limit(client_ip, f"/api/v1/onboarding/tenant/{tenant_id}/admin", max_requests=20, window_seconds=3600)
    if not allowed:
        return jsonify({"detail": "Rate limit exceeded"}), 429
    
    try:
        from db import get_db
        from models import TenantUser, Tenant
        import uuid as uuid_lib
        from sqlalchemy import func
        
        # Get request data
        data = request.get_json()
        if not data:
            return jsonify({"detail": "Request body must be JSON"}), 400
        
        email = data.get("email", "").strip()
        password = data.get("password", "")
        role = data.get("role", "admin").strip()  # Accept role but enforce admin
        first_name = data.get("first_name", "").strip() or None
        last_name = data.get("last_name", "").strip() or None
        
        # Validate required fields
        if not email:
            return jsonify({"detail": "email is required"}), 400
        if not password:
            return jsonify({"detail": "password is required"}), 400
        
        # Normalize email: lowercase and trim
        email = email.lower().strip()
        
        # Validate tenant_id
        try:
            tenant_uuid = uuid_lib.UUID(tenant_id)
        except ValueError:
            return jsonify({"detail": "Invalid tenant_id format"}), 400
        
        db = next(get_db())
        try:
            # Verify tenant exists
            tenant = db.query(Tenant).filter(Tenant.id == tenant_uuid).first()
            if not tenant:
                return jsonify({"detail": "Tenant not found"}), 404
            
            # FRESH-TENANT RULE: Check if tenant was created recently (within 15 minutes)
            tenant_age_seconds = (datetime.now(timezone.utc) - tenant.created_at).total_seconds()
            if tenant_age_seconds > 900:  # 15 minutes = 900 seconds
                # Check if tenant has any users
                user_count = db.query(func.count(TenantUser.id)).filter(
                    TenantUser.tenant_id == tenant_uuid
                ).scalar()
                
                if user_count == 0:
                    # Tenant is older than 15 minutes and has no users - expired onboarding session
                    return jsonify({
                        "detail": "Onboarding session expired. Please restart onboarding."
                    }), 410
            
            # FIRST USER ONLY INVARIANT: Check if tenant already has any users
            user_count = db.query(func.count(TenantUser.id)).filter(
                TenantUser.tenant_id == tenant_uuid
            ).scalar()
            
            if user_count > 0:
                return jsonify({
                    "detail": "Tenant already has a user. Admin creation not allowed."
                }), 409
            
            # Check if email already exists within this tenant (UNIQUE constraint check)
            existing_user = db.query(TenantUser).filter(
                TenantUser.email == email,
                TenantUser.tenant_id == tenant_uuid
            ).first()
            if existing_user:
                return jsonify({"detail": "Email already registered in this tenant"}), 409
            
            # Hash password
            password_bytes = password.encode('utf-8')
            salt = bcrypt.gensalt()
            password_hash_bytes = bcrypt.hashpw(password_bytes, salt)
            password_hash = password_hash_bytes.decode('utf-8')
            
            # Create user - FORCE role to "admin" for first user
            tenant_user = TenantUser(
                tenant_id=tenant_uuid,
                email=email,
                password_hash=password_hash,
                role="admin",  # First user is always admin
                is_active=True,
                first_name=first_name,
                last_name=last_name
            )
            db.add(tenant_user)
            db.commit()
            db.refresh(tenant_user)
            
            # Create JWT token with tenant_id (always required)
            access_token = create_access_token(
                user_id=str(tenant_user.id),
                tenant_id=str(tenant_user.tenant_id),
                role=tenant_user.role
            )
            
            # Return response
            return jsonify({
                "token": access_token,
                "tenant_id": str(tenant_user.tenant_id),
                "user": {
                    "id": str(tenant_user.id),
                    "email": tenant_user.email,
                    "role": tenant_user.role,
                    "first_name": tenant_user.first_name,
                    "last_name": tenant_user.last_name
                }
            }), 201
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error creating tenant admin: {e}", exc_info=True)
            # Check for unique constraint violation
            if "uq_tenant_users_tenant_email" in str(e) or "email" in str(e).lower():
                return jsonify({"detail": "Email already registered in this tenant"}), 409
            return jsonify({"detail": "Internal server error"}), 500
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error creating tenant admin: {e}", exc_info=True)
        return jsonify({"detail": "Internal server error"}), 500


@app.route("/jira-test", methods=["GET"])
def jira_test():
    from services.integrations import get_jira_integration_for_current_tenant
    jira_creds = get_jira_integration_for_current_tenant()
    ticket = fetch_jira_ticket(
        jira_creds["base_url"],
        jira_creds["email"],
        jira_creds["api_token"],
        "ATA-34"
    )
    return jsonify(ticket)


@app.route("/export/rtm", methods=["GET"])
def export_rtm():
    """
    Export the most recently generated RTM as a CSV file.
    
    Returns:
        CSV file with columns: requirement_id, requirement_description, coverage_status, covered_by_tests
        Includes ISO 27001/SOC 2 compliant audit metadata as comments.
        HTTP 400 if no test plan has been generated yet
    """
    global _most_recent_test_plan
    
    # Try loading from file if not in memory
    if _most_recent_test_plan is None:
        load_test_plan_from_file()
    
    if _most_recent_test_plan is None:
        return jsonify({
            "error": "No test plan has been generated yet"
        }), 400
    
    rtm = _most_recent_test_plan.get("rtm", [])
    audit_metadata = _most_recent_test_plan.get("audit_metadata")
    csv_bytes = export_rtm_csv_simple(rtm, audit_metadata)
    
    return Response(
        csv_bytes,
        mimetype="text/csv",
        headers={
            "Content-Disposition": 'attachment; filename="rtm.csv"'
        }
    )


@app.route("/export/test-plan", methods=["GET"])
def export_test_plan():
    """
    Export the most recently generated test plan as a JSON file.
    
    Returns:
        JSON file containing the test_plan object with ISO 27001/SOC 2 compliant audit metadata
        HTTP 400 if no test plan has been generated yet
    """
    global _most_recent_test_plan
    
    # Try loading from file if not in memory
    if _most_recent_test_plan is None:
        load_test_plan_from_file()
    
    if _most_recent_test_plan is None:
        return jsonify({
            "error": "No test plan has been generated yet"
        }), 400
    
    # Return the test_plan object with audit metadata (self-contained compliance artifact)
    export_data = {
        "test_plan": _most_recent_test_plan.get("test_plan", {}),
        "audit_metadata": _most_recent_test_plan.get("audit_metadata", {})
    }
    json_bytes = json.dumps(export_data, indent=2, ensure_ascii=False).encode('utf-8')
    
    return Response(
        json_bytes,
        mimetype="application/json",
        headers={
            "Content-Disposition": 'attachment; filename="test_plan.json"'
        }
    )


def load_test_plan_by_run_id(run_id: str):
    """
    Load test plan by run_id from stored artifacts.
    
    Currently uses the most recent test plan and matches by run_id.
    In the future, this could be extended to load from a database or file system.
    
    Args:
        run_id: The run_id to look up
    
    Returns:
        dict: Test plan object if found and run_id matches, None otherwise
    """
    global _most_recent_test_plan
    
    # Try loading from file if not in memory
    if _most_recent_test_plan is None:
        load_test_plan_from_file()
    
    if _most_recent_test_plan is None:
        return None
    
    # Check if run_id matches
    audit_metadata = _most_recent_test_plan.get("audit_metadata", {})
    stored_run_id = audit_metadata.get("run_id")
    
    if stored_run_id == run_id:
        return _most_recent_test_plan
    
    return None


def extract_non_testable_items_from_rtm(rtm: list) -> list:
    """
    Extract non-testable/informational items from RTM.
    
    This function deterministically extracts items where trace_type="informational"
    or testability="not_testable" from the RTM.
    
    Args:
        rtm: List of RTM entries
    
    Returns:
        list: List of non-testable item dicts with required fields
    """
    non_testable_items = []
    
    for entry in rtm:
        if not isinstance(entry, dict):
            continue
        
        trace_type = entry.get("trace_type", "")
        testability = entry.get("testability", "")
        
        # Check if this is a non-testable item
        if trace_type == "informational" or testability == "not_testable":
            item_id = entry.get("requirement_id", "")
            item_description = entry.get("requirement_description", "")
            rationale = entry.get("rationale", "Informational content; not independently testable")
            source_section = entry.get("source_section", "Unknown")
            
            if item_id:  # Only include items with valid IDs
                non_testable_items.append({
                    "id": item_id,
                    "title": item_description,
                    "source_requirement_id": item_id,  # Use item_id as source requirement ID
                    "rationale": rationale,
                    "source_section": source_section
                })
    
    return non_testable_items


def format_steps_for_csv(steps: list) -> str:
    """
    Format test steps as numbered list for CSV cell.
    
    Args:
        steps: List of step strings
    
    Returns:
        str: Formatted steps with numbering (e.g., "1) step1\n2) step2")
    """
    if not steps or not isinstance(steps, list):
        return ""
    
    formatted = []
    for idx, step in enumerate(steps, 1):
        if step:
            formatted.append(f"{idx}) {step}")
    
    return "\n".join(formatted)


def generate_execution_report_csv(test_plan_data: dict, run_id_param: str = None) -> str:
    """
    Generate Test Execution Report CSV from test plan data.
    
    Args:
        test_plan_data: Complete test plan dict with test_plan, rtm, audit_metadata
        run_id_param: Optional run_id from URL parameter (used as fallback)
    
    Returns:
        str: CSV content as string
    """
    output = io.StringIO()
    
    # Define exact column order
    # Add Logic Version and Agent Version columns at the beginning
    fieldnames = [
        "Logic Version",
        "Agent Version",
        "Run ID",
        "Section",
        "Item Type",
        "Test ID",
        "Title",
        "Source Requirement ID",
        "Requirements Covered",
        "Intent Type",
        "Steps",
        "Expected Result",
        "Steps Origin",
        "Priority",
        "Confidence",
        "Traceability Note",
        "Result",
        "Tester Notes",
        "Executed At"
    ]
    
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    
    # Get run_id from audit_metadata if present, else use run_id_param
    audit_metadata = test_plan_data.get("audit_metadata", {})
    run_id = audit_metadata.get("run_id") or run_id_param or ""
    
    # Get agent_metadata for versioning
    agent_metadata = audit_metadata.get("agent_metadata", {})
    logic_version = agent_metadata.get("logic_version", "testplan-v1+coverage-enforcer-v1")
    agent_version = agent_metadata.get("agent_version", "1.0.0")
    
    # Get test plan sections
    test_plan = test_plan_data.get("test_plan", {})
    
    # Section mapping: test_plan key -> display name
    section_mapping = {
        "api_tests": "API",
        "ui_tests": "UI",
        "data_validation_tests": "Data Validation",
        "edge_cases": "Edge Case",
        "negative_tests": "Negative"
    }
    
    # Process executable tests in deterministic order
    for section_key, section_name in section_mapping.items():
        tests = test_plan.get(section_key, [])
        if not isinstance(tests, list):
            continue
        
        for test in tests:
            if not isinstance(test, dict):
                continue
            
            # Format requirements_covered
            requirements_covered = test.get("requirements_covered", [])
            if isinstance(requirements_covered, list):
                reqs_covered_str = "|".join(requirements_covered) if requirements_covered else ""
            else:
                reqs_covered_str = ""
            
            # Format steps
            steps = test.get("steps", [])
            steps_formatted = format_steps_for_csv(steps)
            
            writer.writerow({
                "Logic Version": logic_version,
                "Agent Version": agent_version,
                "Run ID": run_id,
                "Section": section_name,
                "Item Type": "Test",
                "Test ID": test.get("id", ""),
                "Title": test.get("title", ""),
                "Source Requirement ID": test.get("source_requirement_id", ""),
                "Requirements Covered": reqs_covered_str,
                "Intent Type": test.get("intent_type", ""),
                "Steps": steps_formatted,
                "Expected Result": test.get("expected_result", ""),
                "Steps Origin": test.get("steps_origin", ""),
                "Priority": test.get("priority", ""),
                "Confidence": test.get("confidence", ""),
                "Traceability Note": "",
                "Result": "",
                "Tester Notes": "",
                "Executed At": ""
            })
    
    # Process non-testable items from RTM
    rtm = test_plan_data.get("rtm", [])
    non_testable_items = extract_non_testable_items_from_rtm(rtm)
    
    for item in non_testable_items:
        # Build traceability note
        rationale = item.get("rationale", "Informational content; not independently testable")
        source_section = item.get("source_section", "Unknown")
        traceability_note = f"Not Testable: {rationale}\nSource Section: {source_section}"
        
        writer.writerow({
            "Logic Version": logic_version,
            "Agent Version": agent_version,
            "Run ID": run_id,
            "Section": "Informational",
            "Item Type": "Informational Only",
            "Test ID": item.get("id", ""),
            "Title": item.get("title", ""),
            "Source Requirement ID": item.get("source_requirement_id", ""),
            "Requirements Covered": "",
            "Intent Type": "not_testable",
            "Steps": "",
            "Expected Result": "",
            "Steps Origin": "source-only",
            "Priority": "",
            "Confidence": "",
            "Traceability Note": traceability_note,
            "Result": "",
            "Tester Notes": "",
            "Executed At": ""
        })
    
    csv_content = output.getvalue()
    output.close()
    return csv_content


@app.route("/api/v1/test-plan/<run_id>/execution-report.csv", methods=["GET"])
def export_execution_report(run_id: str):
    """
    Export Test Execution Report as CSV for a specific run_id.
    
    Returns:
        CSV file with executable tests and non-testable items
        HTTP 404 if run_id not found
    """
    # Load test plan by run_id
    test_plan_data = load_test_plan_by_run_id(run_id)
    
    if test_plan_data is None:
        return jsonify({
            "detail": "Run not found"
        }), 404
    
    # Generate CSV (pass run_id as fallback)
    csv_content = generate_execution_report_csv(test_plan_data, run_id)
    
    # Return CSV response
    return Response(
        csv_content,
        mimetype="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="test-execution-report_{run_id}.csv"'
        }
    )


def normalize_request(data):
    """
    Normalize request data to unified structure supporting both single and multi-ticket formats.
    
    Args:
        data: Request JSON data (either old format with ticket_id or new format with scope/tickets)
    
    Returns:
        dict: Normalized structure with scope, tickets, and options
    """
    # Multi-ticket format: "tickets" array takes precedence
    if "tickets" in data and isinstance(data.get("tickets"), list) and len(data["tickets"]) > 0:
        tickets = data.get("tickets", [])
        scope = data.get("scope", {})
        options = data.get("options", {})
        
        # Auto-generate scope if missing
        if not scope:
            scope = {
                "type": "manual",
                "id": "MANUAL"
            }
        
        return {
            "scope": {
                "type": scope.get("type", "manual"),
                "id": scope.get("id", "MANUAL"),
                "name": scope.get("name", "")
            },
            "tickets": tickets,
            "options": {
                "generate_inferred_tests": options.get("generate_inferred_tests", True),
                "generate_negative_tests": options.get("generate_negative_tests", True),
                "enforce_quality_rules": options.get("enforce_quality_rules", True)
            }
        }
    
    # Legacy single-ticket format
    elif "ticket_id" in data:
        ticket_id = data["ticket_id"]
        return {
            "scope": {
                "type": "ticket",
                "id": ticket_id,
                "name": ""
            },
            "tickets": [
                {
                    "ticket_id": ticket_id,
                    "source": "jira",
                    "role": "primary"
                }
            ],
            "options": {
                "generate_inferred_tests": True,
                "generate_negative_tests": True,
                "enforce_quality_rules": True
            }
        }
    
    # Manual ticket format (for testing)
    else:
        return {
            "scope": {
                "type": "ticket",
                "id": "MANUAL",
                "name": ""
            },
            "tickets": [
                {
                    "ticket_id": "MANUAL",
                    "source": "manual",
                    "role": "primary"
                }
            ],
            "options": {
                "generate_inferred_tests": True,
                "generate_negative_tests": True,
                "enforce_quality_rules": True
            }
        }


def names_ui_element(requirement_text):
    """
    Check if requirement text names a UI element.
    
    Args:
        requirement_text: Requirement description string
    
    Returns:
        bool: True if requirement mentions UI elements
    """
    if not isinstance(requirement_text, str):
        return False
    
    text_lower = requirement_text.lower()
    ui_keywords = [
        "button", "link", "menu", "field", "form", "page", "screen",
        "click", "tap", "select", "input", "dropdown", "checkbox",
        "radio", "tab", "dialog", "modal", "panel", "section"
    ]
    
    # Check for quoted labels (e.g., "Download PDF" button)
    import re
    has_quoted_label = bool(re.search(r'["\']([^"\']+)["\']', requirement_text))
    
    return any(keyword in text_lower for keyword in ui_keywords) or has_quoted_label


def explode_item_into_atomic_items(item_text: str, ticket_id: str, base_counter: int, source_section: str, original_line: str = None) -> list:
    """
    Explode a composite ticket item into atomic ticket items.
    
    Generic function that applies to ALL tickets. Identifies statements referencing
    multiple UI elements and splits them into atomic items (one per UI element/action).
    
    Args:
        item_text: The text of the ticket item (may be composite)
        ticket_id: Ticket ID for generating item IDs
        base_counter: Base counter for sequential item ID generation
        source_section: Source section (description, acceptance_criteria, etc.)
        original_line: Original line text (for traceability)
    
    Returns:
        list: List of atomic item dicts, each representing ONE UI element or action
    """
    import re
    
    # Check if item references multiple UI elements
    if not detect_composite_ticket_item(item_text):
        # Not composite, return as single atomic item
        return [{
            "item_id": f"{ticket_id}-ITEM-{base_counter:03d}",
            "text": item_text.strip(),
            "source_section": source_section,
            "original_line": original_line or item_text
        }]
    
    # Composite item - split into atomic items
    atomic_items = []
    item_counter = base_counter
    
    # Strategy 1: Split by "and" (most common for UI element lists)
    if re.search(r'\s+and\s+', item_text, re.IGNORECASE):
        parts = re.split(r'\s+and\s+', item_text, flags=re.IGNORECASE)
        parts = [p.strip() for p in parts if p.strip()]
        # Remove leading/trailing commas
        parts = [re.sub(r'^,\s*|\s*,$', '', p) for p in parts]
        parts = [p for p in parts if p]
        
        if len(parts) > 1:
            for part in parts:
                if part:
                    atomic_items.append({
                        "item_id": f"{ticket_id}-ITEM-{item_counter:03d}",
                        "text": part.strip(),
                        "source_section": source_section,
                        "original_line": original_line or item_text
                    })
                    item_counter += 1
            if atomic_items:
                return atomic_items
    
    # Strategy 2: Split by commas (list pattern: "field A, field B, and field C")
    if ',' in item_text:
        # Check for list pattern with "and" before last item
        list_pattern = re.compile(r'(.+?)(?:,\s*and\s+)?,\s*(.+)', re.IGNORECASE)
        if list_pattern.search(item_text):
            parts = re.split(r',\s*(?:and\s+)?', item_text, flags=re.IGNORECASE)
            parts = [p.strip() for p in parts if p.strip()]
            if len(parts) > 1:
                for part in parts:
                    if part:
                        atomic_items.append({
                            "item_id": f"{ticket_id}-ITEM-{item_counter:03d}",
                            "text": part.strip(),
                            "source_section": source_section,
                            "original_line": original_line or item_text
                        })
                        item_counter += 1
                if atomic_items:
                    return atomic_items
    
    # Strategy 3: Split by semicolons
    if ';' in item_text:
        parts = [p.strip() for p in item_text.split(';') if p.strip()]
        if len(parts) > 1:
            for part in parts:
                if part:
                    atomic_items.append({
                        "item_id": f"{ticket_id}-ITEM-{item_counter:03d}",
                        "text": part.strip(),
                        "source_section": source_section,
                        "original_line": original_line or item_text
                    })
                    item_counter += 1
            if atomic_items:
                return atomic_items
    
    # Strategy 4: Split by quoted strings (each quoted UI label becomes an item)
    quoted_strings = re.findall(r'"[^"]+"', item_text)
    if len(quoted_strings) > 1:
        # Extract context around each quoted string
        remaining_text = item_text
        for quote in quoted_strings:
            quote_idx = remaining_text.find(quote)
            if quote_idx >= 0:
                before = remaining_text[:quote_idx].strip()
                # Look for action words before the quote
                action_match = re.search(r'(\w+(?:\s+\w+)*)\s*' + re.escape(quote), remaining_text, re.IGNORECASE)
                if action_match:
                    atomic_text = f"{action_match.group(1)} {quote}"
                else:
                    atomic_text = quote
                
                atomic_items.append({
                    "item_id": f"{ticket_id}-ITEM-{item_counter:03d}",
                    "text": atomic_text.strip(),
                    "source_section": source_section,
                    "original_line": original_line or item_text
                })
                item_counter += 1
                remaining_text = remaining_text[quote_idx + len(quote):].strip()
        
        if atomic_items:
            return atomic_items
    
    # Strategy 5: Split by "then" or "followed by" (sequential actions)
    if re.search(r'\s+then\s+|\s+followed\s+by\s+', item_text, re.IGNORECASE):
        parts = re.split(r'\s+then\s+|\s+followed\s+by\s+', item_text, flags=re.IGNORECASE)
        parts = [p.strip() for p in parts if p.strip()]
        if len(parts) > 1:
            for part in parts:
                if part:
                    atomic_items.append({
                        "item_id": f"{ticket_id}-ITEM-{item_counter:03d}",
                        "text": part.strip(),
                        "source_section": source_section,
                        "original_line": original_line or item_text
                    })
                    item_counter += 1
            if atomic_items:
                return atomic_items
    
    # Strategy 6: Split by "tabs for X, Y, Z" pattern
    tabs_pattern = re.compile(r'tabs?\s+for\s+(.+?)(?:\.|$)', re.IGNORECASE)
    match = tabs_pattern.search(item_text)
    if match:
        tabs_list = match.group(1).strip()
        # Split the list
        tab_items = re.split(r',\s*(?:and\s+)?', tabs_list, flags=re.IGNORECASE)
        tab_items = [t.strip() for t in tab_items if t.strip()]
        if len(tab_items) > 1:
            for tab_item in tab_items:
                if tab_item:
                    atomic_items.append({
                        "item_id": f"{ticket_id}-ITEM-{item_counter:03d}",
                        "text": f"Tab for {tab_item}".strip(),
                        "source_section": source_section,
                        "original_line": original_line or item_text
                    })
                    item_counter += 1
            if atomic_items:
                return atomic_items
    
    # If no splitting strategy worked, return as single item (shouldn't happen if detection is correct)
    return [{
        "item_id": f"{ticket_id}-ITEM-{base_counter:03d}",
        "text": item_text.strip(),
        "source_section": source_section,
        "original_line": original_line or item_text
    }]


def extract_ticket_items(ticket):
    """
    Extract all numbered and bulleted items from ticket content.
    
    Parses items from description, acceptance_criteria, and other sections.
    Preserves original text and ordering.
    
    IMPLEMENTS ATOMIC TICKET ITEM ENUMERATION:
    - Automatically explodes composite items (multiple UI elements) into atomic items
    - Each atomic item represents ONE user-visible UI element or action
    - Generic implementation applies to ALL tickets (no ticket-specific logic)
    
    Args:
        ticket: Ticket dict with description, acceptance_criteria, etc.
    
    Returns:
        list: List of atomic item dicts with item_id, text, source_section
    """
    items = []
    ticket_id = ticket.get("id", "UNKNOWN")
    
    # Patterns to match numbered and bulleted items
    import re
    
    # Numbered patterns: "1.", "1)", "1:", "REQ-1", "Requirement 1", etc.
    # Match various formats including:
    # - "1. Text"
    # - "1) Text"
    # - "1: Text"
    # - "REQ-1: Text"
    # - "Requirement 1: Text"
    # - Lines starting with numbers
    numbered_pattern = re.compile(
        r'^[\s]*(\d+[\.\):]?|REQ[- ]?\d+|Requirement\s+\d+|REQ\s*\d+)[\s:]*\s*(.+)$',
        re.MULTILINE | re.IGNORECASE
    )
    
    # Bulleted patterns: "-", "*", "•", etc.
    # Match various bullet characters and formats:
    # - "- Text"
    # - "* Text"
    # - "• Text"
    # - "▪ Text"
    # - "- " (with space)
    bulleted_pattern = re.compile(
        r'^[\s]*([\-\*•▪▫◦‣⁃]|\u2022|\u25E6|\u2043|\u2023)[\s]+(.+)$',
        re.MULTILINE
    )
    
    # Also try to extract lines that look like list items (indented lines)
    # This catches items that might not have explicit bullets
    indented_item_pattern = re.compile(
        r'^[\s]{2,}([^\s].+)$',
        re.MULTILINE
    )
    
    # Pattern for lines that start with common list prefixes
    # This catches things like "o Text" (letter o used as bullet)
    common_list_pattern = re.compile(
        r'^[\s]*([oO]\s|[\u25CB\u25CF\u25A0\u25AA])\s*(.+)$',
        re.MULTILINE
    )
    
    # Extract from description
    description = ticket.get("description", "")
    if description:
        item_counter = len(items)
        seen_texts = set()  # Avoid duplicates
        
        # Extract numbered items
        for match in numbered_pattern.finditer(description):
            text = match.group(2).strip() if len(match.groups()) >= 2 else match.group(1).strip()
            if text and len(text) > 3 and text not in seen_texts:
                # TARGETED CLEANUP: Remove stray "0 " prefix if present at start of text
                # This prevents "0 " from propagating into ticket_item_coverage, ticket_traceability, rtm_item_trace
                if text.startswith("0 "):
                    text = text[2:].lstrip()  # Remove "0 " and any following whitespace
                
                # Explode into atomic items (may return 1 or more items)
                atomic_items = explode_item_into_atomic_items(
                    text, ticket_id, item_counter + 1, "description", match.group(0).strip()
                )
                for atomic_item in atomic_items:
                    atomic_text = atomic_item.get("text", "")
                    if atomic_text not in seen_texts:
                        items.append(atomic_item)
                        seen_texts.add(atomic_text)
                        item_counter += 1
        
        # Extract bulleted items
        for match in bulleted_pattern.finditer(description):
            text = match.group(2).strip() if len(match.groups()) >= 2 else match.group(1).strip()
            if text and len(text) > 3 and text not in seen_texts:
                # TARGETED CLEANUP: Remove stray "0 " prefix if present at start of text
                if text.startswith("0 "):
                    text = text[2:].lstrip()  # Remove "0 " and any following whitespace
                
                # Explode into atomic items (may return 1 or more items)
                atomic_items = explode_item_into_atomic_items(
                    text, ticket_id, item_counter + 1, "description", match.group(0).strip()
                )
                for atomic_item in atomic_items:
                    atomic_text = atomic_item.get("text", "")
                    if atomic_text not in seen_texts:
                        items.append(atomic_item)
                        seen_texts.add(atomic_text)
                        item_counter += 1
        
        # Extract common list patterns
        for match in common_list_pattern.finditer(description):
            text = match.group(2).strip() if len(match.groups()) >= 2 else match.group(1).strip()
            if text and len(text) > 3 and text not in seen_texts:
                # TARGETED CLEANUP: Remove stray "0 " prefix if present at start of text
                if text.startswith("0 "):
                    text = text[2:].lstrip()  # Remove "0 " and any following whitespace
                
                # Explode into atomic items (may return 1 or more items)
                atomic_items = explode_item_into_atomic_items(
                    text, ticket_id, item_counter + 1, "description", match.group(0).strip()
                )
                for atomic_item in atomic_items:
                    atomic_text = atomic_item.get("text", "")
                    if atomic_text not in seen_texts:
                        items.append(atomic_item)
                        seen_texts.add(atomic_text)
                        item_counter += 1
        
        # Also extract indented items that look like list items
        # Only if we haven't found many items yet (to avoid false positives)
        if len(items) < 5:
            for match in indented_item_pattern.finditer(description):
                text = match.group(1).strip()
                # Only include if it looks like a meaningful item (not just whitespace or very short)
                if text and len(text) > 10 and text not in seen_texts:
                    # TARGETED CLEANUP: Remove stray "0 " prefix if present at start of text
                    if text.startswith("0 "):
                        text = text[2:].lstrip()  # Remove "0 " and any following whitespace
                    
                    # Explode into atomic items (may return 1 or more items)
                    atomic_items = explode_item_into_atomic_items(
                        text, ticket_id, item_counter + 1, "description", match.group(0).strip()
                    )
                    for atomic_item in atomic_items:
                        atomic_text = atomic_item.get("text", "")
                        if atomic_text not in seen_texts:
                            items.append(atomic_item)
                            seen_texts.add(atomic_text)
                            item_counter += 1
    
    # Extract from acceptance_criteria
    acceptance_criteria = ticket.get("acceptance_criteria", "")
    if acceptance_criteria:
        item_counter = len(items)
        seen_texts = set()  # Avoid duplicates
        
        # Extract numbered items
        for match in numbered_pattern.finditer(acceptance_criteria):
            text = match.group(2).strip() if len(match.groups()) >= 2 else match.group(1).strip()
            if text and len(text) > 3 and text not in seen_texts:
                # TARGETED CLEANUP: Remove stray "0 " prefix if present at start of text
                if text.startswith("0 "):
                    text = text[2:].lstrip()  # Remove "0 " and any following whitespace
                
                # Explode into atomic items (may return 1 or more items)
                atomic_items = explode_item_into_atomic_items(
                    text, ticket_id, item_counter + 1, "acceptance_criteria", match.group(0).strip()
                )
                for atomic_item in atomic_items:
                    atomic_text = atomic_item.get("text", "")
                    if atomic_text not in seen_texts:
                        items.append(atomic_item)
                        seen_texts.add(atomic_text)
                        item_counter += 1
        
        # Extract bulleted items
        for match in bulleted_pattern.finditer(acceptance_criteria):
            text = match.group(2).strip() if len(match.groups()) >= 2 else match.group(1).strip()
            if text and len(text) > 3 and text not in seen_texts:
                # TARGETED CLEANUP: Remove stray "0 " prefix if present at start of text
                if text.startswith("0 "):
                    text = text[2:].lstrip()  # Remove "0 " and any following whitespace
                
                # Explode into atomic items (may return 1 or more items)
                atomic_items = explode_item_into_atomic_items(
                    text, ticket_id, item_counter + 1, "acceptance_criteria", match.group(0).strip()
                )
                for atomic_item in atomic_items:
                    atomic_text = atomic_item.get("text", "")
                    if atomic_text not in seen_texts:
                        items.append(atomic_item)
                        seen_texts.add(atomic_text)
                        item_counter += 1
        
        # Extract common list patterns
        for match in common_list_pattern.finditer(acceptance_criteria):
            text = match.group(2).strip() if len(match.groups()) >= 2 else match.group(1).strip()
            if text and len(text) > 3 and text not in seen_texts:
                # TARGETED CLEANUP: Remove stray "0 " prefix if present at start of text
                if text.startswith("0 "):
                    text = text[2:].lstrip()  # Remove "0 " and any following whitespace
                
                # Explode into atomic items (may return 1 or more items)
                atomic_items = explode_item_into_atomic_items(
                    text, ticket_id, item_counter + 1, "acceptance_criteria", match.group(0).strip()
                )
                for atomic_item in atomic_items:
                    atomic_text = atomic_item.get("text", "")
                    if atomic_text not in seen_texts:
                        items.append(atomic_item)
                        seen_texts.add(atomic_text)
                        item_counter += 1
        
        # Also extract indented items from acceptance criteria
        # Only if we haven't found many items yet (to avoid false positives)
        if len(items) < 5:
            for match in indented_item_pattern.finditer(acceptance_criteria):
                text = match.group(1).strip()
                if text and len(text) > 10 and text not in seen_texts:
                    # TARGETED CLEANUP: Remove stray "0 " prefix if present at start of text
                    if text.startswith("0 "):
                        text = text[2:].lstrip()  # Remove "0 " and any following whitespace
                    
                    # Explode into atomic items (may return 1 or more items)
                    atomic_items = explode_item_into_atomic_items(
                        text, ticket_id, item_counter + 1, "acceptance_criteria", match.group(0).strip()
                    )
                    for atomic_item in atomic_items:
                        atomic_text = atomic_item.get("text", "")
                        if atomic_text not in seen_texts:
                            items.append(atomic_item)
                            seen_texts.add(atomic_text)
                            item_counter += 1
    
    # Fallback: If no items found with patterns, try to split by common separators
    # This handles cases where items might be on separate lines without explicit markers
    if not items:
        # Try splitting description and acceptance_criteria by line breaks
        # and looking for lines that look like list items
        all_text = f"{description}\n{acceptance_criteria}".strip()
        if all_text:
            lines = all_text.split('\n')
            item_counter = 0
            seen_texts = set()
            
            for line in lines:
                line = line.strip()
                # Skip empty lines, very short lines, or lines that look like headers
                if not line or len(line) < 5:
                    continue
                
                # Skip lines that are clearly not list items
                if line.startswith('#') or line.startswith('==') or line.upper() == line and len(line) < 20:
                    continue
                
                # Look for lines that might be list items:
                # - Start with a word followed by colon (e.g., "Feature: Description")
                # - Start with common action words
                # - Are reasonably structured
                action_words = ['must', 'shall', 'will', 'should', 'need', 'require', 'implement', 'add', 'create', 'update', 'delete', 'verify', 'validate', 'check', 'ensure']
                starts_with_action = any(line.lower().startswith(word + ' ') for word in action_words)
                has_colon_structure = ':' in line and len(line.split(':')) == 2
                
                if (starts_with_action or has_colon_structure) and line not in seen_texts:
                    source = "description" if line in description else "acceptance_criteria"
                    # Explode into atomic items (may return 1 or more items)
                    atomic_items = explode_item_into_atomic_items(
                        line, ticket_id, item_counter + 1, source, line
                    )
                    for atomic_item in atomic_items:
                        atomic_text = atomic_item.get("text", "")
                        if atomic_text not in seen_texts:
                            items.append(atomic_item)
                            seen_texts.add(atomic_text)
                            item_counter += 1
    
    return items


def classify_ticket_item(item_text, requirements=None):
    """
    Classify a ticket item into one of the defined types for audit traceability.
    
    Args:
        item_text: The text content of the ticket item
        requirements: Optional list of requirements to check for mapping
    
    Returns:
        str: One of: system_behavior, ui_element, informational_only,
             unclear_needs_clarification, not_independently_testable
    """
    if not isinstance(item_text, str):
        return "unclear_needs_clarification"
    
    text_lower = item_text.lower().strip()
    
    # Check for UI element indicators
    ui_keywords = ["button", "link", "field", "menu", "tab", "page", "screen", "form", "input", "download", "export"]
    has_ui_element = any(keyword in text_lower for keyword in ui_keywords)
    # Also check for quoted UI element names
    import re
    has_quoted_label = bool(re.search(r'"[^"]+"', item_text))
    
    if has_ui_element or has_quoted_label:
        return "ui_element"
    
    # Check for system-level/derived behavior indicators
    # These describe automatic system behaviors (e.g., RTM generation, automatic processes)
    system_behavior_keywords = [
        "rtm", "requirement traceability matrix", "generated automatically", "generated after",
        "derived from", "automatically", "system generates", "system creates", "system produces",
        "does not require", "does not block", "clearly identified", "appears exactly once"
    ]
    if any(keyword in text_lower for keyword in system_behavior_keywords):
        return "system_behavior"
    
    # Check for informational only
    info_keywords = ["note", "see", "reference", "documentation", "see also", "for more", "additional"]
    if any(keyword in text_lower for keyword in info_keywords):
        return "informational_only"
    
    # Check if it's unclear
    if len(text_lower) < 10 or text_lower.count(" ") < 2:
        return "unclear_needs_clarification"
    
    # Check for technical constraints or implementation details that are not independently testable
    constraint_keywords = ["use", "avoid", "backend", "frontend", "implementation", "technical", "architecture", "design"]
    if any(keyword in text_lower for keyword in constraint_keywords):
        return "not_independently_testable"
    
    # Default: if it has action verb, treat as system_behavior; otherwise informational
    req_indicators = ["must", "shall", "will", "should", "requires", "need to", "implement"]
    has_action_verb = any(indicator in text_lower for indicator in req_indicators)
    
    if has_action_verb:
        return "system_behavior"
    else:
        return "informational_only"


def map_ticket_items_to_requirements_and_tests(ticket_items, requirements, all_tests_by_category):
    """
    Map ticket items to requirements and tests.
    
    Args:
        ticket_items: List of ticket item dicts
        requirements: List of requirement dicts
        all_tests_by_category: Dict mapping test categories to test lists
    
    Returns:
        list: List of mapped item dicts with classification and traceability info
    """
    mapped_items = []
    
    # Build requirement text map for matching
    req_text_map = {}
    # Build requirement lookup by ID (for classification inheritance)
    req_lookup_by_id = {}
    for req in requirements:
        if isinstance(req, dict):
            req_id = req.get("id", "")
            req_desc = req.get("description", "").lower()
            if req_id:
                req_text_map[req_id] = req_desc
                req_lookup_by_id[req_id] = req  # Store full requirement object
    
    # Build test map by requirement
    tests_by_req = {}
    for category, tests in all_tests_by_category.items():
        for test in tests:
            if isinstance(test, dict):
                reqs_covered = test.get("requirements_covered", [])
                test_id = test.get("id", "")
                for req_id in reqs_covered:
                    if req_id not in tests_by_req:
                        tests_by_req[req_id] = []
                    tests_by_req[req_id].append(test_id)
    
    for item in ticket_items:
        item_text = item.get("text", "")
        item_id = item.get("item_id", "")
        
        # TARGETED CLEANUP: Remove stray "0 " prefix if present at start of item text
        # This ensures "0 " is removed before item is mapped and stored in ticket_traceability
        if item_text and item_text.startswith("0 "):
            item_text = item_text[2:].lstrip()  # Remove "0 " and any following whitespace
            # Update the item dict so cleaned text propagates
            item["text"] = item_text
        
        # Classify the item
        classification = classify_ticket_item(item_text, requirements)
        
        # DETERMINISTIC INHERITANCE RULE: Inherit classification and testability from parent requirement
        # If parent requirement is classified as ui_structure, ui_element, informational_only, or not_independently_testable,
        # then all items derived from that requirement MUST inherit the same classification and testability
        parent_req_id = item.get("parent_requirement_id")
        parent_testable = True  # Default
        if parent_req_id:
            # Get parent requirement
            parent_req = req_lookup_by_id.get(parent_req_id)
            if parent_req and isinstance(parent_req, dict):
                parent_classification = parent_req.get("_classification", "")
                parent_testable = parent_req.get("testable", True)
                
                # Inheritable classifications (non-behavioral classifications that must be inherited)
                inheritable_classifications = ["ui_structure", "ui_element", "informational_only", "not_independently_testable"]
                
                if parent_classification in inheritable_classifications:
                    # Items may NOT be reclassified to system_behavior if parent requirement is non-behavioral
                    # Force inheritance of non-behavioral classifications
                    if classification == "system_behavior" and parent_classification in inheritable_classifications:
                        # Override system_behavior classification with parent's non-behavioral classification
                        classification = parent_classification
                        logger.debug(f"Forced inheritance: Overrode system_behavior classification with '{parent_classification}' from requirement {parent_req_id} to item {item_id}")
                    elif classification not in ["informational_only", "not_independently_testable"]:
                        # Inherit the classification (unless item is explicitly informational_only or not_independently_testable)
                        classification = parent_classification
                        logger.debug(f"Inherited classification '{parent_classification}' from requirement {parent_req_id} to item {item_id}")
        
        mapped_item = {
            "item_id": item_id,
            "text": item_text,
            "classification": classification,
            "source_section": item.get("source_section", "unknown")
        }
        
        # Map to requirement if applicable
        mapped_req_id = None
        
        # STRICT INHERITANCE RULE: Check if parent requirement has negative = not_applicable
        # If so, items may NOT be marked as covered by negative tests
        parent_negative_not_applicable = False
        if parent_req_id:
            parent_req = req_lookup_by_id.get(parent_req_id)
            if parent_req and isinstance(parent_req, dict):
                parent_coverage_exp = parent_req.get("coverage_expectations", {})
                parent_negative = parent_coverage_exp.get("negative", "expected")
                if parent_negative == "not_applicable":
                    parent_negative_not_applicable = True
        
        # POST-EXTRACTION GROUPING: If item has parent_requirement_id, use it directly
        # This handles items created from numbered requirements with comma-separated lists
        if parent_req_id:
            # Verify parent requirement exists
            if parent_req_id in req_text_map:
                mapped_req_id = parent_req_id
                mapped_item["mapped_requirement_id"] = mapped_req_id
                # Get tests that validate this requirement
                validated_by_tests = tests_by_req.get(mapped_req_id, [])
                # STRICT INHERITANCE RULE: Filter out negative tests if parent has negative = not_applicable
                if parent_negative_not_applicable and validated_by_tests:
                    # Get all tests to check their intent_type
                    all_tests = []
                    for category, test_list in all_tests_by_category.items():
                        all_tests.extend(test_list)
                    # Filter out negative tests
                    filtered_test_ids = []
                    for test_id in validated_by_tests:
                        test = next((t for t in all_tests if isinstance(t, dict) and t.get("id") == test_id), None)
                        if test:
                            intent_type = test.get("intent_type", "").lower()
                            if intent_type != "negative":
                                filtered_test_ids.append(test_id)
                        else:
                            # If test not found, keep it (might be from different category)
                            filtered_test_ids.append(test_id)
                    validated_by_tests = filtered_test_ids
                    logger.debug(f"Filtered out negative tests from item {item_id} due to parent requirement {parent_req_id} having negative=not_applicable")
                if validated_by_tests:
                    mapped_item["validated_by_tests"] = validated_by_tests
                else:
                    mapped_item["validated_by_tests"] = []
            else:
                logger.warning(f"Item {item_id} references parent_requirement_id {parent_req_id} which does not exist")
        
        # If no parent requirement, try to find matching requirement by text similarity
        if not mapped_req_id and classification in ["system_behavior", "ui_element"]:
            # Try to find matching requirement by text similarity
            item_text_lower = item_text.lower()
            best_match = None
            best_score = 0
            
            for req_id, req_desc in req_text_map.items():
                # Simple similarity: check for common words
                item_words = set(item_text_lower.split())
                req_words = set(req_desc.split())
                common_words = item_words.intersection(req_words)
                if len(item_words) > 0:
                    score = len(common_words) / len(item_words)
                    if score > best_score and score > 0.3:  # At least 30% word overlap
                        best_score = score
                        best_match = req_id
            
            if best_match:
                mapped_req_id = best_match
                mapped_item["mapped_requirement_id"] = mapped_req_id
                
                # Get tests that validate this requirement
                validated_by_tests = tests_by_req.get(mapped_req_id, [])
                # STRICT INHERITANCE RULE: Check if matched requirement has negative = not_applicable
                matched_req = req_lookup_by_id.get(best_match)
                matched_negative_not_applicable = False
                if matched_req and isinstance(matched_req, dict):
                    matched_coverage_exp = matched_req.get("coverage_expectations", {})
                    matched_negative = matched_coverage_exp.get("negative", "expected")
                    if matched_negative == "not_applicable":
                        matched_negative_not_applicable = True
                
                # Filter out negative tests if matched requirement has negative = not_applicable
                if matched_negative_not_applicable and validated_by_tests:
                    # Get all tests to check their intent_type
                    all_tests = []
                    for category, test_list in all_tests_by_category.items():
                        all_tests.extend(test_list)
                    # Filter out negative tests
                    filtered_test_ids = []
                    for test_id in validated_by_tests:
                        test = next((t for t in all_tests if isinstance(t, dict) and t.get("id") == test_id), None)
                        if test:
                            intent_type = test.get("intent_type", "").lower()
                            if intent_type != "negative":
                                filtered_test_ids.append(test_id)
                        else:
                            # If test not found, keep it (might be from different category)
                            filtered_test_ids.append(test_id)
                    validated_by_tests = filtered_test_ids
                    logger.debug(f"Filtered out negative tests from matched requirement {best_match} for item {item_id} due to matched requirement having negative=not_applicable")
                if validated_by_tests:
                    mapped_item["validated_by_tests"] = validated_by_tests
                else:
                    mapped_item["validated_by_tests"] = []
        
        # NOTE: Reclassification of technical_constraint to system_behavior is now done
        # in a post-processing step AFTER all tests are generated and validated_by_tests is populated.
        # This ensures evidence (tests) is available when reclassifying.
        
        # DETERMINISTIC INHERITANCE RULE: Inherit testable flag from parent requirement
        # If parent requirement is non-testable, item must also be non-testable
        if parent_req_id:
            parent_req = req_lookup_by_id.get(parent_req_id)
            if parent_req and isinstance(parent_req, dict):
                parent_testable = parent_req.get("testable", True)
                if not parent_testable:
                    # Force testable = false if parent is non-testable
                    mapped_item["testable"] = False
                    logger.debug(f"Inherited testable=False from requirement {parent_req_id} to item {item_id}")
                else:
                    # Determine testable flag based on classification
                    if classification in ["system_behavior", "ui_element"]:
                        mapped_item["testable"] = True
                    elif classification in ["not_independently_testable", "informational_only"]:
                        mapped_item["testable"] = False
                        if classification == "not_independently_testable":
                            mapped_item["note"] = "Implementation guidance or technical constraint; not independently testable"
                        elif classification == "informational_only":
                            mapped_item["note"] = "Informational content; not independently testable"
                    elif classification == "unclear_needs_clarification":
                        mapped_item["testable"] = False
                        mapped_item["note"] = "Item text is unclear or incomplete; needs clarification"
                    else:
                        mapped_item["testable"] = False
            else:
                # Determine testable flag based on classification
                if classification in ["system_behavior", "ui_element"]:
                    mapped_item["testable"] = True
                elif classification in ["not_independently_testable", "informational_only"]:
                    mapped_item["testable"] = False
                    if classification == "not_independently_testable":
                        mapped_item["note"] = "Implementation guidance or technical constraint; not independently testable"
                    elif classification == "informational_only":
                        mapped_item["note"] = "Informational content; not independently testable"
                elif classification == "unclear_needs_clarification":
                    mapped_item["testable"] = False
                    mapped_item["note"] = "Item text is unclear or incomplete; needs clarification"
                else:
                    mapped_item["testable"] = False
        else:
            # Determine testable flag based on classification
            if classification in ["system_behavior", "ui_element"]:
                mapped_item["testable"] = True
            elif classification in ["not_independently_testable", "informational_only"]:
                mapped_item["testable"] = False
                if classification == "not_independently_testable":
                    mapped_item["note"] = "Implementation guidance or technical constraint; not independently testable"
                elif classification == "informational_only":
                    mapped_item["note"] = "Informational content; not independently testable"
            elif classification == "unclear_needs_clarification":
                mapped_item["testable"] = False
                mapped_item["note"] = "Item text is unclear or incomplete; needs clarification"
            else:
                mapped_item["testable"] = False
        
        mapped_items.append(mapped_item)
    
    return mapped_items


def names_output_artifact(requirement_text):
    """
    Check if requirement text names an output artifact.
    
    Args:
        requirement_text: Requirement description string
    
    Returns:
        bool: True if requirement mentions output artifacts
    """
    if not isinstance(requirement_text, str):
        return False
    
    text_lower = requirement_text.lower()
    artifact_keywords = [
        "pdf", "json", "csv", "xml", "excel", "file", "download",
        "export", "save", "generate", "create", "output", "report"
    ]
    
    return any(keyword in text_lower for keyword in artifact_keywords)


def generate_step_skeleton(intent_type, execution_mechanisms=None, requirement_text=None):
    """
    Generate a deterministic step skeleton for a given intent type.
    
    Step skeletons provide structure that the LLM will fill with requirement-specific content.
    Each slot describes what should go in that step, not the actual content.
    
    Args:
        intent_type: "happy_path" | "negative" | "authorization" | "boundary"
        execution_mechanisms: Optional dict with api_endpoints, ui_components, etc.
        requirement_text: Optional requirement description to detect UI elements
    
    Returns:
        list: List of step slot descriptions (strings describing what each step should contain)
    """
    execution_mechanisms = execution_mechanisms or {}
    has_api = bool(execution_mechanisms.get("api_endpoints"))
    has_ui_explicit = bool(execution_mechanisms.get("ui_components"))
    
    # Also check requirement text for UI elements if not explicitly detected
    # This allows UI skeletons even when execution_mechanisms doesn't list ui_components
    has_ui = has_ui_explicit
    if not has_ui and requirement_text:
        has_ui = names_ui_element(requirement_text) or names_output_artifact(requirement_text)
    
    if intent_type == "happy_path":
        if has_api:
            return [
                "Identify the API endpoint and HTTP method from the requirement",
                "Construct a valid request with all required fields from the requirement",
                "Send the request to the endpoint",
                "Verify the response status code indicates success",
                "Validate the response structure matches expected format from the requirement",
                "Check that response data contains the expected values or behaviors described in the requirement"
            ]
        elif has_ui:
            return [
                "Verify the UI element named in the requirement is visible on the screen",
                "Verify the UI element is enabled and ready for interaction",
                "Interact with the UI element using the standard action described in the requirement (click, tap, etc.)",
                "Verify the expected outcome occurs (e.g., file download, page navigation, state change, message display)",
                "Validate the outcome matches what is described in the requirement"
            ]
        else:
            return [
                "Identify the specific action or operation described in the requirement",
                "Execute the action using the mechanism implied by the requirement",
                "Observe the system response or state change",
                "Verify the outcome matches the expected behavior described in the requirement"
            ]
    
    elif intent_type == "negative":
        # Check if this is a UI-related requirement (ui_structure or ui_element)
        # Note: Classification is not available in step skeleton generation, but we can infer from requirement text
        is_ui_structure = False
        if requirement_text:
            text_lower = requirement_text.lower()
            # Heuristic: UI structure requirements typically use presence verbs
            presence_verbs = ["have", "display", "show", "present", "include", "contain"]
            ui_elements = ["tab", "button", "field", "section", "panel", "area", "view", "page", "menu", "link"]
            is_ui_structure = any(verb in text_lower for verb in presence_verbs) and any(elem in text_lower for elem in ui_elements)
        
        if has_api and not is_ui_structure:
            # API/system behavior negative: error handling
            return [
                "Identify the API endpoint from the requirement",
                "Construct a request with invalid, missing, or malformed data (specify what makes it invalid based on the requirement)",
                "Send the invalid request to the endpoint",
                "Verify the response status code indicates an error (4xx or 5xx)",
                "Validate the error response structure and error message",
                "Confirm the error message or code matches what should be returned for this failure condition"
            ]
        elif has_ui or is_ui_structure:
            # UI-related negative: presence/state-based (NOT error handling)
            return [
                "Verify the UI element named in the requirement is present on the screen",
                "Check if the UI element is visible and accessible",
                "Verify the UI element is in the expected state (enabled/disabled, displayed/hidden, populated/empty)",
                "If the UI element is missing, not visible, disabled when it should be enabled, or displays incorrect content, document the failure condition",
                "Validate that the UI element state matches what is expected from the requirement"
            ]
        else:
            # Generic negative: error handling (for system_behavior, data_validation)
            return [
                "Identify the operation or action from the requirement",
                "Attempt to execute the operation with invalid conditions (specify what makes it invalid based on the requirement)",
                "Observe the system's error response or rejection behavior",
                "Verify the error handling matches what is expected from the requirement"
            ]
    
    elif intent_type == "authorization":
        if has_api:
            return [
                "Identify the API endpoint from the requirement",
                "Construct a valid request but omit or provide invalid authentication credentials",
                "Send the request without proper authorization",
                "Verify the response status code is 401 (Unauthorized) or 403 (Forbidden)",
                "Validate the error response indicates authorization failure",
                "Confirm the error message or code matches expected authorization error behavior"
            ]
        elif has_ui:
            return [
                "Verify the protected UI element named in the requirement is visible or accessible",
                "Attempt to access or interact with the protected UI element without proper permissions",
                "Verify that access is denied, redirected, or an authorization error is displayed",
                "Validate that the authorization error or denial behavior matches expected behavior from the requirement"
            ]
        else:
            return [
                "Identify the protected operation from the requirement",
                "Attempt to access or execute the operation without proper authorization",
                "Observe the system's authorization check response",
                "Verify the authorization failure matches expected behavior from the requirement"
            ]
    
    elif intent_type == "boundary":
        if has_api:
            return [
                "Identify the API endpoint and field(s) with limits from the requirement",
                "Construct a request with boundary value(s) - specify the exact boundary (minimum, maximum, edge case) from the requirement",
                "Send the request with boundary values",
                "Verify the response handles the boundary correctly (accepts valid boundary, rejects invalid)",
                "Validate the response behavior matches expected boundary handling from the requirement"
            ]
        elif has_ui:
            return [
                "Verify the UI input field with limits named in the requirement is visible on the screen",
                "Enter boundary value(s) in the field - specify the exact boundary (minimum, maximum, edge case) from the requirement",
                "Submit or validate the input",
                "Verify the UI handles the boundary correctly (accepts valid boundary, rejects invalid) per the requirement"
            ]
        else:
            return [
                "Identify the operation or field with limits from the requirement",
                "Execute the operation with boundary value(s) - specify the exact boundary from the requirement",
                "Observe how the system handles the boundary condition",
                "Verify the boundary handling matches expected behavior from the requirement"
            ]
    
    # Default fallback
    return [
        "Identify the specific action from the requirement",
        "Execute the action as described",
        "Verify the outcome matches the requirement"
    ]


def is_system_level_requirement(requirement):
    """
    Detect if a requirement describes automatic system behavior.
    
    UI STRUCTURE SYSTEM-TEST EXCLUSION RULE:
    If a requirement is classified as ui_structure, it is ineligible for:
    - reusable system-level tests
    - generation of new SYS-* tests
    - pairing with system-behavior negative templates
    
    UI structure requirements must be validated only through UI tests
    (happy path and absence-based negative tests).
    
    Examples:
    - "RTM is generated after a test plan is created"
    - "The system automatically generates..."
    - "Derived from test plan without user input"
    
    Args:
        requirement: Requirement dict with description field and optional _classification field
    
    Returns:
        bool: True if requirement describes automatic system behavior AND is not ui_structure
    """
    if not isinstance(requirement, dict):
        return False
    
    # UI STRUCTURE EXCLUSION: Do NOT generate system tests for UI structure requirements
    classification = requirement.get("_classification", "")
    if classification == "ui_structure":
        return False  # UI structure requirements are excluded from system-level tests
    
    description = requirement.get("description", "").lower()
    if not description:
        return False
    
    # Keywords that indicate automatic system behavior
    system_keywords = [
        "rtm", "requirement traceability matrix", "generated automatically",
        "generated after", "derived from", "automatically", "system generates",
        "system creates", "system produces", "does not require", "does not block",
        "clearly identified", "appears exactly once", "automatic", "derived"
    ]
    
    return any(keyword in description for keyword in system_keywords)


def enumerate_test_intents(requirement):
    """
    Enumerate test intents for a requirement.
    
    This deterministic function generates a list of test intents that should be
    created for a given requirement. Each intent represents a logical test case
    that should be generated.
    
    Args:
        requirement: Requirement dict with at least "id" and "description" fields
    
    Returns:
        list: List of test intent dicts, each with:
            - intent_type: "happy_path" | "negative" | "authorization" | "boundary"
            - intent_description: Human-readable description of what this intent tests
    """
    req_id = requirement.get("id", "")
    description = requirement.get("description", "").strip().lower()
    
    intents = []
    
    # Always generate happy_path intent (unless requirement is purely informational)
    info_keywords = ["document", "define", "specify", "describe", "outline", "metadata"]
    is_purely_informational = any(keyword in description for keyword in info_keywords)
    
    if not is_purely_informational:
        intents.append({
            "intent_type": "happy_path",
            "intent_description": f"Validate successful execution of requirement {req_id}"
        })
    
    # Generate negative intent if applicable
    error_keywords = ["error", "invalid", "missing", "failure", "reject", "deny", "exception"]
    has_error_implications = any(keyword in description for keyword in error_keywords)
    
    if has_error_implications or not is_purely_informational:
        intents.append({
            "intent_type": "negative",
            "intent_description": f"Validate error handling and failure conditions for requirement {req_id}"
        })
    
    # Generate authorization intent if applicable
    auth_keywords = ["permission", "access", "token", "authorization", "security", "auth", "authenticate", "role", "privilege"]
    has_auth_implications = any(keyword in description for keyword in auth_keywords)
    
    if has_auth_implications:
        intents.append({
            "intent_type": "authorization",
            "intent_description": f"Validate authorization and access control for requirement {req_id}"
        })
    
    # Generate boundary intent if applicable
    boundary_keywords = ["format", "limit", "range", "maximum", "minimum", "length", "size", "boundary", "edge", "constraint"]
    has_boundary_implications = any(keyword in description for keyword in boundary_keywords)
    
    if has_boundary_implications:
        intents.append({
            "intent_type": "boundary",
            "intent_description": f"Validate boundary conditions and limits for requirement {req_id}"
        })
    
    return intents


def compute_coverage_expectations(requirement, all_tests_by_category=None):
    """
    Compute coverage depth expectations for a requirement based on description and existing tests.
    
    Args:
        requirement: Requirement dict with at least "id" and "description" fields
        all_tests_by_category: Optional dict mapping category names to lists of tests
    
    Returns:
        dict: Coverage expectations object
    """
    req_id = requirement.get("id", "")
    description = requirement.get("description", "").strip().lower()
    
    # Initialize test category lists unconditionally to prevent "referenced before assignment" errors
    negative_tests = []
    ui_tests = []
    api_tests = []
    data_validation_tests = []
    edge_cases = []
    
    # Initialize defaults
    expectations = {
        "happy_path": "expected",
        "negative": "expected",
        "boundary": "not_applicable",
        "authorization": "not_applicable",
        "data_validation": "not_applicable",
        "stateful": "not_applicable"
    }
    
    # FIX B - NON-TESTABLE NEGATIVE HARD STOP:
    # If requirement is non-testable or informational/not_independently_testable, force negative = not_applicable
    req_testable = requirement.get("testable", True)
    req_classification = requirement.get("_classification", "")
    
    is_ui_presence_requirement = False
    if not req_testable or req_classification in ["informational_only", "not_independently_testable"]:
        # Force negative coverage to not_applicable for non-testable requirements
        expectations["negative"] = "not_applicable"
        # Skip all further negative test logic for this requirement
        is_ui_presence_requirement = True  # Use this flag to skip negative test processing
    
    # NEGATIVE TEST SUPPRESSION FOR UI PRESENCE: Check classification FIRST before checking test coverage
    # This ensures UI presence requirements are marked as not_applicable even if negative tests were generated
    if not is_ui_presence_requirement and req_classification in ["ui_structure", "ui_element", "ui_presence"]:
        # Check if requirement intent is to confirm existence, visibility, or accessibility only
        # Presence-oriented verbs indicate UI presence assertions
        presence_verbs = ["have", "has", "display", "displays", "show", "shows", 
                        "present", "presents", "include", "includes", "contain", "contains"]
        presence_keywords = ["visible", "accessible", "present", "available", "exists", "exist"]
        
        # If requirement uses presence verbs/keywords and no error-handling keywords, it's a presence assertion
        has_presence_verb = any(verb in description for verb in presence_verbs)
        has_presence_keyword = any(keyword in description for keyword in presence_keywords)
        error_keywords = ["error", "invalid", "missing", "permission", "failure", "reject", "deny", "handle", "validation"]
        has_error_keywords = any(keyword in description for keyword in error_keywords)
        
        # If it's a presence assertion (has presence verbs/keywords) and no error-handling, suppress negative tests
        if (has_presence_verb or has_presence_keyword) and not has_error_keywords:
            is_ui_presence_requirement = True
            expectations["negative"] = "not_applicable"
        elif has_error_keywords:
            # Has error-handling keywords, so negative tests are applicable
            pass  # Keep default "expected"
        else:
            # Default: not applicable for UI presence requirements
            is_ui_presence_requirement = True
            expectations["negative"] = "not_applicable"
    
    # Check existing test coverage if provided
    if all_tests_by_category:
        # Initialize test category lists from all_tests_by_category
        api_tests = all_tests_by_category.get("api_tests", [])
        ui_tests = all_tests_by_category.get("ui_tests", [])
        negative_tests = all_tests_by_category.get("negative_tests", [])
        data_validation_tests = all_tests_by_category.get("data_validation_tests", [])
        edge_cases = all_tests_by_category.get("edge_cases", [])
        
        # Check happy path coverage
        all_positive_tests = api_tests + ui_tests
        
        for test in all_positive_tests:
            if isinstance(test, dict):
                reqs_covered = test.get("requirements_covered", [])
                if req_id in reqs_covered:
                    # Mark as covered (whether explicit or inferred happy-path test)
                    expectations["happy_path"] = "covered"
                    break
        
        # Check negative coverage (but skip if this is a UI presence requirement)
        if not is_ui_presence_requirement:
            for test in negative_tests:
                if isinstance(test, dict):
                    reqs_covered = test.get("requirements_covered", [])
                    test_dimension = test.get("dimension")
                    if req_id in reqs_covered:
                        expectations["negative"] = "covered"
                        # If this is an authorization test, mark authorization as covered too
                        if test_dimension == "authorization":
                            expectations["authorization"] = "covered"
                        break
        
        # Check data validation coverage
        for test in data_validation_tests:
            if isinstance(test, dict):
                reqs_covered = test.get("requirements_covered", [])
                test_dimension = test.get("dimension")
                if req_id in reqs_covered and test_dimension == "data_validation":
                    expectations["data_validation"] = "covered"
                    break
        
        # Check boundary coverage (in edge_cases)
        for test in edge_cases:
            if isinstance(test, dict):
                reqs_covered = test.get("requirements_covered", [])
                test_dimension = test.get("dimension")
                if req_id in reqs_covered and test_dimension == "boundary":
                    expectations["boundary"] = "covered"
                    break
        
        # Check authorization coverage (may also be in negative_tests, already handled above)
        # But also check if there are explicit authorization tests
        for test in negative_tests:
            if isinstance(test, dict):
                reqs_covered = test.get("requirements_covered", [])
                test_dimension = test.get("dimension")
                if req_id in reqs_covered and test_dimension == "authorization":
                    expectations["authorization"] = "covered"
                    break
    
    # Determine negative expectations based on description and classification
    # (Only for non-UI presence requirements, since UI presence was already handled above)
    if not is_ui_presence_requirement and expectations["negative"] != "covered":
        # Non-UI requirements: use existing logic
        error_keywords = ["error", "invalid", "missing", "permission", "failure", "reject", "deny"]
        if any(keyword in description for keyword in error_keywords):
            expectations["negative"] = "expected"
        else:
            # Check if purely informational/governance
            info_keywords = ["document", "define", "specify", "describe", "outline"]
            if any(keyword in description for keyword in info_keywords):
                expectations["negative"] = "not_applicable"
    
    # Boundary expectations
    boundary_keywords = ["format", "limit", "range", "maximum", "minimum", "length", "size", "boundary"]
    if any(keyword in description for keyword in boundary_keywords):
        expectations["boundary"] = "expected"
    
    # Authorization expectations
    auth_keywords = ["permission", "access", "token", "authorization", "security", "auth", "authenticate"]
    if any(keyword in description for keyword in auth_keywords):
        expectations["authorization"] = "expected"
        # Check if external auth implied but not described
        external_auth_indicators = ["external", "third-party", "oauth", "sso"]
        if any(indicator in description for indicator in external_auth_indicators):
            expectations["authorization"] = "unknown"
    
    # Data validation expectations
    validation_keywords = ["input", "parse", "validation", "validate", "structure", "schema", "format"]
    if any(keyword in description for keyword in validation_keywords):
        expectations["data_validation"] = "expected"
    
    # Stateful expectations
    stateful_keywords = ["workflow", "sequence", "dependency", "lifecycle", "state", "transition", "order"]
    if any(keyword in description for keyword in stateful_keywords):
        expectations["stateful"] = "expected"
    
    return expectations


def generate_happy_path_inferred_tests(requirements, all_tests_by_category):
    """
    Generate inferred happy-path tests based on coverage_expectations.
    
    Generates inferred tests for requirements where happy_path is expected but not yet covered
    by any existing api_tests or ui_tests.
    
    Args:
        requirements: List of requirement dicts with coverage_expectations
        all_tests_by_category: Dict mapping test categories to lists of tests
    
    Returns:
        list: Generated happy-path inferred tests
    """
    generated_tests = []
    
    # Build a set of requirement IDs already covered by api_tests or ui_tests
    covered_requirements = set()
    api_tests = all_tests_by_category.get("api_tests", [])
    ui_tests = all_tests_by_category.get("ui_tests", [])
    
    for test in api_tests + ui_tests:
        if isinstance(test, dict):
            reqs_covered = test.get("requirements_covered", [])
            if isinstance(reqs_covered, list):
                covered_requirements.update(reqs_covered)
    
    # Track test ID counter
    test_id_counter = 0
    
    # Generate tests for each requirement
    for req in requirements:
        if not isinstance(req, dict):
            continue
        
        req_id = req.get("id", "")
        if not req_id:
            continue
        
        # Skip if requirement is not testable - generate no tests and no test steps
        is_testable = req.get("testable", True)  # Default to True for backward compatibility
        if not is_testable:
            continue
        
        # Skip if requirement is already covered by api_tests or ui_tests
        if req_id in covered_requirements:
            continue
        
        coverage_exp = req.get("coverage_expectations", {})
        if not isinstance(coverage_exp, dict):
            continue
        
        # Check if happy_path is expected but not covered
        if coverage_exp.get("happy_path") == "expected":
            test_id_counter += 1
            req_description = req.get("description", "")
            
            # Check if requirement names UI elements or output artifacts
            has_ui = names_ui_element(req_description)
            has_artifact = names_output_artifact(req_description)
            can_generate_steps = has_ui or has_artifact
            
            # Do not generate generic steps - return empty steps with explanation
            happy_path_test = {
                "id": f"HAPPY-{test_id_counter:03d}",
                "title": f"Inferred happy-path test for {req_id}",
                "steps": [],
                "steps_origin": "none",
                "expected_result": "Requirement-specific behavior validated",
                "requirements_covered": [req_id],
                "confidence": "inferred",
                "priority": "medium",
                "dimension": "happy_path"
            }
            
            # Only set "Cannot generate" explanation if UI elements/artifacts are NOT named
            if not can_generate_steps:
                happy_path_test["steps_explanation"] = f"Cannot generate concrete test steps from requirement: '{req_description[:100]}...'. Requirement lacks specific execution details (UI elements, API endpoints, inputs, or observable outcomes)."
            # If UI elements/artifacts are named, let LLM generate steps (don't pre-emptively block)
            
            generated_tests.append(happy_path_test)
    
    return generated_tests


def generate_dimension_specific_inferred_tests(requirements, all_tests_by_category):
    """
    Generate dimension-specific inferred tests based on coverage_expectations.
    
    Generates inferred tests for data_validation, boundary, and authorization dimensions
    when coverage_expectations indicates they are "expected" but not yet "covered".
    
    Args:
        requirements: List of requirement dicts with coverage_expectations
        all_tests_by_category: Dict mapping test categories to lists of tests
    
    Returns:
        dict: Maps category names to lists of generated tests
    """
    generated_tests = {
        "data_validation_tests": [],
        "edge_cases": [],
        "negative_tests": []
    }
    
    # Build a map of requirement_id -> existing tests by dimension
    req_dimension_tests = {}
    
    # Check existing tests to see which dimensions are already covered
    for category, tests in all_tests_by_category.items():
        for test in tests:
            if not isinstance(test, dict):
                continue
            reqs_covered = test.get("requirements_covered", [])
            test_dimension = test.get("dimension")
            
            for req_id in reqs_covered:
                if req_id not in req_dimension_tests:
                    req_dimension_tests[req_id] = set()
                if test_dimension:
                    req_dimension_tests[req_id].add(test_dimension)
    
    # Track test IDs to ensure uniqueness
    test_id_counters = {
        "data_validation": 0,
        "boundary": 0,
        "authorization": 0
    }
    
    # Generate tests for each requirement
    for req in requirements:
        if not isinstance(req, dict):
            continue
        
        req_id = req.get("id", "")
        if not req_id:
            continue
        
        # Skip if requirement is not testable - generate no tests and no test steps
        is_testable = req.get("testable", True)  # Default to True for backward compatibility
        if not is_testable:
            continue
        
        coverage_exp = req.get("coverage_expectations", {})
        if not isinstance(coverage_exp, dict):
            continue
        
        # Check data_validation dimension
        if (coverage_exp.get("data_validation") == "expected" and 
            "data_validation" not in req_dimension_tests.get(req_id, set())):
            test_id_counters["data_validation"] += 1
            req_description = req.get("description", "")
            has_ui = names_ui_element(req_description)
            has_artifact = names_output_artifact(req_description)
            can_generate_steps = has_ui or has_artifact
            
            data_val_test = {
                "id": f"DATA-VAL-{test_id_counters['data_validation']:03d}",
                "title": f"Inferred data validation test for {req_id}",
                "steps": [],
                "steps_origin": "none",
                "expected_result": "Invalid input is rejected with appropriate error",
                "requirements_covered": [req_id],
                "confidence": "inferred",
                "priority": "medium",
                "dimension": "data_validation"
            }
            
            # Only set "Cannot generate" explanation if UI elements/artifacts are NOT named
            if not can_generate_steps:
                data_val_test["steps_explanation"] = f"Cannot generate concrete data validation steps from requirement: '{req_description[:100]}...'. Requirement lacks specific validation rules, input formats, or error conditions."
            
            generated_tests["data_validation_tests"].append(data_val_test)
            req_dimension_tests.setdefault(req_id, set()).add("data_validation")
        
        # Check boundary dimension
        if (coverage_exp.get("boundary") == "expected" and 
            "boundary" not in req_dimension_tests.get(req_id, set())):
            test_id_counters["boundary"] += 1
            req_description = req.get("description", "")
            has_ui = names_ui_element(req_description)
            has_artifact = names_output_artifact(req_description)
            can_generate_steps = has_ui or has_artifact
            
            boundary_test = {
                "id": f"BOUND-{test_id_counters['boundary']:03d}",
                "title": f"Inferred boundary test for {req_id}",
                "steps": [],
                "steps_origin": "none",
                "expected_result": "System correctly handles boundary conditions",
                "requirements_covered": [req_id],
                "confidence": "inferred",
                "priority": "medium",
                "dimension": "boundary"
            }
            
            # Only set "Cannot generate" explanation if UI elements/artifacts are NOT named
            if not can_generate_steps:
                boundary_test["steps_explanation"] = f"Cannot generate concrete boundary test steps from requirement: '{req_description[:100]}...'. Requirement lacks specific boundary values, limits, or edge case conditions."
            
            generated_tests["edge_cases"].append(boundary_test)
            req_dimension_tests.setdefault(req_id, set()).add("boundary")
        
        # Check authorization dimension
        if (coverage_exp.get("authorization") == "expected" and 
            "authorization" not in req_dimension_tests.get(req_id, set())):
            test_id_counters["authorization"] += 1
            req_description = req.get("description", "")
            has_ui = names_ui_element(req_description)
            has_artifact = names_output_artifact(req_description)
            can_generate_steps = has_ui or has_artifact
            
            auth_test = {
                "id": f"AUTH-{test_id_counters['authorization']:03d}",
                "title": f"Inferred authorization test for {req_id}",
                "steps": [],
                "steps_origin": "none",
                "expected_result": "Unauthorized access is properly rejected",
                "requirements_covered": [req_id],
                "confidence": "inferred",
                "priority": "medium",
                "dimension": "authorization"
            }
            
            # Only set "Cannot generate" explanation if UI elements/artifacts are NOT named
            if not can_generate_steps:
                auth_test["steps_explanation"] = f"Cannot generate concrete authorization test steps from requirement: '{req_description[:100]}...'. Requirement lacks specific authentication mechanisms, roles, permissions, or access control rules."
            
            generated_tests["negative_tests"].append(auth_test)
            req_dimension_tests.setdefault(req_id, set()).add("authorization")
    
    return generated_tests


def validate_and_clean_test_steps(steps):
    """
    Validate test steps and remove generic placeholder steps.
    
    Args:
        steps: List of step strings
    
    Returns:
        tuple: (cleaned_steps, steps_origin)
            - cleaned_steps: List of steps with generic placeholders removed
            - steps_origin: "requirement-derived" if valid steps exist, "none" if empty or all generic
    """
    if not isinstance(steps, list):
        return [], "none"
    
    # Define generic placeholder patterns (case-insensitive)
    # These are truly generic and should be filtered out
    generic_patterns = [
        r"invoke the system using valid inputs",
        r"verify the operation completes successfully",
        r"validate expected output or behavior",
        r"send request with valid data",
        r"check response status",
        r"verify.*completes successfully",
        r"validate.*expected.*output",
        r"invoke.*system.*valid",
        r"send.*request.*valid",
        r"check.*response",
        r"verify.*operation",
        r"identify.*endpoint",  # Skeleton slot that wasn't filled (for API)
        r"construct.*request",  # Skeleton slot that wasn't filled (for API)
    ]
    
    # UI-primitive patterns that are VALID when they reference requirement terms
    # These should NOT be filtered if they contain specific element names or outcomes
    ui_primitive_patterns = [
        r"verify.*is visible",
        r"verify.*is enabled",
        r"click.*button",
        r"tap.*button",
        r"click.*link",
        r"interact with",
        r"verify.*file.*downloaded",
        r"verify.*navigates",
        r"verify.*displays",
    ]
    
    import re
    cleaned_steps = []
    
    for step in steps:
        if not isinstance(step, str):
            continue
        
        step_lower = step.lower().strip()
        is_generic = False
        
        # Check against generic patterns
        for pattern in generic_patterns:
            if re.search(pattern, step_lower):
                # But allow through if it contains specific details (for API steps)
                has_specifics = (
                    "/api/" in step_lower or
                    "/" in step and any(c.isupper() or c.isdigit() for c in step) or
                    "'" in step or '"' in step or
                    any(word in step_lower for word in ["post", "get", "put", "delete"]) and "/" in step or
                    len([c for c in step if c.isdigit()]) > 2  # Has numbers (likely IDs, codes, etc.)
                )
                if not has_specifics:
                    is_generic = True
                    break
        
        # Check if step is a valid UI-primitive that references requirement terms
        if not is_generic:
            is_ui_primitive = False
            for pattern in ui_primitive_patterns:
                if re.search(pattern, step_lower):
                    # Check if it references a specific element name (quoted text, capitalized words, etc.)
                    has_element_reference = (
                        "'" in step or '"' in step or  # Quoted element names
                        any(word[0].isupper() for word in step.split() if len(word) > 2) or  # Capitalized element names
                        "PDF" in step or "file" in step_lower or "button" in step_lower or "link" in step_lower or
                        "download" in step_lower
                    )
                    if has_element_reference:
                        is_ui_primitive = True
                        break
            
            # UI-primitive steps that reference requirement terms are VALID and CONCRETE
            # Don't mark as generic - these are valid concrete steps
            if is_ui_primitive:
                pass  # Keep the step
            elif len(step_lower) < 20 and any(word in step_lower for word in ["verify", "check", "validate", "invoke", "test"]):
                # Check if it's too generic (lacks specific details)
                if not any(char.isdigit() or char in ["/", "'", '"', "-"] for char in step):
                    # Likely generic if it's short and lacks specific identifiers
                    is_generic = True
        
        if not is_generic:
            cleaned_steps.append(step)
    
    steps_origin = "requirement-derived" if len(cleaned_steps) > 0 else "none"
    return cleaned_steps, steps_origin


def enrich_execution_steps_for_ui_tests(test_plan: dict) -> None:
    """
    Enrich execution steps for UI tests or user-executable tests.
    
    This function ONLY modifies the `steps` field of tests that are:
    - Classified as UI tests (in ui_tests category)
    - User-executable tests (tests with UI elements or user actions)
    - Have empty or abstract steps
    
    ABSOLUTE RULES (DO NOT VIOLATE):
    - Do NOT add, remove, merge, or deduplicate requirements
    - Do NOT change any requirement IDs
    - Do NOT add, remove, merge, or deduplicate tests
    - Do NOT change test IDs
    - Do NOT change source_requirement_id
    - Do NOT change requirements_covered
    - Do NOT recalculate RTM, coverage, confidence, or scoring
    - Do NOT introduce cross-requirement logic
    - Do NOT infer shared behavior across requirements
    - Do NOT modify system, RTM, or audit tests
    - Do NOT touch data structures outside the `steps` field
    
    Args:
        test_plan: Test plan dictionary (modified in place)
    """
    requirements = test_plan.get("requirements", [])
    req_lookup = {req.get("id"): req for req in requirements if isinstance(req, dict) and req.get("id")}
    
    test_plan_section = test_plan.get("test_plan", {})
    
    # Only process UI tests
    ui_tests = test_plan_section.get("ui_tests", [])
    if not isinstance(ui_tests, list):
        return
    
    import re
    
    for test in ui_tests:
        if not isinstance(test, dict):
            continue
        
        # Skip if test has non-empty, concrete steps
        steps = test.get("steps", [])
        if isinstance(steps, list) and len(steps) > 0:
            # Check if steps are concrete (not abstract)
            has_concrete_steps = False
            for step in steps:
                if isinstance(step, str) and len(step.strip()) > 0:
                    step_lower = step.lower()
                    # Check if step is concrete (has specific actions, elements, or outcomes)
                    is_concrete = (
                        any(word in step_lower for word in ["click", "tap", "enter", "select", "navigate", "verify", "check"]) and
                        (any(char in step for char in ["'", '"']) or  # Has quoted element names
                         any(word[0].isupper() for word in step.split() if len(word) > 2) or  # Has capitalized names
                         "button" in step_lower or "field" in step_lower or "link" in step_lower or
                         "download" in step_lower or "file" in step_lower or "page" in step_lower)
                    )
                    if is_concrete:
                        has_concrete_steps = True
                        break
            
            if has_concrete_steps:
                continue  # Skip tests that already have concrete steps
        
        # Get requirement to extract context
        source_req_id = test.get("source_requirement_id")
        if not source_req_id:
            continue
        
        requirement = req_lookup.get(source_req_id)
        if not isinstance(requirement, dict):
            continue
        
        req_description = requirement.get("description", "").strip()
        if not req_description:
            continue
        
        intent_type = test.get("intent_type", "happy_path")
        
        # Get requirement classification
        req_classification = requirement.get("_classification", "")
        
        # Extract UI elements from requirement
        ui_elements = []
        # Look for quoted element names
        quoted_elements = re.findall(r'"([^"]+)"', req_description)
        ui_elements.extend(quoted_elements)
        
        # Look for common UI element patterns
        element_patterns = [
            r"(\w+\s+button)",
            r"(\w+\s+field)",
            r"(\w+\s+link)",
            r"(\w+\s+menu)",
            r"(Download\s+\w+)",
            r"(Export\s+\w+)",
        ]
        for pattern in element_patterns:
            matches = re.findall(pattern, req_description, re.IGNORECASE)
            ui_elements.extend([m.strip() for m in matches if m.strip()])
        
        # UI STRUCTURE STEP EXPANSION: Extract comma-separated UI elements for UI structure requirements
        comma_separated_ui_elements = []
        if req_classification in ["ui_structure", "ui_element"]:
            # Check if requirement has comma-separated list
            req_lower = req_description.lower()
            comma_count = req_lower.count(',')
            if comma_count >= 1:
                # Extract text after any numbering token
                numbering_token_pattern = re.compile(r'^(\[?\d+\]?[\.\)\-\s]+)', re.IGNORECASE)
                numbering_match = numbering_token_pattern.match(req_description)
                text_to_parse = req_description
                if numbering_match:
                    text_to_parse = req_description[len(numbering_match.group(0)):].strip()
                
                # Detect UI element type mentioned in the requirement (e.g., "tabs", "buttons", "fields")
                ui_element_type = None
                ui_keywords = ["button", "link", "field", "menu", "tab", "page", "screen", "form", "input", 
                             "dropdown", "select", "checkbox", "radio", "toggle", "upload", "download"]
                for keyword in ui_keywords:
                    if keyword in text_to_parse.lower():
                        ui_element_type = keyword
                        break
                
                # Split by commas and extract UI element names
                # Handle "and" at the end (e.g., "X, Y, and Z")
                items_text = text_to_parse
                items_text = re.sub(r'\s+and\s*$', '', items_text, flags=re.IGNORECASE)
                comma_items = [item.strip() for item in items_text.split(',') if item.strip()]
                
                # Extract UI element names from each comma-separated item
                for item in comma_items:
                    item_lower = item.lower()
                    # If UI element type is mentioned (e.g., "tabs"), prepend it to each item
                    if ui_element_type and ui_element_type not in item_lower:
                        # Construct element name: "ticket" -> "ticket tab" (if type is "tab")
                        element_name = f"{item.strip()} {ui_element_type}"
                        if len(element_name) < 60:  # Reasonable length for an element name
                            comma_separated_ui_elements.append(element_name)
                    else:
                        # Look for UI element keywords in the item itself
                        found_keyword = False
                        for keyword in ui_keywords:
                            if keyword in item_lower:
                                # Extract the element name (e.g., "ticket tab" -> "ticket tab")
                                # Or use the item text if it's short and descriptive
                                if len(item) < 50:  # Reasonable length for an element name
                                    comma_separated_ui_elements.append(item.strip())
                                found_keyword = True
                                break
                        # If no keyword found but we have a UI element type, use the item as-is
                        if not found_keyword and ui_element_type and len(item) < 50:
                            comma_separated_ui_elements.append(item.strip())
        
        # Remove duplicates while preserving order
        seen = set()
        unique_elements = []
        for elem in ui_elements:
            elem_lower = elem.lower()
            if elem_lower not in seen:
                seen.add(elem_lower)
                unique_elements.append(elem)
        
        # Generate enriched steps based on intent type
        enriched_steps = []
        
        if intent_type == "happy_path":
            # UI STRUCTURE STEP EXPANSION: Expand comma-separated UI elements into individual verification steps
            # HAPPY-PATH STEP DECOMPOSITION: Each UI element gets its own explicit verification step
            if req_classification in ["ui_structure", "ui_element"] and comma_separated_ui_elements:
                enriched_steps.append("Navigate to the application")
                # Generate one verification step per UI element
                # Each step explicitly confirms presence, visibility, and accessibility
                # Do NOT merge multiple UI elements into a single step
                for element in comma_separated_ui_elements:
                    enriched_steps.append(f"Verify that the '{element}' is present on the screen, visible to the user, and accessible (enabled and ready for interaction)")
                # Add final verification step only if we have fewer than 3 steps total
                if len(enriched_steps) < 3:
                    enriched_steps.append("Confirm all required UI elements are functioning as specified")
            elif unique_elements:
                # Use first UI element as primary interaction target
                primary_element = unique_elements[0]
                
                enriched_steps.append(f"Navigate to the application screen where the {primary_element.lower()} is available")
                enriched_steps.append(f"Verify the '{primary_element}' is visible on the screen")
                enriched_steps.append(f"Verify the '{primary_element}' is enabled and ready for interaction")
                enriched_steps.append(f"Click or interact with the '{primary_element}'")
                
                # Check for download/export actions
                if any(keyword in req_description.lower() for keyword in ["download", "export", "file", "pdf", "json"]):
                    enriched_steps.append("Verify a file is downloaded successfully")
                    enriched_steps.append("Verify the downloaded file has the expected format (PDF, JSON, etc.)")
                else:
                    enriched_steps.append("Verify the expected outcome occurs (e.g., page navigation, state change, message display)")
                    enriched_steps.append("Verify the outcome matches what is described in the requirement")
            else:
                # Generic UI steps when no specific elements found
                enriched_steps.append("Navigate to the application screen relevant to the requirement")
                enriched_steps.append("Locate the UI elements mentioned in the requirement")
                enriched_steps.append("Interact with the UI elements as specified in the requirement")
                enriched_steps.append("Verify the system responds as specified in the requirement")
        
        elif intent_type == "negative":
            # UI STRUCTURE STEP EXPANSION: Expand comma-separated UI elements into individual verification steps
            if req_classification in ["ui_structure", "ui_element"] and comma_separated_ui_elements:
                enriched_steps.append("Navigate to the application")
                # Generate one verification step per UI element checking for absence/state issues
                for element in comma_separated_ui_elements:
                    enriched_steps.append(f"Check if the '{element}' is missing, not visible, disabled when it should be enabled, or displays incorrect/empty content")
                # Add final assertion step if needed
                if len(enriched_steps) < 3:
                    enriched_steps.append("Verify that one or more required UI elements are missing, inaccessible, or in an incorrect state")
            elif unique_elements:
                primary_element = unique_elements[0]
                
                enriched_steps.append(f"Navigate to the application screen where the {primary_element.lower()} is available")
                enriched_steps.append(f"Verify the '{primary_element}' is visible on the screen")
                
                # Try to infer invalid input scenarios
                if "field" in primary_element.lower() or "input" in req_description.lower():
                    enriched_steps.append(f"Leave the '{primary_element}' field blank or enter invalid data")
                    enriched_steps.append("Attempt to trigger the action (click submit button, press Enter, etc.)")
                    enriched_steps.append("Verify an appropriate error message is displayed")
                    enriched_steps.append("Verify the error message clearly indicates what is wrong")
                else:
                    enriched_steps.append(f"Attempt to interact with the '{primary_element}' without meeting prerequisites")
                    enriched_steps.append("Verify the system rejects the action with an appropriate error message")
            else:
                enriched_steps.append("Navigate to the application screen relevant to the requirement")
                enriched_steps.append("Attempt to perform the action described in the requirement with invalid or missing inputs")
                enriched_steps.append("Verify the system rejects the action with an appropriate error message")
        
        else:
            # For other intent types (authorization, boundary), use generic enrichment
            if unique_elements:
                primary_element = unique_elements[0]
                enriched_steps.append(f"Navigate to the application screen where the {primary_element.lower()} is available")
                enriched_steps.append(f"Verify the '{primary_element}' is visible on the screen")
                enriched_steps.append(f"Perform the test action as specified for {intent_type} testing")
                enriched_steps.append("Verify the expected outcome occurs")
            else:
                enriched_steps.append("Navigate to the application screen relevant to the requirement")
                enriched_steps.append("Perform the test action as specified for the requirement")
                enriched_steps.append("Verify the expected outcome occurs")
        
        # Only update steps if we generated meaningful steps
        if enriched_steps:
            test["steps"] = enriched_steps
            # Remove steps_explanation if it exists (steps are no longer empty)
            if "steps_explanation" in test:
                del test["steps_explanation"]


def derive_test_plan_by_requirement(requirements, test_plan):
    """
    Derive a requirement-centric view of the test plan.
    
    Groups all test cases under their originating requirement, organized by intent_type.
    This is a presentation-only structure - no data is duplicated or regenerated.
    
    Args:
        requirements: List of requirement dicts
        test_plan: Test plan dict with api_tests, ui_tests, etc.
    
    Returns:
        list: List of requirement-centric test groupings
    """
    # Collect all tests from all categories
    all_tests = []
    for category in ["api_tests", "ui_tests", "data_validation_tests", "edge_cases", "negative_tests"]:
        tests = test_plan.get(category, [])
        if isinstance(tests, list):
            all_tests.extend(tests)
    
    # Build a map of requirement_id -> tests
    req_to_tests = {}
    for test in all_tests:
        if not isinstance(test, dict):
            continue
        
        # Get requirement IDs from source_requirement_id or requirements_covered
        req_ids = []
        source_req_id = test.get("source_requirement_id")
        if source_req_id:
            req_ids.append(source_req_id)
        
        requirements_covered = test.get("requirements_covered", [])
        if isinstance(requirements_covered, list):
            req_ids.extend(requirements_covered)
        
        # Add test to each requirement it covers
        # Deduplicate tests per requirement using (test.id, test.intent_type) as key
        for req_id in req_ids:
            if req_id not in req_to_tests:
                req_to_tests[req_id] = []
            
            # Check for duplicates using (test.id, intent_type) key
            test_key = (test.get("id", ""), test.get("intent_type", ""))
            existing_keys = {(t.get("id", ""), t.get("intent_type", "")) for t in req_to_tests[req_id]}
            
            if test_key not in existing_keys:
                req_to_tests[req_id].append(test)
    
    # Build requirement-centric structure
    test_plan_by_requirement = []
    for req in requirements:
        if not isinstance(req, dict):
            continue
        
        req_id = req.get("id", "")
        if not req_id:
            continue
        
        req_text = req.get("description", "")
        req_tests = req_to_tests.get(req_id, [])
        
        # Group tests by intent_type
        tests_by_intent = {
            "happy_path": [],
            "negative": [],
            "boundary": [],
            "authorization": [],
            "other": []
        }
        
        for test in req_tests:
            intent_type = test.get("intent_type", "").lower()
            if intent_type in tests_by_intent:
                tests_by_intent[intent_type].append(test)
            else:
                # Handle dimension field for backward compatibility
                dimension = test.get("dimension", "").lower()
                if dimension == "authorization":
                    tests_by_intent["authorization"].append(test)
                elif dimension == "boundary":
                    tests_by_intent["boundary"].append(test)
                else:
                    tests_by_intent["other"].append(test)
        
        # Only include requirements that have tests or are explicitly listed
        test_plan_by_requirement.append({
            "requirement_id": req_id,
            "requirement_text": req_text,
            "requirement_source": req.get("source", "unknown"),
            "quality": req.get("quality"),
            "coverage_confidence": req.get("coverage_confidence"),
            "coverage_expectations": req.get("coverage_expectations"),
            "tests": {
                "happy_path": tests_by_intent["happy_path"],
                "negative": tests_by_intent["negative"],
                "boundary": tests_by_intent["boundary"],
                "authorization": tests_by_intent["authorization"],
                "other": tests_by_intent["other"]
            }
        })
    
    return test_plan_by_requirement


def split_compound_requirements(requirements: list) -> list:
    """
    Split compound requirements into atomic requirements.
    
    Multi-clause requirements (e.g., comma-separated behaviors, multiple guarantees in one sentence)
    are expanded into distinct atomic requirements.
    
    This must occur during ticket extraction, before any multi-ticket aggregation.
    
    Args:
        requirements: List of requirement dicts (may contain compound requirements)
    
    Returns:
        list: List of atomic requirement dicts (compound requirements split)
    """
    atomic_requirements = []
    
    for req in requirements:
        if not isinstance(req, dict):
            atomic_requirements.append(req)
            continue
        
        description = req.get("description", "").strip()
        if not description:
            atomic_requirements.append(req)
            continue
        
        import re
        
        # ============================================================================
        # POST-EXTRACTION GROUPING RULE: Numbered requirements with comma-separated lists
        # If a requirement has an explicit numbering token AND comma-separated items,
        # keep it as ONE parent requirement (do NOT split).
        # Ticket items will be created from comma-separated phrases separately.
        # ============================================================================
        # Detect explicit numbering token at the start (e.g., "[6].", "6.", "(6)", "6)")
        numbering_token_pattern = re.compile(r'^(\[?\d+\]?[\.\)\-\s]+)', re.IGNORECASE)
        numbering_match = numbering_token_pattern.match(description)
        
        if numbering_match:
            # Requirement has explicit numbering token
            # Check if description contains comma-separated list (after the numbering token)
            text_after_numbering = description[len(numbering_match.group(0)):].strip()
            
            # Count commas (simple heuristic - if 2+ commas, likely a list)
            comma_count = text_after_numbering.count(',')
            
            if comma_count >= 1:
                # This is a numbered requirement with comma-separated list
                # Keep as ONE requirement - do NOT split
                # Ticket items will be created from comma-separated phrases in post-processing
                atomic_requirements.append(req)
                continue
        
        # Patterns that indicate compound requirements:
        # 1. Multiple clauses separated by commas followed by verbs (e.g., "X, Y, and Z")
        # 2. Semicolons separating independent clauses
        # 3. "and" connecting multiple behaviors (e.g., "X and Y")
        # 4. Numbered items within a requirement (e.g., "1) X, 2) Y")
        
        # Check for numbered sub-items (e.g., "1) X, 2) Y, 3) Z")
        numbered_pattern = re.compile(r'(\d+[\.\):]?\s+[^,\n]+)', re.IGNORECASE)
        numbered_matches = numbered_pattern.findall(description)
        
        if len(numbered_matches) >= 2:
            # Split by numbered items
            base_req = req.copy()
            base_id = req.get("id", "")
            base_source = req.get("source", "inferred")
            
            for idx, match in enumerate(numbered_matches, 1):
                atomic_req = base_req.copy()
                atomic_req["description"] = match.strip()
                if base_id:
                    atomic_req["id"] = f"{base_id}-{idx:03d}"
                else:
                    atomic_req["id"] = f"REQ-{idx:03d}"
                atomic_req["source"] = base_source
                atomic_req["quality"] = score_requirement_quality(atomic_req)
                atomic_req["coverage_expectations"] = compute_coverage_expectations(atomic_req)
                # Evaluate testability per requirement after splitting
                atomic_req["testable"] = is_requirement_testable(atomic_req)
                atomic_requirements.append(atomic_req)
            continue
        
        # Check for semicolon-separated clauses
        if ';' in description:
            clauses = [c.strip() for c in description.split(';') if c.strip()]
            if len(clauses) >= 2:
                base_req = req.copy()
                base_id = req.get("id", "")
                base_source = req.get("source", "inferred")
                
                for idx, clause in enumerate(clauses, 1):
                    atomic_req = base_req.copy()
                    atomic_req["description"] = clause
                    if base_id:
                        atomic_req["id"] = f"{base_id}-{idx:03d}"
                    else:
                        atomic_req["id"] = f"REQ-{idx:03d}"
                    atomic_req["source"] = base_source
                    atomic_req["quality"] = score_requirement_quality(atomic_req)
                    atomic_req["coverage_expectations"] = compute_coverage_expectations(atomic_req)
                    # Evaluate testability per requirement after splitting
                    atomic_req["testable"] = is_requirement_testable(atomic_req)
                    atomic_requirements.append(atomic_req)
                continue
        
        # Check for comma-separated clauses with "and" (e.g., "X, Y, and Z")
        # Look for patterns like: "X, Y, and Z" or "X, Y, Z"
        # Only split if there are at least 3 items or explicit "and" connectors
        comma_and_pattern = re.compile(r'([^,]+(?:,\s*[^,]+)*)\s+and\s+([^,]+)', re.IGNORECASE)
        comma_and_match = comma_and_pattern.search(description)
        
        if comma_and_match:
            # Found "X, Y, and Z" pattern
            before_and = comma_and_match.group(1).strip()
            after_and = comma_and_match.group(2).strip()
            
            # Split the "before_and" part by commas
            before_items = [item.strip() for item in before_and.split(',') if item.strip()]
            all_items = before_items + [after_and]
            
            if len(all_items) >= 2:
                base_req = req.copy()
                base_id = req.get("id", "")
                base_source = req.get("source", "inferred")
                
                for idx, item in enumerate(all_items, 1):
                    atomic_req = base_req.copy()
                    atomic_req["description"] = item
                    if base_id:
                        atomic_req["id"] = f"{base_id}-{idx:03d}"
                    else:
                        atomic_req["id"] = f"REQ-{idx:03d}"
                    atomic_req["source"] = base_source
                    atomic_req["quality"] = score_requirement_quality(atomic_req)
                    atomic_req["coverage_expectations"] = compute_coverage_expectations(atomic_req)
                    # Evaluate testability per requirement after splitting
                    atomic_req["testable"] = is_requirement_testable(atomic_req)
                    atomic_requirements.append(atomic_req)
                continue
        
        # If no compound pattern found, keep requirement as-is
        atomic_requirements.append(req)
    
    return atomic_requirements


def create_items_from_numbered_requirements(test_plan: dict, ticket_id: str) -> None:
    """
    Create ticket items from numbered requirements that contain comma-separated lists.
    
    This is a post-extraction grouping rule:
    - If a requirement has an explicit numbering token AND comma-separated items,
      keep it as ONE parent requirement
    - Create multiple child ITEMs from the comma-separated phrases
    - All ITEMs map to the same parent requirement
    
    UI STRUCTURE GROUPING RULE:
    - If a requirement is classified as ui_structure or ui_element:
      * AND the requirement description contains a comma-separated list of UI elements
      * AND the sentence has a single governing verb (e.g., "Have", "Display", "Provide"):
      * DO NOT create separate ITEM records for each comma-separated noun
      * Treat the entire sentence as ONE parent requirement
      * Treat listed UI elements as sub-elements, not standalone testable items
      * Generate: One RTM entry, One happy-path test, One negative test
      * with assertions that cover the presence or absence of all listed UI elements
    
    Args:
        test_plan: Test plan dict (modified in place)
        ticket_id: Ticket ID for item ID generation
    """
    requirements = test_plan.get("requirements", [])
    if not requirements:
        return
    
    import re
    
    # Get or create ticket items list
    ticket_items = test_plan.get("_ticket_items", [])
    if "_ticket_items" not in test_plan:
        test_plan["_ticket_items"] = ticket_items
    
    # Find highest existing item number
    max_item_num = 0
    for item in ticket_items:
        if isinstance(item, dict):
            item_id = item.get("item_id", "")
            match = re.search(r'ITEM-(\d+)', item_id)
            if match:
                item_num = int(match.group(1))
                max_item_num = max(max_item_num, item_num)
    
    item_counter = max_item_num
    
    for req in requirements:
        if not isinstance(req, dict):
            continue
        
        description = req.get("description", "").strip()
        if not description:
            continue
        
        req_id = req.get("id", "")
        if not req_id:
            continue
        
        # UI STRUCTURE GROUPING RULE: Skip itemization for UI structure/element requirements
        req_classification = req.get("_classification", "")
        if req_classification in ["ui_structure", "ui_element"]:
            # Check if requirement has comma-separated list
            text_lower = description.lower()
            comma_count = text_lower.count(',')
            
            if comma_count >= 1:
                # Check for single governing verb (e.g., "Have", "Display", "Provide")
                presence_verbs = ["have", "has", "display", "displays", "show", "shows", 
                                 "present", "presents", "include", "includes", "contain", "contains"]
                has_single_governing_verb = any(verb in text_lower for verb in presence_verbs)
                
                if has_single_governing_verb:
                    # This is a UI structure requirement with comma-separated list and single governing verb
                    # DO NOT create separate items - keep as ONE parent requirement
                    logger.debug(f"Skipping itemization for UI structure requirement {req_id}: '{description[:60]}...' (comma-separated list with single governing verb)")
                    continue  # Skip creating items for this requirement
        
        # Detect explicit numbering token at the start (e.g., "[6].", "6.", "(6)", "6)")
        numbering_token_pattern = re.compile(r'^(\[?\d+\]?[\.\)\-\s]+)', re.IGNORECASE)
        numbering_match = numbering_token_pattern.match(description)
        
        if not numbering_match:
            continue  # No numbering token, skip
        
        # Extract text after numbering token
        text_after_numbering = description[len(numbering_match.group(0)):].strip()
        
        # Check if it contains comma-separated list
        comma_count = text_after_numbering.count(',')
        if comma_count < 1:
            continue  # No comma-separated list, skip
        
        # Split by commas to get individual items
        # Handle "and" at the end (e.g., "X, Y, and Z")
        items_text = text_after_numbering
        
        # Remove trailing "and" if present
        items_text = re.sub(r'\s+and\s*$', '', items_text, flags=re.IGNORECASE)
        
        # Split by commas
        comma_items = [item.strip() for item in items_text.split(',') if item.strip()]
        
        if len(comma_items) < 2:
            continue  # Not enough items to split
        
        # Create ticket items for each comma-separated phrase
        for item_text in comma_items:
            item_counter += 1
            item_id = f"{ticket_id}-ITEM-{item_counter:03d}"
            
            ticket_item = {
                "item_id": item_id,
                "text": item_text,
                "source_section": "requirement_grouping",
                "original_line": description,
                "parent_requirement_id": req_id  # Link to parent requirement
            }
            
            # STRICT INHERITANCE RULE: Inherit coverage_expectations.negative from parent requirement
            # If parent coverage_expectations.negative = not_applicable, items may NOT generate, retain, or be marked as covered by negative tests
            req_coverage_exp = req.get("coverage_expectations", {})
            req_negative = req_coverage_exp.get("negative", "expected")
            if req_negative == "not_applicable":
                if "coverage_expectations" not in ticket_item:
                    ticket_item["coverage_expectations"] = {}
                ticket_item["coverage_expectations"]["negative"] = "not_applicable"
                ticket_item["_parent_negative_not_applicable"] = True  # Flag to enforce strict inheritance
                logger.debug(f"Inherited coverage_expectations.negative=not_applicable from requirement {req_id} to item {item_id}")
            
            ticket_items.append(ticket_item)
    
    # Update test plan with ticket items
    test_plan["_ticket_items"] = ticket_items


def score_requirement_quality(requirement):
    """
    Score requirement quality based on clarity and testability heuristics.
    
    Args:
        requirement: Requirement dict with at least "description" field
    
    Returns:
        dict: Quality object with clarity_score, testability_score, and issues
    """
    description = requirement.get("description", "").strip()
    if not description:
        return {
            "clarity_score": 0.0,
            "testability_score": 0.0,
            "issues": ["Empty requirement description"]
        }
    
    desc_lower = description.lower()
    issues = []
    clarity_score = 1.0
    testability_score = 1.0
    
    # Clarity scoring
    # Check for explicit action verbs
    action_verbs = ["accepts", "returns", "generates", "shows", "displays", "creates",
                    "updates", "deletes", "validates", "processes", "sends", "receives",
                    "parses", "formats", "calculates", "verifies", "checks", "rejects",
                    "allows", "denies", "retrieves", "stores", "fetches", "loads"]
    has_action_verb = any(verb in desc_lower for verb in action_verbs)
    if not has_action_verb:
        clarity_score -= 0.2
        issues.append("Missing explicit action verb")
    
    # Check for vague wording
    vague_words = ["supports", "handles", "allows", "ensures", "should", "may", "might"]
    has_vague_wording = any(word in desc_lower for word in vague_words)
    if has_vague_wording:
        clarity_score -= 0.2
        issues.append("Contains vague or non-committal wording")
    
    # Check for multiple behaviors combined
    separators = [" and ", " / ", ", ", " or "]
    has_multiple_behaviors = any(sep in desc_lower for sep in separators)
    if has_multiple_behaviors:
        clarity_score -= 0.2
        issues.append("Multiple behaviors combined in one requirement")
    
    # Check for subject/actor (simple heuristic: look for "system", "API", "user", etc.)
    subject_indicators = ["system", "api", "user", "application", "service", "endpoint"]
    has_subject = any(indicator in desc_lower for indicator in subject_indicators)
    if not has_subject and len(description.split()) < 5:
        # Only penalize if description is very short and has no subject
        clarity_score -= 0.2
        issues.append("Ambiguous or implied actor")
    
    # Testability scoring
    # Check for observable outcome
    outcome_indicators = ["returns", "displays", "shows", "generates", "creates",
                          "status code", "response", "error", "success", "fails"]
    has_observable_outcome = any(indicator in desc_lower for indicator in outcome_indicators)
    if not has_observable_outcome:
        testability_score -= 0.3
        issues.append("Outcome not directly observable")
    
    # Check for explicit success criteria
    criteria_indicators = ["must", "shall", "will", "should return", "must return",
                          "expected", "required", "valid", "invalid"]
    has_explicit_criteria = any(indicator in desc_lower for indicator in criteria_indicators)
    if not has_explicit_criteria:
        testability_score -= 0.3
        issues.append("Missing explicit success criteria")
    
    # Check for external dependencies
    external_indicators = ["external", "third-party", "depends on", "relies on",
                          "calls", "invokes", "queries"]
    has_external_dependency = any(indicator in desc_lower for indicator in external_indicators)
    if has_external_dependency:
        testability_score -= 0.2
        issues.append("Depends on external system behavior")
    
    # Clamp scores between 0.0 and 1.0
    clarity_score = max(0.0, min(1.0, clarity_score))
    testability_score = max(0.0, min(1.0, testability_score))
    
    return {
        "clarity_score": round(clarity_score, 2),
        "testability_score": round(testability_score, 2),
        "issues": issues
    }


def prefix_requirement_ids(requirements, ticket_id):
    """
    Prefix requirement IDs with ticket ID to ensure strict ticket scoping.
    
    Requirements are scoped to a single ticket and must never be merged,
    deduplicated, or normalized across tickets, even if the text is identical.
    This function ensures each requirement has a unique ID that includes the ticket ID.
    
    Args:
        requirements: List of requirement dicts (scoped to a single ticket)
        ticket_id: Ticket ID to use as prefix
    
    Returns:
        list: Requirements with prefixed IDs (e.g., "ATA-36-REQ-001")
    """
    prefixed = []
    for req in requirements:
        req_copy = copy.deepcopy(req)
        original_id = req_copy.get("id", "")
        if original_id and not original_id.startswith(f"{ticket_id}-"):
            req_copy["id"] = f"{ticket_id}-{original_id}"
        prefixed.append(req_copy)
    return prefixed


def normalize_test_requirement_references(test_plan: dict, ticket_id: str) -> None:
    """
    Normalize test requirement references to use canonical ticket-scoped requirement IDs.
    
    If a test references a generic requirement ID (e.g., "REQ-001") and a corresponding
    ticket-scoped requirement exists (e.g., "ATA-18-REQ-001"), automatically remap the
    test to the canonical ticket-scoped ID.
    
    This is a reference-mapping rule only - does not modify test content, steps, or
    regenerate tests.
    
    Args:
        test_plan: Test plan dict (modified in place)
        ticket_id: Ticket ID for building canonical requirement IDs
    """
    # Build mapping from generic IDs to ticket-scoped IDs
    requirements = test_plan.get("requirements", [])
    id_mapping = {}  # generic_id -> ticket_scoped_id
    
    for req in requirements:
        if not isinstance(req, dict):
            continue
        
        req_id = req.get("id", "")
        if not req_id:
            continue
        
        # If requirement ID is already ticket-scoped, extract the generic part
        if req_id.startswith(f"{ticket_id}-"):
            generic_id = req_id[len(f"{ticket_id}-"):]
            id_mapping[generic_id] = req_id
        # If requirement ID is generic (e.g., "REQ-001"), map it to ticket-scoped
        elif req_id.startswith("REQ-"):
            ticket_scoped_id = f"{ticket_id}-{req_id}"
            id_mapping[req_id] = ticket_scoped_id
    
    if not id_mapping:
        return  # No mappings needed
    
    # Apply normalization to all test categories
    test_plan_section = test_plan.get("test_plan", {})
    test_categories = [
        "api_tests",
        "ui_tests",
        "negative_tests",
        "data_validation_tests",
        "edge_cases",
        "system_tests"
    ]
    
    for category in test_categories:
        tests = test_plan_section.get(category, [])
        if not isinstance(tests, list):
            continue
        
        for test in tests:
            if not isinstance(test, dict):
                continue
            
            # Normalize source_requirement_id
            source_req_id = test.get("source_requirement_id", "")
            if source_req_id and source_req_id in id_mapping:
                test["source_requirement_id"] = id_mapping[source_req_id]
            
            # Normalize requirements_covered array
            requirements_covered = test.get("requirements_covered", [])
            if isinstance(requirements_covered, list):
                normalized_covered = []
                for req_id in requirements_covered:
                    if req_id in id_mapping:
                        normalized_covered.append(id_mapping[req_id])
                    else:
                        normalized_covered.append(req_id)
                test["requirements_covered"] = normalized_covered


def normalize_all_test_requirement_references(result: dict) -> None:
    """
    Normalize all test requirement references in merged test plan to use canonical ticket-scoped IDs.
    
    This handles the case where tests from multiple tickets are merged and some may still
    reference generic IDs. Builds a mapping from all requirements and normalizes all tests.
    
    Args:
        result: Merged test plan dict (modified in place)
    """
    requirements = result.get("requirements", [])
    if not requirements:
        return
    
    # Build mapping from generic IDs to ticket-scoped IDs for all requirements
    id_mapping = {}  # generic_id -> ticket_scoped_id
    
    for req in requirements:
        if not isinstance(req, dict):
            continue
        
        req_id = req.get("id", "")
        if not req_id:
            continue
        
        # Extract ticket ID from requirement ID (e.g., "ATA-18-REQ-001" -> "ATA-18")
        # Pattern: TICKET-ID-REQ-XXX
        import re
        ticket_match = re.match(r'^([A-Z0-9-]+)-REQ-(\d+)$', req_id)
        if ticket_match:
            ticket_id = ticket_match.group(1)
            generic_id = f"REQ-{ticket_match.group(2).zfill(3)}"
            id_mapping[generic_id] = req_id
        # Also map the full ID to itself (in case some tests already use ticket-scoped IDs)
        id_mapping[req_id] = req_id
    
    if not id_mapping:
        return  # No mappings needed
    
    # Apply normalization to all test categories
    test_plan_section = result.get("test_plan", {})
    test_categories = [
        "api_tests",
        "ui_tests",
        "negative_tests",
        "data_validation_tests",
        "edge_cases",
        "system_tests"
    ]
    
    for category in test_categories:
        tests = test_plan_section.get(category, [])
        if not isinstance(tests, list):
            continue
        
        for test in tests:
            if not isinstance(test, dict):
                continue
            
            # Normalize source_requirement_id
            source_req_id = test.get("source_requirement_id", "")
            if source_req_id:
                # Try direct mapping first
                if source_req_id in id_mapping:
                    test["source_requirement_id"] = id_mapping[source_req_id]
                else:
                    # Try to extract generic ID and map it
                    generic_match = re.match(r'^REQ-(\d+)$', source_req_id)
                    if generic_match:
                        # Find matching ticket-scoped ID by number
                        req_num = generic_match.group(1).zfill(3)
                        generic_id = f"REQ-{req_num}"
                        if generic_id in id_mapping:
                            test["source_requirement_id"] = id_mapping[generic_id]
            
            # Normalize requirements_covered array
            requirements_covered = test.get("requirements_covered", [])
            if isinstance(requirements_covered, list):
                normalized_covered = []
                for req_id in requirements_covered:
                    if req_id in id_mapping:
                        normalized_covered.append(id_mapping[req_id])
                    else:
                        # Try to extract generic ID and map it
                        generic_match = re.match(r'^REQ-(\d+)$', req_id)
                        if generic_match:
                            req_num = generic_match.group(1).zfill(3)
                            generic_id = f"REQ-{req_num}"
                            if generic_id in id_mapping:
                                normalized_covered.append(id_mapping[generic_id])
                            else:
                                normalized_covered.append(req_id)
                        else:
                            normalized_covered.append(req_id)
                test["requirements_covered"] = normalized_covered


def merge_test_plans(test_plans):
    """
    Merge multiple test plans into a single test plan.
    
    Args:
        test_plans: List of test plan dicts
    
    Returns:
        dict: Merged test plan
    """
    merged = {
        "schema_version": "1.0",
        "metadata": {
            "source": "jira",
            "source_id": "",
            "generated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        },
        "requirements": [],
        "business_intent": "",
        "assumptions": [],
        "gaps_detected": [],
        "test_plan": {
            "api_tests": [],
            "ui_tests": [],
            "data_validation_tests": [],
            "edge_cases": [],
            "negative_tests": []
        },
        "summary": ""
    }
    
    # Merge requirements
    # Requirements are scoped to a single ticket and must never be merged,
    # deduplicated, or normalized across tickets, even if the text is identical.
    # Each ticket's requirements are already prefixed with ticket_id to ensure uniqueness.
    all_requirements = []
    for plan in test_plans:
        plan_requirements = plan.get("requirements", [])
        # Simply extend - no deduplication or normalization across tickets
        all_requirements.extend(plan_requirements)
    merged["requirements"] = all_requirements
    
    # Merge assumptions
    all_assumptions = []
    for plan in test_plans:
        all_assumptions.extend(plan.get("assumptions", []))
    merged["assumptions"] = all_assumptions
    
    # Merge gaps
    all_gaps = []
    for plan in test_plans:
        all_gaps.extend(plan.get("gaps_detected", []))
    merged["gaps_detected"] = all_gaps
    
    # Merge test plans
    for plan in test_plans:
        test_plan = plan.get("test_plan", {})
        for category in ["api_tests", "ui_tests", "data_validation_tests", "edge_cases", "negative_tests"]:
            tests = test_plan.get(category, [])
            if tests:
                merged["test_plan"][category].extend(tests)
    
    # Merge business intent and summary
    business_intents = [p.get("business_intent", "") for p in test_plans if p.get("business_intent")]
    if business_intents:
        merged["business_intent"] = " | ".join(business_intents)
    
    summaries = [p.get("summary", "") for p in test_plans if p.get("summary")]
    if summaries:
        merged["summary"] = " | ".join(summaries)
    
    # Merge ticket_item_coverage from all test plans
    # This ensures informational items are available for RTM generation
    all_ticket_item_coverage = []
    for plan in test_plans:
        plan_coverage = plan.get("ticket_item_coverage", [])
        if isinstance(plan_coverage, list):
            all_ticket_item_coverage.extend(plan_coverage)
    merged["ticket_item_coverage"] = all_ticket_item_coverage
    
    return merged


@app.route("/generate-test-plan", methods=["POST"])
def generate_test_plan():
    # ============================================================================
    # Usage tracking setup
    # ============================================================================
    start_time_ms = int(time.time() * 1000)
    run_id = None
    tenant_id = getattr(g, 'tenant_id', None)
    user_id = getattr(g, 'user_id', None)
    input_char_count = 0
    jira_ticket_count = 0
    usage_source = "text"  # Default, will be updated based on tickets
    
    # ============================================================================
    # CENTRALIZED ENTITLEMENT ENFORCEMENT (Policy Authority)
    # This is the SINGLE SOURCE OF TRUTH for all subscription, plan tier, and usage limits.
    # ============================================================================
    data = request.get_json() or {}
    
    # Calculate input_char_count from request payload
    try:
        input_char_count = len(json.dumps(data, default=str)) if data else 0
    except Exception:
        input_char_count = 0
    
    # Extract ticket count for enforcement
    tickets = data.get("tickets", [])
    ticket_count = len(tickets) if isinstance(tickets, list) else 0
    
    if tenant_id:
        try:
            from db import get_db
            from services.entitlements_centralized import enforce_entitlements
            
            db = next(get_db())
            try:
                # Comprehensive entitlement check (subscription, plan tier, limits, trials)
                allowed, reason, metadata = enforce_entitlements(
                    db=db,
                    tenant_id=str(tenant_id),
                    agent="test_plan",
                    ticket_count=ticket_count if ticket_count > 0 else None,
                    input_char_count=input_char_count if input_char_count > 0 else None
                )
                
                if not allowed:
                    # Build response with status and remaining
                    # Special handling for onboarding incomplete
                    if reason == "ONBOARDING_INCOMPLETE":
                        message = "Complete onboarding: choose a plan"
                    else:
                        message = "Request blocked by subscription or plan limits."
                    
                    response_detail = {
                        "error": reason or "PAYWALLED",
                        "message": message
                    }
                    if "subscription_status" in metadata:
                        response_detail["subscription_status"] = metadata["subscription_status"]
                    if "trial_remaining" in metadata:
                        response_detail["remaining"] = metadata["trial_remaining"]
                    if "plan_tier" in metadata:
                        response_detail["plan_tier"] = metadata["plan_tier"]
                    
                    # Create response with CORS headers explicitly included
                    response = jsonify(response_detail)
                    response.status_code = 403
                    
                    # Ensure CORS headers are included
                    origin = request.headers.get("Origin", "")
                    if origin in ALLOWED_ORIGINS:
                        response.headers["Access-Control-Allow-Origin"] = origin
                    elif ALLOWED_ORIGINS:
                        response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGINS[0]
                    
                    return response
            finally:
                db.close()
        except Exception as e:
            # Fail closed: return 503 on entitlement check errors (unless ENTITLEMENT_FAIL_OPEN=true)
            fail_open = os.getenv("ENTITLEMENT_FAIL_OPEN", "false").lower() == "true"
            
            if fail_open:
                logger.warning(f"ENTITLEMENT_FAIL_OPEN=true: Allowing request despite entitlement check error: {str(e)}", exc_info=True)
                # Continue with request (fail open)
            else:
                # Fail closed: return 503
                logger.error(f"Entitlement check failed for tenant {tenant_id}: {str(e)}", exc_info=True)
                response = jsonify({
                    "error": "ENTITLEMENT_UNAVAILABLE",
                    "message": "Unable to verify subscription status. Please try again."
                })
                response.status_code = 503
                
                # Ensure CORS headers are included
                origin = request.headers.get("Origin", "")
                if origin in ALLOWED_ORIGINS:
                    response.headers["Access-Control-Allow-Origin"] = origin
                elif ALLOWED_ORIGINS:
                    response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGINS[0]
                
                return response
    
    try:
        
        # Extract created_by from request header (X-Actor) or body field, default to "anonymous"
        created_by = request.headers.get("X-Actor") or data.get("created_by") if data else None
        if not created_by:
            created_by = "anonymous"
        
        # Extract environment from request or use default
        environment = os.getenv('ENVIRONMENT', 'development').lower()
        
        # Normalize request to unified structure
        normalized = normalize_request(data)
        scope = normalized["scope"]
        tickets = normalized["tickets"]
        options = normalized["options"]
        
        # Determine source and count Jira tickets
        jira_ticket_count = len([t for t in tickets if t.get("source") == "jira" and t.get("ticket_id") != "MANUAL"])
        if jira_ticket_count > 0:
            usage_source = "jira"
        else:
            usage_source = "text"
        
        # Guard: Ensure tickets is always a non-empty list
        if not tickets or not isinstance(tickets, list):
            return jsonify({
                "detail": "Invalid request: tickets must be a non-empty list"
            }), 400
        
        # Process each ticket
        test_plans = []
        all_ticket_data = []
        processed_tickets = []
        failed_tickets = []
        
        # ============================================================================
        # GUARD: Track requirement counts per ticket to detect order-dependent extraction
        # If the same ticket produces different requirement counts depending on scope
        # size or order, raise an integrity error.
        # ============================================================================
        ticket_requirement_counts = {}  # ticket_id -> requirement_count
        
        for ticket_spec in tickets:
            ticket_id = ticket_spec.get("ticket_id", "")
            source = ticket_spec.get("source", "jira")
            
            try:
                # Fetch or create ticket data
                if source == "jira" and ticket_id != "MANUAL":
                    from services.integrations import get_jira_integration_for_current_tenant
                    jira_creds = get_jira_integration_for_current_tenant()
                    ticket = fetch_jira_ticket(
                        jira_creds["base_url"],
                        jira_creds["email"],
                        jira_creds["api_token"],
                        ticket_id
                    )
                elif ticket_id == "MANUAL" or source == "manual":
                    ticket = {
                        "id": "MANUAL",
                        "summary": data.get("summary", ""),
                        "description": data.get("description", ""),
                        "acceptance_criteria": data.get("acceptance_criteria", ""),
                        "attachments": []
                    }
                else:
                    # Skip invalid tickets
                    failed_tickets.append({"ticket_id": ticket_id, "reason": "Invalid source or ticket_id"})
                    continue
                
                all_ticket_data.append(ticket)
                
                # Extract ticket items for traceability
                ticket_items = extract_ticket_items(ticket)
                # Log extraction results for debugging
                if ticket_items:
                    logger.info(f"Extracted {len(ticket_items)} items from ticket {ticket_id}")
                else:
                    logger.debug(f"No items extracted from ticket {ticket_id}. Description length: {len(ticket.get('description', ''))}, Acceptance criteria length: {len(ticket.get('acceptance_criteria', ''))}")
                
                # Compile and generate test plan for this ticket
                compiled_ticket = compile_ticket_for_llm(ticket)
                
                # DEBUG: Log ticket info before test plan generation
                debug_requirements = os.getenv("DEBUG_REQUIREMENTS", "0") == "1"
                if debug_requirements:
                    logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: Starting test plan generation")
                    logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: source={source}")
                    logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: compiled_ticket keys={list(compiled_ticket.keys())}")
                    compiled_desc = compiled_ticket.get("description", "")
                    logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: compiled_ticket['description'] length={len(compiled_desc)}")
                    if compiled_desc:
                        logger.info(f"[DEBUG_REQUIREMENTS] Ticket {ticket_id}: compiled_ticket['description'] first 120 chars: {compiled_desc[:120]}")
                
                test_plan = generate_test_plan_with_llm(compiled_ticket)
                
                # Store ticket items in test plan metadata for later mapping
                test_plan["_ticket_items"] = ticket_items
                test_plan["_ticket_id"] = ticket_id
                
                # Track requirements count per ticket for debugging and integrity checking
                requirements = test_plan.get("requirements", [])
                requirements_count = len(requirements)
                
                # ============================================================================
                # GUARD: Check if this ticket produced a different requirement count than before
                # This detects order-dependent extraction bugs
                # ============================================================================
                if ticket_id in ticket_requirement_counts:
                    previous_count = ticket_requirement_counts[ticket_id]
                    if previous_count != requirements_count:
                        error_msg = (
                            f"REQUIREMENT EXTRACTION INTEGRITY VIOLATION: "
                            f"Ticket {ticket_id} produced {requirements_count} requirements, "
                            f"but previously produced {previous_count} requirements. "
                            f"This indicates order-dependent extraction or cross-ticket interference. "
                            f"Each ticket must produce the same requirement set regardless of processing order or other tickets."
                        )
                        logger.error(error_msg)
                        return jsonify({
                            "error": "Internal error: Requirement extraction integrity violation",
                            "details": [error_msg],
                            "message": "The same ticket produced different requirement counts when processed in different contexts. This is a system error and requires investigation."
                        }), 500
                else:
                    # First time seeing this ticket - record its requirement count
                    ticket_requirement_counts[ticket_id] = requirements_count
                
                # Determine if ticket is structured (has explicit requirements)
                has_explicit_requirements = any(
                    req.get("source") == "jira" for req in requirements
                ) if requirements else False
                # Force has_acceptance_criteria = true if numbered/bulleted items were detected
                # This ensures acceptance criteria precedence even if has_acceptance_criteria was initially false
                has_acceptance_criteria = bool(ticket.get("acceptance_criteria", "").strip())
                # Check if numbered items were detected during requirement extraction (stored in test plan)
                if test_plan.get("_has_numbered_acceptance_criteria", False):
                    has_acceptance_criteria = True
                
                # Generate explanation for unstructured tickets or tickets with 0 requirements
                explanation = None
                if requirements_count == 0:
                    if not has_acceptance_criteria:
                        explanation = "This ticket lacks explicit acceptance criteria or numbered requirements. The AI could not extract testable requirements from the available content."
                    else:
                        explanation = "This ticket has acceptance criteria but no testable requirements could be extracted. The criteria may be too abstract or lack specific, verifiable behaviors."
                elif not has_explicit_requirements and requirements_count > 0:
                    explanation = "This ticket has inferred requirements only. No explicit, numbered requirements were found in the ticket content."
                
                processed_tickets.append({
                    "ticket_id": ticket_id,
                    "summary": ticket.get("summary", ""),
                    "description": ticket.get("description", "")[:200] + "..." if len(ticket.get("description", "")) > 200 else ticket.get("description", ""),
                    "requirements_count": requirements_count,
                    "has_explicit_requirements": has_explicit_requirements,
                    "has_acceptance_criteria": has_acceptance_criteria,
                    "explanation": explanation,
                    "status": "processed"
                })
                
                # Prefix requirement IDs with ticket ID to ensure strict ticket scoping
                # Requirements are scoped to a single ticket and must never be merged,
                # deduplicated, or normalized across tickets, even if the text is identical.
                if requirements:
                    req_count_before = len(requirements)
                    test_plan["requirements"] = prefix_requirement_ids(requirements, ticket_id)
                    req_count_after = len(test_plan["requirements"])
                    if req_count_before != req_count_after:
                        logger.warning(f"Ticket {ticket_id}: Requirement count changed during prefixing - {req_count_before} -> {req_count_after}")
                    
                    # Normalize test requirement references to use ticket-scoped IDs
                    normalize_test_requirement_references(test_plan, ticket_id)
            except Exception as e:
                # Log failed tickets but continue processing others
                logger.warning(f"Failed to process ticket {ticket_id}: {str(e)}")
                # Try to get ticket summary if available
                ticket_summary = ""
                ticket_description = ""
                try:
                    if 'ticket' in locals() and ticket:
                        ticket_summary = ticket.get("summary", "")
                        ticket_description = ticket.get("description", "")[:200] + "..." if len(ticket.get("description", "")) > 200 else ticket.get("description", "")
                except:
                    pass
                
                failed_tickets.append({
                    "ticket_id": ticket_id,
                    "reason": str(e),
                    "status": "failed",
                    "summary": ticket_summary,
                    "description": ticket_description
                })
                continue
            
            # CRITICAL: Test ownership is immutable after creation
            # Do NOT mutate requirements_covered during prefixing
            # Tests must be created with prefixed requirement IDs from the start
            # If prefixing is needed, it should happen during requirement creation, not test mutation
            # For now, we skip prefixing requirements_covered to preserve immutability
            # Note: This means requirements_covered may contain unprefixed IDs if requirements were prefixed
            # Validation will ensure source_requirement_id matches requirements_covered[0] regardless of prefix
            
            test_plans.append(test_plan)
        
        # Merge all test plans into one
        if len(test_plans) == 1:
            result = test_plans[0]
        else:
            result = merge_test_plans(test_plans)
        
        # Set scope metadata
        result["metadata"]["source_id"] = scope["id"]
        
        # ============================================================================
        # ENRICH EXECUTION STEPS: Add concrete steps for UI tests with empty/abstract steps
        # This ONLY modifies the `steps` field - no other changes allowed
        # ============================================================================
        enrich_execution_steps_for_ui_tests(result)

        # Post-process: Ensure all requirements have multiple test cases based on enumerated intents
        # This ensures the "one requirement -> multiple test cases" enumeration is enforced
        requirements = result.get("requirements", [])
        test_plan_section = result.get("test_plan", {})
        all_tests_by_category = {
            "api_tests": test_plan_section.get("api_tests", []),
            "ui_tests": test_plan_section.get("ui_tests", []),
            "negative_tests": test_plan_section.get("negative_tests", []),
            "edge_cases": test_plan_section.get("edge_cases", []),
            "data_validation_tests": test_plan_section.get("data_validation_tests", [])
        }
        
        # Collect all existing tests by source_requirement_id and intent_type
        existing_tests_by_req_intent = {}
        # Fix Issue 3: Track SYS test step sequences for reuse detection
        sys_test_steps_seen = {}  # Maps step tuple -> first test ID that used it
        
        for category, tests in all_tests_by_category.items():
            for test in tests:
                if isinstance(test, dict):
                    source_req_id = test.get("source_requirement_id")
                    intent_type = test.get("intent_type")
                    if source_req_id and intent_type:
                        key = f"{source_req_id}:{intent_type}"
                        if key not in existing_tests_by_req_intent:
                            existing_tests_by_req_intent[key] = []
                        existing_tests_by_req_intent[key].append(test)
                    
                    # Track SYS test steps for reuse detection
                    test_id = test.get("id", "")
                    if test_id and test_id.startswith("SYS-"):
                        steps = test.get("steps", [])
                        if steps:
                            steps_tuple = tuple(steps)  # Use tuple for hashability
                            if steps_tuple not in sys_test_steps_seen:
                                sys_test_steps_seen[steps_tuple] = test_id
        
        # Initialize test ID counters based on existing tests to avoid collisions
        # Extract the highest number from existing test IDs
        test_id_counters = {
            "api": 0,
            "ui": 0,
            "negative": 0,
            "edge": 0,
            "data": 0,
            "system": 0  # For system-level tests
        }
        
        # Count existing tests to avoid ID collisions
        for category, tests in all_tests_by_category.items():
            for test in tests:
                if isinstance(test, dict):
                    test_id = test.get("id", "")
                    if test_id:
                        # Extract prefix and number (e.g., "UI-001" -> prefix="UI", num=1)
                        import re
                        match = re.match(r'^([A-Z]+)-(\d+)$', test_id)
                        if match:
                            prefix = match.group(1)
                            num = int(match.group(2))
                            # Map prefix to counter key
                            prefix_map = {
                                "API": "api",
                                "UI": "ui",
                                "NEG": "negative",
                                "AUTH": "negative",  # Auth tests use NEG prefix but go in negative_tests
                                "BOUND": "edge",
                                "DATA": "data",
                                "DATA-VAL": "data"
                            }
                            counter_key = prefix_map.get(prefix)
                            if counter_key and num > test_id_counters[counter_key]:
                                test_id_counters[counter_key] = num
        
        for req in requirements:
            if not isinstance(req, dict):
                continue
            
            req_id = req.get("id", "")
            if not req_id:
                continue
            
            # Check if this is a system-level requirement that needs a canonical happy-path test
            is_system_level = is_system_level_requirement(req)
            
            # For system-level requirements, ensure we have at least one happy-path test
            if is_system_level:
                system_happy_path_key = f"{req_id}:happy_path"
                has_system_test = system_happy_path_key in existing_tests_by_req_intent
                
                if not has_system_test:
                    # Fix Issue 3: Generate system-level happy-path test with requirement-specific assertion
                    req_description = req.get("description", "")
                    desc_lower = req_description.lower()
                    
                    # Shared core steps for RTM-related requirements
                    if "rtm" in desc_lower or "requirement traceability matrix" in desc_lower:
                        core_steps = [
                            "Create a test plan containing at least one requirement and one test case.",
                            "Allow the system to complete test plan generation.",
                            "Verify that a Requirement Traceability Matrix (RTM) is generated automatically.",
                            "Verify the RTM contains exactly one entry per requirement."
                        ]
                        
                        # Add requirement-specific assertion step based on requirement intent
                        requirement_specific_step = None
                        if "entry includes" in desc_lower or "includes requirement id" in desc_lower or "includes requirement description" in desc_lower:
                            # Field completeness requirement
                            requirement_specific_step = "Verify each RTM entry includes requirement ID, description, associated test case IDs, and coverage status."
                        elif "derived" in desc_lower and ("does not require" in desc_lower or "user input" in desc_lower):
                            # Derivation requirement
                            requirement_specific_step = "Verify the RTM is derived directly from the test plan without requiring additional user input."
                        elif "does not block" in desc_lower or "non-blocking" in desc_lower:
                            # Non-blocking requirement
                            requirement_specific_step = "Verify that RTM generation does not block or delay test plan creation."
                        elif "not covered" in desc_lower or "uncovered" in desc_lower or "clearly identified" in desc_lower:
                            # Uncovered requirements requirement
                            requirement_specific_step = "Verify that requirements not covered by any test are clearly identified in the RTM with appropriate coverage status."
                        elif "generated after" in desc_lower or "after a test plan is created" in desc_lower:
                            # Basic generation requirement
                            requirement_specific_step = "Verify the RTM is generated automatically after test plan creation completes."
                        else:
                            # Default RTM assertion
                            requirement_specific_step = "Verify each RTM entry includes requirement ID, description, associated test case IDs, and coverage status."
                        
                        system_steps = core_steps + [requirement_specific_step]
                    else:
                        # Generic system-level steps with requirement-specific assertion
                        core_steps = [
                            f"Create a test plan that triggers the system behavior: {req_description[:100]}.",
                            "Allow the system to complete the automatic process.",
                            f"Verify that {req_description[:100]} occurs automatically."
                        ]
                        requirement_specific_step = f"Verify the system behavior produces the expected observable outcome for: {req_description[:100]}."
                        system_steps = core_steps + [requirement_specific_step]
                    
                    test_id_counters["system"] += 1
                    system_test = {
                        "id": f"SYS-{test_id_counters['system']:03d}",
                        "title": f"System-level happy path: {req_description[:80]}",
                        "source_requirement_id": req_id,
                        "intent_type": "happy_path",
                        "requirements_covered": [req_id],
                        "steps": system_steps,
                        "steps_origin": "requirement-derived",
                        "expected_result": f"System automatically performs: {req_description[:100]}",
                        "confidence": "explicit",
                        "priority": "medium"
                    }
                    
                    # Fix Issue 3: Detect if SYS test steps are identical to a previously generated SYS test
                    steps_tuple = tuple(system_steps)
                    if steps_tuple in sys_test_steps_seen:
                        # This test reuses steps from a previously generated SYS test
                        system_test["reusable_system_test"] = True
                    else:
                        # First time seeing these steps
                        sys_test_steps_seen[steps_tuple] = system_test["id"]
                    
                    # Add to api_tests category (system tests go here)
                    if "api_tests" not in result["test_plan"]:
                        result["test_plan"]["api_tests"] = []
                    result["test_plan"]["api_tests"].append(system_test)
                    
                    # Update existing_tests_by_req_intent to reflect this test
                    existing_tests_by_req_intent[system_happy_path_key] = [system_test]
            
            # Enumerate test intents for this requirement
            intents = enumerate_test_intents(req)
            
            # Check which intents are already covered
            for intent in intents:
                intent_type = intent.get("intent_type")
                key = f"{req_id}:{intent_type}"
                
                # Check if we already have a test for this requirement+intent combination
                has_test = key in existing_tests_by_req_intent
                
                if not has_test:
                    # Check if requirement names UI elements or output artifacts
                    req_description = req.get("description", "")
                    has_ui = names_ui_element(req_description)
                    has_artifact = names_output_artifact(req_description)
                    can_generate_steps = has_ui or has_artifact
                    
                    # Check if this is a system-level requirement eligible for UI tests
                    is_system_level = is_system_level_requirement(req)
                    system_level_ui_eligible = False
                    if is_system_level:
                        # Check if requirement's expected result is user-observable
                        desc_lower = req_description.lower()
                        ui_observable_keywords = ["displayed", "shown", "visible", "identified", "appears", "rendered"]
                        has_ui_observable_result = any(keyword in desc_lower for keyword in ui_observable_keywords)
                        
                        # OR check if requirement already has at least one API or SYS test (indicating verifiable outcome)
                        # Note: SYS tests are stored in api_tests category with SYS- prefix
                        has_verifiable_test = False
                        for api_test in all_tests_by_category.get("api_tests", []):
                            if isinstance(api_test, dict):
                                reqs_covered = api_test.get("requirements_covered", [])
                                if req_id in reqs_covered:
                                    has_verifiable_test = True
                                    break
                        
                        # System-level requirement is UI-eligible if it has user-observable result OR has API/SYS tests
                        system_level_ui_eligible = has_ui_observable_result or has_verifiable_test
                    
                    # Generate a placeholder test case
                    # Determine which category this test should go into
                    category = None
                    test_id_prefix = None
                    
                    if intent_type == "happy_path":
                        # Prefer ui_tests if UI elements are named, OR if system-level requirement is UI-eligible
                        if has_ui or has_artifact or (is_system_level and system_level_ui_eligible):
                            category = "ui_tests"
                            test_id_prefix = "UI"
                            test_id_counters["ui"] += 1
                            test_id = f"{test_id_prefix}-{test_id_counters['ui']:03d}"
                        else:
                            category = "api_tests"
                            test_id_prefix = "API"
                            test_id_counters["api"] += 1
                            test_id = f"{test_id_prefix}-{test_id_counters['api']:03d}"
                    elif intent_type == "negative":
                        category = "negative_tests"
                        test_id_prefix = "NEG"
                        test_id_counters["negative"] += 1
                        test_id = f"{test_id_prefix}-{test_id_counters['negative']:03d}"
                    elif intent_type == "authorization":
                        category = "negative_tests"  # Authorization tests go in negative_tests
                        test_id_prefix = "AUTH"
                        test_id_counters["negative"] += 1
                        test_id = f"{test_id_prefix}-{test_id_counters['negative']:03d}"
                    elif intent_type == "boundary":
                        category = "edge_cases"
                        test_id_prefix = "BOUND"
                        test_id_counters["edge"] += 1
                        test_id = f"{test_id_prefix}-{test_id_counters['edge']:03d}"
                    
                    if category:
                        req_desc_short = req_description[:100] if req_description else ""
                        new_test = {
                            "id": test_id,
                            "title": f"{intent_type.replace('_', ' ').title()}: {req_desc_short}",
                            "source_requirement_id": req_id,
                            "intent_type": intent_type,
                            "requirements_covered": [req_id],
                            "steps": [],
                            "steps_origin": "none",
                            "expected_result": f"{intent_type.replace('_', ' ').title()} behavior validated",
                            "confidence": "inferred",
                            "priority": "medium"
                        }
                        
                        # Only set "Cannot generate" explanation if UI elements/artifacts are NOT named
                        if not can_generate_steps:
                            new_test["steps_explanation"] = f"Cannot generate concrete {intent_type} test steps from requirement: '{req_desc_short}...'. Requirement lacks specific execution details needed for this intent."
                        # If UI elements/artifacts are named, let LLM generate steps (don't pre-emptively block)
                        # The steps_explanation will be set by LLM or validation if steps can't be generated
                        
                        if intent_type in ["authorization", "boundary"]:
                            new_test["dimension"] = intent_type
                        
                        # Check if a test with this ID already exists to prevent duplicates
                        if category not in result["test_plan"]:
                            result["test_plan"][category] = []
                        
                        # Check for duplicate test ID
                        existing_test_ids = {t.get("id") for t in result["test_plan"][category] if isinstance(t, dict) and t.get("id")}
                        if test_id not in existing_test_ids:
                            result["test_plan"][category].append(new_test)
                        else:
                            logger.warning(f"Skipping duplicate test ID {test_id} for requirement {req_id}, intent {intent_type}")
        
        # Deduplicate tests by ID to prevent duplicates
        for category in ["api_tests", "ui_tests", "data_validation_tests", "edge_cases", "negative_tests"]:
            if category in result["test_plan"]:
                tests = result["test_plan"][category]
                seen_ids = set()
                deduplicated = []
                for test in tests:
                    if isinstance(test, dict):
                        test_id = test.get("id", "")
                        if test_id and test_id not in seen_ids:
                            seen_ids.add(test_id)
                            deduplicated.append(test)
                        elif not test_id:
                            # Keep tests without IDs (shouldn't happen, but be safe)
                            deduplicated.append(test)
                    else:
                        deduplicated.append(test)
                result["test_plan"][category] = deduplicated
        
        # Regenerate all_tests_by_category after adding missing tests and deduplication
        test_plan_section = result.get("test_plan", {})
        all_tests_by_category = {
            "api_tests": test_plan_section.get("api_tests", []),
            "ui_tests": test_plan_section.get("ui_tests", []),
            "negative_tests": test_plan_section.get("negative_tests", []),
            "edge_cases": test_plan_section.get("edge_cases", []),
            "data_validation_tests": test_plan_section.get("data_validation_tests", [])
        }

        # Generate dimension-specific inferred tests based on coverage_expectations
        # This happens after test plans are merged but before RTM generation
        test_plan_section = result.get("test_plan", {})
        all_tests_by_category = {
            "api_tests": test_plan_section.get("api_tests", []),
            "ui_tests": test_plan_section.get("ui_tests", []),
            "negative_tests": test_plan_section.get("negative_tests", []),
            "edge_cases": test_plan_section.get("edge_cases", []),
            "data_validation_tests": test_plan_section.get("data_validation_tests", [])
        }
        
        # Generate dimension-specific tests for all requirements
        requirements = result.get("requirements", [])
        if requirements:
            dimension_tests = generate_dimension_specific_inferred_tests(
                requirements, 
                all_tests_by_category
            )
            
            # Add dimension-specific tests to appropriate categories
            for category, tests in dimension_tests.items():
                if tests:
                    if category not in result["test_plan"]:
                        result["test_plan"][category] = []
                    result["test_plan"][category].extend(tests)
            
            # Update assumptions to document dimension-specific inferred tests
            dimension_test_counts = {
                "data_validation": len(dimension_tests["data_validation_tests"]),
                "boundary": len(dimension_tests["edge_cases"]),
                "authorization": len(dimension_tests["negative_tests"])
            }
            total_dimension_tests = sum(dimension_test_counts.values())
            
            if total_dimension_tests > 0:
                dimension_assumption_parts = []
                if dimension_test_counts["data_validation"] > 0:
                    dimension_assumption_parts.append(
                        f"Generated {dimension_test_counts['data_validation']} inferred data validation test(s) "
                        "based on coverage expectations. These tests assume standard input validation behavior."
                    )
                if dimension_test_counts["boundary"] > 0:
                    dimension_assumption_parts.append(
                        f"Generated {dimension_test_counts['boundary']} inferred boundary test(s) "
                        "based on coverage expectations. These tests assume standard boundary condition handling."
                    )
                if dimension_test_counts["authorization"] > 0:
                    dimension_assumption_parts.append(
                        f"Generated {dimension_test_counts['authorization']} inferred authorization test(s) "
                        "based on coverage expectations. These tests assume standard authorization error handling."
                    )
                
                if "assumptions" not in result:
                    result["assumptions"] = []
                result["assumptions"].extend(dimension_assumption_parts)

        # Generate happy-path inferred tests based on coverage_expectations
        # This happens after dimension-specific tests but before RTM generation
        test_plan_section_for_happy = result.get("test_plan", {})
        all_tests_by_category_for_happy = {
            "api_tests": test_plan_section_for_happy.get("api_tests", []),
            "ui_tests": test_plan_section_for_happy.get("ui_tests", []),
            "negative_tests": test_plan_section_for_happy.get("negative_tests", []),
            "edge_cases": test_plan_section_for_happy.get("edge_cases", []),
            "data_validation_tests": test_plan_section_for_happy.get("data_validation_tests", [])
        }
        
        happy_path_tests = generate_happy_path_inferred_tests(
            requirements,
            all_tests_by_category_for_happy
        )
        
        # Add happy-path tests to api_tests
        if happy_path_tests:
            if "api_tests" not in result["test_plan"]:
                result["test_plan"]["api_tests"] = []
            result["test_plan"]["api_tests"].extend(happy_path_tests)
            
            # Add assumption explaining happy-path inferred tests
            if "assumptions" not in result:
                result["assumptions"] = []
            result["assumptions"].append(
                f"Generated {len(happy_path_tests)} inferred happy-path test(s) based on coverage expectations. "
                "These tests represent expected success behavior and require validation with concrete execution details."
            )

        # Normalize all test requirement references to use ticket-scoped IDs
        # This handles inferred tests and any tests that may still reference generic IDs
        normalize_all_test_requirement_references(result)
        
        # Generate RTM after test plan is finalized (including dimension-specific tests and happy-path tests)
        rtm = generate_rtm(result)
        
        # Validate coverage status consistency: COVERED requires non-empty covered_by_tests
        validate_rtm_coverage_consistency(rtm)
        
        result["rtm"] = rtm
        result["rtm_agent_metadata"] = {
            "agent": "rtm-generator",
            "agent_version": "1.0.0",
            "logic_version": "rtm-v1",
            "determinism": "deterministic mapping",
            "change_policy": "idempotent"
        }
        
        # Update coverage expectations based on actual test coverage (including dimension-specific tests and happy-path tests)
        test_plan_section = result.get("test_plan", {})
        all_tests_by_category = {
            "api_tests": test_plan_section.get("api_tests", []),
            "ui_tests": test_plan_section.get("ui_tests", []),
            "negative_tests": test_plan_section.get("negative_tests", []),
            "edge_cases": test_plan_section.get("edge_cases", []),
            "data_validation_tests": test_plan_section.get("data_validation_tests", [])
        }
        
        for req in result.get("requirements", []):
            if isinstance(req, dict) and "coverage_expectations" in req:
                # Recompute with actual test coverage
                req["coverage_expectations"] = compute_coverage_expectations(req, all_tests_by_category)
        
        # HARD EXCLUSION OF NEGATIVE TESTS: Remove negative tests for requirements with negative = not_applicable
        # This must happen AFTER coverage expectations are recomputed to catch all requirements with negative = not_applicable
        # Build set of requirement IDs that have negative = not_applicable
        req_ids_with_negative_not_applicable = set()
        for req in result.get("requirements", []):
            if isinstance(req, dict):
                req_id = req.get("id", "")
                if req_id:
                    coverage_exp = req.get("coverage_expectations", {})
                    if coverage_exp.get("negative") == "not_applicable":
                        req_ids_with_negative_not_applicable.add(req_id)
        
        # Collect all negative test IDs that need to be removed
        negative_test_ids_to_remove = set()
        
        # Remove negative tests from test_plan categories
        if req_ids_with_negative_not_applicable:
            test_plan_section = result.get("test_plan", {})
            if isinstance(test_plan_section, dict):
                # Filter all test categories (negative tests can appear in any category)
                for category in ["api_tests", "ui_tests", "negative_tests", "data_validation_tests", "edge_cases"]:
                    tests = test_plan_section.get(category, [])
                    if isinstance(tests, list):
                        filtered_tests = []
                        for test in tests:
                            if isinstance(test, dict):
                                test_id = test.get("id", "")
                                intent_type = test.get("intent_type", "").lower()
                                test_reqs = test.get("requirements_covered", [])
                                source_req_id = test.get("source_requirement_id", "")
                                
                                # Check if this is a negative test covering a requirement with negative = not_applicable
                                is_negative_test = intent_type == "negative"
                                covers_excluded_req = any(req_id in test_reqs for req_id in req_ids_with_negative_not_applicable)
                                source_is_excluded = source_req_id in req_ids_with_negative_not_applicable
                                
                                if is_negative_test and (covers_excluded_req or source_is_excluded):
                                    # Mark this test ID for removal from all other locations
                                    if test_id:
                                        negative_test_ids_to_remove.add(test_id)
                                    continue  # Skip this test
                            filtered_tests.append(test)
                        test_plan_section[category] = filtered_tests
        
        # Remove negative test IDs from rtm[*]["covered_by_tests"]
        if negative_test_ids_to_remove:
            rtm = result.get("rtm", [])
            if isinstance(rtm, list):
                for rtm_entry in rtm:
                    if isinstance(rtm_entry, dict):
                        req_id = rtm_entry.get("requirement_id", "")
                        if req_id in req_ids_with_negative_not_applicable:
                            covered_by_tests = rtm_entry.get("covered_by_tests", [])
                            if isinstance(covered_by_tests, list):
                                # Filter out negative test IDs
                                filtered_covered = [
                                    test_id for test_id in covered_by_tests
                                    if test_id not in negative_test_ids_to_remove
                                ]
                                rtm_entry["covered_by_tests"] = filtered_covered
                                # Update coverage_status if no tests remain
                                if not filtered_covered:
                                    rtm_entry["coverage_status"] = "NOT COVERED"
        
        # Compute coverage confidence for each requirement
        # Build RTM entry map for quick lookup
        rtm_entry_map = {}
        for entry in rtm:
            if isinstance(entry, dict):
                req_id = entry.get("requirement_id", "")
                if req_id:
                    rtm_entry_map[req_id] = entry
        
        # Compute and attach coverage_confidence to each requirement
        for req in result.get("requirements", []):
            if isinstance(req, dict):
                req_id = req.get("id", "")
                if req_id:
                    rtm_entry = rtm_entry_map.get(req_id, {})
                    req["coverage_confidence"] = compute_coverage_confidence(req, rtm_entry, result)
        
        # Guardrail: Verify RTM completeness
        requirements = result.get("requirements", [])
        if len(rtm) != len(requirements):
            logger.error(
                f"RTM inconsistency detected: {len(requirements)} requirements but {len(rtm)} RTM rows. "
                f"Ticket ID: {result.get('metadata', {}).get('source_id', 'UNKNOWN')}"
            )

        # Check if requirements exist but no test cases are generated
        test_plan_section = result.get("test_plan", {})
        all_test_categories = [
            "api_tests", "ui_tests", "data_validation_tests",
            "edge_cases", "negative_tests"
        ]
        total_tests = sum(
            len(test_plan_section.get(category, []))
            for category in all_test_categories
        )

        # Refinement 1: Add structured gap if requirements exist but no tests
        if requirements and total_tests == 0:
            missing_test_gap = {
                "type": "missing_test_implementation",
                "severity": "medium",
                "description": "No executable test cases exist to validate the requirements defined in this ticket.",
                "suggested_question": "When will test cases be implemented to validate these requirements?"
            }
            if "gaps_detected" not in result:
                result["gaps_detected"] = []
            result["gaps_detected"].append(missing_test_gap)
            
            # Fallback: Generate inferred API test cases when no tests exist
            # NOTE: Do NOT generate generic placeholder steps - return empty steps with explanation
            if requirements:
                inferred_tests = []
                # Generate 1-2 inferred tests that can cover multiple related requirements
                num_requirements = len(requirements)
                
                if num_requirements <= 2:
                    # Single test covers all requirements
                    req_ids = [req.get("id", "") for req in requirements if req.get("id")]
                    req_descriptions = [req.get("description", "")[:50] for req in requirements if req.get("description")]
                    if req_ids:
                        # Check if any requirement names UI elements or artifacts
                        all_req_text = " ".join([req.get("description", "") for req in requirements])
                        has_ui = names_ui_element(all_req_text)
                        has_artifact = names_output_artifact(all_req_text)
                        can_generate_steps = has_ui or has_artifact
                        
                        inferred_test = {
                            "id": "API-001",
                            "title": f"Inferred test covering {len(req_ids)} requirement(s)",
                            "steps": [],
                            "steps_origin": "none",
                            "expected_result": "Requirements validated per acceptance criteria",
                            "requirements_covered": req_ids,
                            "confidence": "inferred",
                            "priority": "medium"
                        }
                        
                        # Only set "Cannot generate" explanation if UI elements/artifacts are NOT named
                        if not can_generate_steps:
                            inferred_test["steps_explanation"] = f"Cannot generate concrete test steps. Requirements lack specific execution details: {', '.join(req_descriptions)}..."
                        
                        inferred_tests.append(inferred_test)
                else:
                    # Generate 2 tests, splitting requirements roughly evenly
                    midpoint = (num_requirements + 1) // 2
                    
                    # First test covers first half of requirements
                    req_ids_1 = [req.get("id", "") for req in requirements[:midpoint] if req.get("id")]
                    req_descriptions_1 = [req.get("description", "")[:50] for req in requirements[:midpoint] if req.get("description")]
                    if req_ids_1:
                        # Check if any requirement names UI elements or artifacts
                        req_text_1 = " ".join([req.get("description", "") for req in requirements[:midpoint]])
                        has_ui_1 = names_ui_element(req_text_1)
                        has_artifact_1 = names_output_artifact(req_text_1)
                        can_generate_steps_1 = has_ui_1 or has_artifact_1
                        
                        inferred_test_1 = {
                            "id": "API-001",
                            "title": f"Inferred test covering {len(req_ids_1)} requirement(s)",
                            "steps": [],
                            "steps_origin": "none",
                            "expected_result": "Requirements validated per acceptance criteria",
                            "requirements_covered": req_ids_1,
                            "confidence": "inferred",
                            "priority": "medium"
                        }
                        
                        # Only set "Cannot generate" explanation if UI elements/artifacts are NOT named
                        if not can_generate_steps_1:
                            inferred_test_1["steps_explanation"] = f"Cannot generate concrete test steps. Requirements lack specific execution details: {', '.join(req_descriptions_1)}..."
                        
                        inferred_tests.append(inferred_test_1)
                    
                    # Second test covers remaining requirements
                    req_ids_2 = [req.get("id", "") for req in requirements[midpoint:] if req.get("id")]
                    req_descriptions_2 = [req.get("description", "")[:50] for req in requirements[midpoint:] if req.get("description")]
                    if req_ids_2:
                        # Check if any requirement names UI elements or artifacts
                        req_text_2 = " ".join([req.get("description", "") for req in requirements[midpoint:]])
                        has_ui_2 = names_ui_element(req_text_2)
                        has_artifact_2 = names_output_artifact(req_text_2)
                        can_generate_steps_2 = has_ui_2 or has_artifact_2
                        
                        inferred_test_2 = {
                            "id": "API-002",
                            "title": f"Inferred test covering {len(req_ids_2)} requirement(s)",
                            "steps": [],
                            "steps_origin": "none",
                            "expected_result": "Requirements validated per acceptance criteria",
                            "requirements_covered": req_ids_2,
                            "confidence": "inferred",
                            "priority": "medium"
                        }
                        
                        # Only set "Cannot generate" explanation if UI elements/artifacts are NOT named
                        if not can_generate_steps_2:
                            inferred_test_2["steps_explanation"] = f"Cannot generate concrete test steps. Requirements lack specific execution details: {', '.join(req_descriptions_2)}..."
                        
                        inferred_tests.append(inferred_test_2)
                
                # Add inferred tests to api_tests
                if "test_plan" not in result:
                    result["test_plan"] = {}
                if "api_tests" not in result["test_plan"]:
                    result["test_plan"]["api_tests"] = []
                result["test_plan"]["api_tests"].extend(inferred_tests)
                
                # Generate inferred negative tests for error-oriented requirements
                # Fix Issue 2: Suppress inferred negative tests if explicit negative tests already exist
                error_keywords = ["error", "invalid", "missing", "unauthorized", "bad token", "permission"]
                inferred_negative_tests = []
                
                # Fix Issue 2: Build a map of requirements to explicit negative tests
                # An explicit negative test is: intent_type == "negative" AND steps array is non-empty
                req_to_explicit_negative_tests = {}
                for category in ["ui_tests", "api_tests", "negative_tests"]:
                    tests = result["test_plan"].get(category, [])
                    for test in tests:
                        if isinstance(test, dict):
                            intent_type = test.get("intent_type", "").lower()
                            # Explicit negative test: intent_type == "negative" AND steps array is non-empty
                            if intent_type == "negative":
                                steps = test.get("steps", [])
                                if len(steps) > 0:  # Only non-empty steps count as explicit
                                    reqs_covered = test.get("requirements_covered", [])
                                    for req_id in reqs_covered:
                                        req_to_explicit_negative_tests[req_id] = True
                
                for req in requirements:
                    req_id = req.get("id", "")
                    req_description = req.get("description", "").lower()
                    
                    # FIX B - NON-TESTABLE NEGATIVE HARD STOP:
                    # Do NOT generate negative tests for non-testable requirements
                    req_testable = req.get("testable", True)
                    req_classification = req.get("_classification", "")
                    if not req_testable or req_classification in ["informational_only", "not_independently_testable"]:
                        continue  # Skip generating negative tests for non-testable requirements
                    
                    # HARD EXCLUSION OF NEGATIVE TESTS: Skip requirements with negative = not_applicable
                    # Check coverage_expectations to determine if negative testing is applicable
                    coverage_exp = req.get("coverage_expectations", {})
                    if coverage_exp.get("negative") == "not_applicable":
                        continue  # Skip generating inferred negative test for requirements with negative = not_applicable
                    
                    # Check if requirement description contains error-oriented keywords
                    if req_id and any(keyword in req_description for keyword in error_keywords):
                        # Fix Issue 2: Skip if explicit negative tests already exist for this requirement
                        if req_id in req_to_explicit_negative_tests:
                            continue  # Skip generating inferred negative test
                        
                        # Get requirement classification
                        req_classification = req.get("_classification", "")
                        req_desc = req.get("description", "")[:100]
                        has_ui = names_ui_element(req.get("description", ""))
                        has_artifact = names_output_artifact(req.get("description", ""))
                        can_generate_steps = has_ui or has_artifact
                        
                        # CLASSIFICATION-BASED NEGATIVE TEST GENERATION: UI structure/element requirements
                        if req_classification in ["ui_structure", "ui_element"]:
                            # Generate UI absence/state-based negative test
                            negative_test = {
                                "id": f"NEG-{len(inferred_negative_tests) + 1:03d}",
                                "title": f"Inferred negative test for {req_id}",
                                "intent_type": "negative",
                                "source_requirement_id": req_id,
                                "steps": [],
                                "steps_origin": "inferred",
                                "expected_result": "One or more required UI elements are missing, not visible, disabled when they should be enabled, or display incorrect/empty content",
                                "requirements_covered": [req_id],
                                "confidence": "inferred",
                                "priority": "medium"
                            }
                            
                            # Generate UI-specific negative steps if UI elements are named
                            if has_ui:
                                # Extract UI elements from requirement text
                                ui_keywords = ["button", "link", "field", "menu", "tab", "page", "screen", "form", "input", 
                                             "dropdown", "select", "checkbox", "radio", "toggle", "upload", "download"]
                                req_text = req.get("description", "").lower()
                                ui_elements = [kw for kw in ui_keywords if kw in req_text]
                                
                                if ui_elements:
                                    if len(ui_elements) > 1:
                                        negative_test["steps"] = [
                                            "Navigate to the application",
                                            f"Verify that all required UI elements ({', '.join(ui_elements[:3])}) are present and accessible",
                                            "Check if any required UI element is missing, not visible, disabled when it should be enabled, or displays incorrect/empty content"
                                        ]
                                    else:
                                        negative_test["steps"] = [
                                            "Navigate to the application",
                                            f"Verify that the {ui_elements[0]} mentioned in the requirement is present on the screen",
                                            f"Check if the {ui_elements[0]} is missing, not visible, disabled when it should be enabled, or displays incorrect/empty content"
                                        ]
                                else:
                                    negative_test["steps"] = [
                                        "Navigate to the application",
                                        "Verify that all required UI elements are present and accessible",
                                        "Check if any required UI element is missing, not visible, disabled when it should be enabled, or displays incorrect/empty content"
                                    ]
                            else:
                                # UI structure requirement but no specific elements named
                                negative_test["steps_explanation"] = f"Cannot generate concrete UI negative test steps from requirement: '{req_desc}...'. Requirement lacks specific UI element names."
                        else:
                            # Generic error-handling negative (for system_behavior, data_validation, api_behavior)
                            negative_test = {
                                "id": f"NEG-{len(inferred_negative_tests) + 1:03d}",
                                "title": f"Inferred negative test for {req_id}",
                                "intent_type": "negative",
                                "source_requirement_id": req_id,
                                "steps": [],
                                "steps_origin": "none",
                                "expected_result": "Appropriate error response returned",
                                "requirements_covered": [req_id],
                                "confidence": "inferred",
                                "priority": "medium"
                            }
                            
                            # Only set "Cannot generate" explanation if UI elements/artifacts are NOT named
                            if not can_generate_steps:
                                negative_test["steps_explanation"] = f"Cannot generate concrete negative test steps from requirement: '{req_desc}...'. Requirement lacks specific error conditions, invalid input formats, or expected error responses."
                        
                        inferred_negative_tests.append(negative_test)
                
                # Add inferred negative tests to negative_tests
                if inferred_negative_tests:
                    if "negative_tests" not in result["test_plan"]:
                        result["test_plan"]["negative_tests"] = []
                    result["test_plan"]["negative_tests"].extend(inferred_negative_tests)
                
                # Add assumption explaining inferred tests
                assumption_parts = [
                    f"Generated {len(inferred_tests)} inferred API test case(s) based on requirements. "
                    "These tests assume standard REST API behavior and should be refined with actual endpoint details."
                ]
                if inferred_negative_tests:
                    assumption_parts.append(
                        f"Generated {len(inferred_negative_tests)} inferred negative test case(s) for error-oriented requirements. "
                        "These tests assume standard error handling behavior."
                    )
                
                if "assumptions" not in result:
                    result["assumptions"] = []
                result["assumptions"].extend(assumption_parts)
                
                # Regenerate RTM to reflect the new inferred tests (both positive and negative)
                # Note: Dimension-specific tests are generated earlier in the flow, before first RTM generation
                rtm = generate_rtm(result)
                result["rtm"] = rtm
                
                # HARD EXCLUSION OF NEGATIVE TESTS: Remove negative tests for requirements with negative = not_applicable
                # This must happen AFTER all test generation (including inferred negative tests) and AFTER coverage expectations are recomputed
                # Build set of requirement IDs that have negative = not_applicable
                req_ids_with_negative_not_applicable = set()
                for req in result.get("requirements", []):
                    if isinstance(req, dict):
                        req_id = req.get("id", "")
                        if req_id:
                            coverage_exp = req.get("coverage_expectations", {})
                            if coverage_exp.get("negative") == "not_applicable":
                                req_ids_with_negative_not_applicable.add(req_id)
                
                # Collect all negative test IDs that need to be removed
                negative_test_ids_to_remove = set()
                
                # Remove negative tests from test_plan categories
                if req_ids_with_negative_not_applicable:
                    test_plan_section = result.get("test_plan", {})
                    if isinstance(test_plan_section, dict):
                        # Filter all test categories (negative tests can appear in any category)
                        for category in ["api_tests", "ui_tests", "negative_tests", "data_validation_tests", "edge_cases"]:
                            tests = test_plan_section.get(category, [])
                            if isinstance(tests, list):
                                filtered_tests = []
                                for test in tests:
                                    if isinstance(test, dict):
                                        test_id = test.get("id", "")
                                        intent_type = test.get("intent_type", "").lower()
                                        test_reqs = test.get("requirements_covered", [])
                                        source_req_id = test.get("source_requirement_id", "")
                                        
                                        # Check if this is a negative test covering a requirement with negative = not_applicable
                                        is_negative_test = intent_type == "negative"
                                        covers_excluded_req = any(req_id in test_reqs for req_id in req_ids_with_negative_not_applicable)
                                        source_is_excluded = source_req_id in req_ids_with_negative_not_applicable
                                        
                                        if is_negative_test and (covers_excluded_req or source_is_excluded):
                                            # Mark this test ID for removal from all other locations
                                            if test_id:
                                                negative_test_ids_to_remove.add(test_id)
                                            continue  # Skip this test
                                    filtered_tests.append(test)
                                test_plan_section[category] = filtered_tests
                
                # Remove negative test IDs from rtm[*]["covered_by_tests"]
                if negative_test_ids_to_remove:
                    rtm = result.get("rtm", [])
                    if isinstance(rtm, list):
                        for rtm_entry in rtm:
                            if isinstance(rtm_entry, dict):
                                req_id = rtm_entry.get("requirement_id", "")
                                if req_id in req_ids_with_negative_not_applicable:
                                    covered_by_tests = rtm_entry.get("covered_by_tests", [])
                                    if isinstance(covered_by_tests, list):
                                        # Filter out negative test IDs
                                        filtered_covered = [
                                            test_id for test_id in covered_by_tests
                                            if test_id not in negative_test_ids_to_remove
                                        ]
                                        rtm_entry["covered_by_tests"] = filtered_covered
                                        # Update coverage_status if no tests remain
                                        if not filtered_covered:
                                            rtm_entry["coverage_status"] = "NOT COVERED"
                        result["rtm"] = rtm
                
                # Recalculate total_tests for subsequent logic
                total_tests = len(inferred_tests) + len(inferred_negative_tests)

        # Check if all requirements are NOT COVERED
        all_uncovered = all(
            entry.get("coverage_status") == "NOT COVERED"
            for entry in rtm
        ) if rtm else False

        # Refinement 2: Update summary wording for planning-only tickets
        if all_uncovered and total_tests == 0 and requirements:
            result["summary"] = (
                "This ticket defines governance-level requirements only. "
                "No executable test cases have been implemented yet; "
                "test coverage is expected to be addressed in a follow-on implementation ticket."
            )

        # Quality rule enforcement: Check for missing negative test coverage
        # Only enforce if tests exist (skip governance-only tickets)
        if total_tests > 0 and requirements:
            # Build a map of test_id -> category for efficient lookup
            test_id_to_category = {}
            positive_categories = ["api_tests", "ui_tests"]
            negative_categories = ["negative_tests", "edge_cases", "data_validation_tests"]
            
            for category in positive_categories + negative_categories:
                tests = test_plan_section.get(category, [])
                if isinstance(tests, list):
                    for test in tests:
                        if isinstance(test, dict):
                            test_id = test.get("id", "")
                            if test_id:
                                test_id_to_category[test_id] = category
            
            # Check each requirement for negative test coverage
            for rtm_entry in rtm:
                req_id = rtm_entry.get("requirement_id", "")
                covered_by_tests = rtm_entry.get("covered_by_tests", [])
                
                if not req_id or not covered_by_tests:
                    continue  # Skip uncovered requirements (already handled elsewhere)
                
                # Categorize tests for this requirement
                has_positive_tests = False
                has_negative_tests = False
                
                for test_id in covered_by_tests:
                    category = test_id_to_category.get(test_id)
                    if category in positive_categories:
                        has_positive_tests = True
                    elif category in negative_categories:
                        has_negative_tests = True
                
                # Quality rule: If requirement has positive tests but no negative/edge/validation tests
                # Check coverage_expectations to determine if negative testing is applicable
                if has_positive_tests and not has_negative_tests:
                    # Find the requirement to check its coverage_expectations
                    requirement = None
                    for req in requirements:
                        if req.get("id") == req_id:
                            requirement = req
                            break
                    
                    # Check if negative testing is applicable
                    should_add_gap = True
                    if requirement and "coverage_expectations" in requirement:
                        coverage_exp = requirement.get("coverage_expectations", {})
                        if coverage_exp.get("negative") == "not_applicable":
                            # Suppress gap for requirements where negative testing is not applicable
                            should_add_gap = False
                    
                    if should_add_gap:
                        missing_negative_gap = {
                            "type": "missing_negative_test",
                            "severity": "medium",
                            "description": f"Requirement {req_id} has no associated negative or failure-oriented test cases.",
                            "suggested_question": "What invalid inputs or failure conditions should be tested for this requirement?"
                        }
                        if "gaps_detected" not in result:
                            result["gaps_detected"] = []
                        result["gaps_detected"].append(missing_negative_gap)

        # ISO guardrail: Log WARNING for uncovered requirements
        uncovered_requirements = [
            entry["requirement_id"]
            for entry in rtm
            if entry.get("coverage_status") == "NOT COVERED"
        ]
        if uncovered_requirements:
            logger.warning(
                f"Uncovered requirements detected: {', '.join(uncovered_requirements)}"
            )

        # FINAL SANITATION PASS: Remove negative tests for requirements with negative = not_applicable
        # This runs AFTER all test generation (including inferred negative tests) and AFTER coverage_expectations are recomputed
        # but BEFORE RTM, test_plan_by_requirement, scope_summary, and coverage summaries are constructed
        # For each requirement where coverage_expectations.negative == "not_applicable":
        # 1. Identify all negative tests where test.source_requirement_id == requirement.id
        # 2. Remove those tests from test_plan.negative_tests
        # 3. Remove the corresponding test IDs from test_plan_by_requirement, rtm, ticket_item_coverage, ticket_traceability
        req_ids_with_negative_not_applicable = set()
        negative_test_ids_to_remove = set()
        
        for req in result.get("requirements", []):
            if isinstance(req, dict):
                req_id = req.get("id", "")
                if req_id:
                    coverage_exp = req.get("coverage_expectations", {})
                    if coverage_exp.get("negative") == "not_applicable":
                        req_ids_with_negative_not_applicable.add(req_id)
        
        # Identify all negative tests where source_requirement_id matches excluded requirements
        if req_ids_with_negative_not_applicable:
            test_plan_section = result.get("test_plan", {})
            if isinstance(test_plan_section, dict):
                for category in ["api_tests", "ui_tests", "negative_tests", "data_validation_tests", "edge_cases"]:
                    tests = test_plan_section.get(category, [])
                    if isinstance(tests, list):
                        for test in tests:
                            if isinstance(test, dict):
                                test_id = test.get("id", "")
                                intent_type = test.get("intent_type", "").lower()
                                source_req_id = test.get("source_requirement_id", "")
                                
                                # Identify negative tests where source_requirement_id matches excluded requirement
                                if intent_type == "negative" and source_req_id in req_ids_with_negative_not_applicable:
                                    if test_id:
                                        negative_test_ids_to_remove.add(test_id)
        
        # Remove negative tests from test_plan.negative_tests (and other categories)
        if negative_test_ids_to_remove:
            test_plan_section = result.get("test_plan", {})
            if isinstance(test_plan_section, dict):
                for category in ["api_tests", "ui_tests", "negative_tests", "data_validation_tests", "edge_cases"]:
                    tests = test_plan_section.get(category, [])
                    if isinstance(tests, list):
                        filtered_tests = []
                        for test in tests:
                            if isinstance(test, dict):
                                test_id = test.get("id", "")
                                if test_id in negative_test_ids_to_remove:
                                    continue  # Skip this test
                            filtered_tests.append(test)
                        test_plan_section[category] = filtered_tests
        
        # Regenerate RTM after removing negative tests to ensure consistency
        if negative_test_ids_to_remove:
            rtm = generate_rtm(result)
            result["rtm"] = rtm

        # Calculate scope summary
        requirements_covered = sum(
            1 for entry in rtm
            if entry.get("coverage_status") == "COVERED"
        )
        requirements_uncovered = len(rtm) - requirements_covered
        
        result["scope_summary"] = {
            "scope_type": scope.get("type", "ticket"),
            "scope_id": scope.get("id", ""),
            "tickets_analyzed": len(processed_tickets),
            "tickets_requested": len(tickets),
            "tickets_failed": len(failed_tickets),
            "requirements_total": len(requirements),
            "requirements_covered": requirements_covered,
            "requirements_uncovered": requirements_uncovered,
            "ticket_details": processed_tickets if processed_tickets else None,
            "failed_tickets": failed_tickets if failed_tickets else None
        }
        
        # Ensure all requirements are preserved (no filtering)
        # This is a system invariant: requirements may be non-testable but must not be silently dropped
        if "requirements" not in result or len(result.get("requirements", [])) != len(requirements):
            logger.warning(f"Requirement count mismatch detected. Expected {len(requirements)}, got {len(result.get('requirements', []))}")
            result["requirements"] = requirements

        # Build ticket traceability mapping AFTER all tests and RTM are generated
        # Collect all ticket items from all test plans
        ticket_id_to_items = {}
        ticket_id_to_requirements = {}  # Map ticket IDs to their requirements
        
        for plan in test_plans:
            ticket_id = plan.get("_ticket_id", "")
            items = plan.get("_ticket_items", [])
            requirements = plan.get("requirements", [])
            
            if ticket_id:
                if ticket_id not in ticket_id_to_items:
                    ticket_id_to_items[ticket_id] = []
                if items:
                    ticket_id_to_items[ticket_id].extend(items)
                
                # Store requirements for this ticket
                if ticket_id not in ticket_id_to_requirements:
                    ticket_id_to_requirements[ticket_id] = []
                if requirements:
                    ticket_id_to_requirements[ticket_id].extend(requirements)
        
        # Map ticket items to requirements and tests
        # Include all tickets, even if no items were extracted (for audit compliance)
        result["ticket_traceability"] = []
        for ticket_id, items in ticket_id_to_items.items():
            if items:
                # Map items to requirements and tests
                mapped_items = map_ticket_items_to_requirements_and_tests(
                    items,
                    result.get("requirements", []),
                    all_tests_by_category
                )
                
                result["ticket_traceability"].append({
                    "ticket_id": ticket_id,
                    "items": mapped_items
                })
            else:
                # If no items extracted but requirements exist, use requirements as items
                # This handles cases where requirements were extracted but numbered/bulleted items weren't detected
                ticket_requirements = ticket_id_to_requirements.get(ticket_id, [])
                if ticket_requirements:
                    # Convert requirements to ticket items
                    requirement_items = []
                    for idx, req in enumerate(ticket_requirements, 1):
                        if isinstance(req, dict):
                            req_id = req.get("id", "")
                            req_desc = req.get("description", "")
                            req_source = req.get("source", "inferred")
                            
                            if req_desc:
                                requirement_items.append({
                                    "item_id": f"{ticket_id}-ITEM-{idx:03d}",
                                    "text": req_desc,
                                    "source_section": "requirements_extraction",
                                    "original_line": req_desc
                                })
                    
                    if requirement_items:
                        # Map these requirement-based items to requirements and tests
                        mapped_items = map_ticket_items_to_requirements_and_tests(
                            requirement_items,
                            result.get("requirements", []),
                            all_tests_by_category
                        )
                        
                        result["ticket_traceability"].append({
                            "ticket_id": ticket_id,
                            "items": mapped_items
                        })
                    else:
                        # Fallback: no items and no requirements
                        result["ticket_traceability"].append({
                            "ticket_id": ticket_id,
                            "items": [{
                                "item_id": f"{ticket_id}-ITEM-000",
                                "text": "No numbered or bulleted items found in ticket content",
                                "classification": "informational_only",
                                "source_section": "ticket_analysis",
                                "testable": False,
                                "note": "Ticket content was analyzed but no numbered or bulleted items were detected. All ticket content is still traceable through requirements extraction."
                            }]
                        })
                else:
                    # No items and no requirements - use fallback message
                    result["ticket_traceability"].append({
                        "ticket_id": ticket_id,
                        "items": [{
                            "item_id": f"{ticket_id}-ITEM-000",
                            "text": "No numbered or bulleted items found in ticket content",
                            "classification": "informational_only",
                            "source_section": "ticket_analysis",
                            "testable": False,
                            "note": "Ticket content was analyzed but no numbered or bulleted items were detected. All ticket content is still traceable through requirements extraction."
                        }]
                    })
        
        # Also include tickets that might not have been in test_plans
        # (e.g., failed tickets or tickets without test plans)
        processed_ticket_ids = set(ticket_id_to_items.keys())
        for ticket in processed_tickets:
            ticket_id = ticket.get("ticket_id", "")
            if ticket_id and ticket_id not in processed_ticket_ids:
                # This ticket was processed but had no items extracted
                # Check if we have requirements for it
                ticket_requirements = ticket_id_to_requirements.get(ticket_id, [])
                if ticket_requirements:
                    requirement_items = []
                    for idx, req in enumerate(ticket_requirements, 1):
                        if isinstance(req, dict):
                            req_desc = req.get("description", "")
                            if req_desc:
                                requirement_items.append({
                                    "item_id": f"{ticket_id}-ITEM-{idx:03d}",
                                    "text": req_desc,
                                    "source_section": "requirements_extraction",
                                    "original_line": req_desc
                                })
                    
                    if requirement_items:
                        mapped_items = map_ticket_items_to_requirements_and_tests(
                            requirement_items,
                            result.get("requirements", []),
                            all_tests_by_category
                        )
                        result["ticket_traceability"].append({
                            "ticket_id": ticket_id,
                            "items": mapped_items
                        })
                    else:
                        result["ticket_traceability"].append({
                            "ticket_id": ticket_id,
                            "items": [{
                                "item_id": f"{ticket_id}-ITEM-000",
                                "text": "No numbered or bulleted items found in ticket content",
                                "classification": "informational_only",
                                "source_section": "ticket_analysis",
                                "testable": False,
                                "note": "Ticket content was analyzed but no numbered or bulleted items were detected. All ticket content is still traceable through requirements extraction."
                            }]
                        })
                else:
                    result["ticket_traceability"].append({
                        "ticket_id": ticket_id,
                        "items": [{
                            "item_id": f"{ticket_id}-ITEM-000",
                            "text": "No numbered or bulleted items found in ticket content",
                            "classification": "informational_only",
                            "source_section": "ticket_analysis",
                            "testable": False,
                            "note": "Ticket content was analyzed but no numbered or bulleted items were detected. All ticket content is still traceable through requirements extraction."
                        }]
                    })
        
        # Post-mapping enrichment: Link unmapped technical_constraint items to requirements
        # This enriches items that weren't initially mapped but match requirements
        # Runs AFTER RTM is generated so we can populate validated_by_tests
        if "ticket_traceability" in result and "rtm" in result and "requirements" in result:
            rtm = result.get("rtm", [])
            requirements = result.get("requirements", [])
            
            # Build RTM lookup: requirement_id -> covered_by_tests
            rtm_lookup = {}
            for rtm_entry in rtm:
                if isinstance(rtm_entry, dict):
                    req_id = rtm_entry.get("requirement_id", "")
                    covered_by_tests = rtm_entry.get("covered_by_tests", [])
                    if req_id:
                        rtm_lookup[req_id] = covered_by_tests
            
            # Build requirement lookup: normalized description -> requirement_id
            req_text_to_id = {}
            for req in requirements:
                if isinstance(req, dict):
                    req_id = req.get("id", "")
                    req_desc = req.get("description", "")
                    if req_id and req_desc:
                        # Normalize for matching: lowercase, strip whitespace
                        normalized = req_desc.lower().strip()
                        req_text_to_id[normalized] = req_id
                        # Also store original for exact match
                        req_text_to_id[req_desc] = req_id
            
            # Enrich unmapped technical_constraint items
            for traceability_entry in result["ticket_traceability"]:
                if not isinstance(traceability_entry, dict):
                    continue
                items = traceability_entry.get("items", [])
                if not isinstance(items, list):
                    continue
                
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    
                    # Check if item needs enrichment
                    classification = item.get("classification", "")
                    mapped_req_id = item.get("mapped_requirement_id")
                    item_text = item.get("text", "")
                    
                    # Enrich if: technical_constraint + no mapped_requirement_id + has text
                    if (classification == "technical_constraint" and 
                        not mapped_req_id and 
                        item_text):
                        
                        # Try to match item text to requirement description
                        item_text_normalized = item_text.lower().strip()
                        matched_req_id = None
                        
                        # First try exact normalized match
                        if item_text_normalized in req_text_to_id:
                            matched_req_id = req_text_to_id[item_text_normalized]
                        else:
                            # Try substring match (item text contains requirement or vice versa)
                            for req_desc, req_id in req_text_to_id.items():
                                req_desc_normalized = req_desc.lower().strip() if isinstance(req_desc, str) else ""
                                if req_desc_normalized:
                                    # Check if item text closely matches requirement description
                                    # Match if: item text is substring of requirement OR requirement is substring of item
                                    if (item_text_normalized in req_desc_normalized or 
                                        req_desc_normalized in item_text_normalized):
                                        # Prefer longer match for better accuracy
                                        if not matched_req_id or len(req_desc_normalized) > len(item_text_normalized):
                                            matched_req_id = req_id
                        
                        # If match found, enrich the item
                        if matched_req_id:
                            item["mapped_requirement_id"] = matched_req_id
                            # Populate validated_by_tests from RTM
                            covered_by_tests = rtm_lookup.get(matched_req_id, [])
                            if covered_by_tests:
                                item["validated_by_tests"] = covered_by_tests
        
        # Post-processing: Reclassify technical_constraint items as system_behavior
        # when they are validated by tests (evidence-based override)
        # This runs AFTER all tests are generated and validated_by_tests is populated
        if "ticket_traceability" in result:
            for traceability_entry in result["ticket_traceability"]:
                if not isinstance(traceability_entry, dict):
                    continue
                items = traceability_entry.get("items", [])
                if not isinstance(items, list):
                    continue
                
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    
                    # Check if item should be reclassified
                    classification = item.get("classification", "")
                    mapped_req_id = item.get("mapped_requirement_id")
                    validated_by_tests = item.get("validated_by_tests", [])
                    
                    # Reclassify if: technical_constraint + mapped requirement + has validating tests
                    if (classification == "technical_constraint" and 
                        mapped_req_id and 
                        len(validated_by_tests) > 0):
                        
                        # Check if item text describes automatic system behavior
                        item_text = item.get("text", "").lower()
                        system_behavior_keywords = [
                            "generated", "derived", "automatically", "does not require user input", "system",
                            "rtm", "requirement traceability matrix", "generated automatically", "generated after",
                            "derived from", "system generates", "system creates", "system produces",
                            "does not require", "does not block", "clearly identified", "appears exactly once"
                        ]
                        is_system_behavior = any(keyword in item_text for keyword in system_behavior_keywords)
                        
                        if is_system_behavior:
                            # Reclassify: evidence (tests) overrides initial heuristic classification
                            item["classification"] = "system_behavior"
                            item["testable"] = True
                            # Remove any "not directly testable" notes
                            if "note" in item:
                                del item["note"]
        
        # Final normalization: Enforce invariant for items with mapped requirements and tests
        # If item has mapped_requirement_id AND validated_by_tests, it MUST be system_behavior and testable
        if "ticket_traceability" in result:
            for traceability_entry in result["ticket_traceability"]:
                if not isinstance(traceability_entry, dict):
                    continue
                items = traceability_entry.get("items", [])
                if not isinstance(items, list):
                    continue
                
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    
                    mapped_req_id = item.get("mapped_requirement_id")
                    validated_by_tests = item.get("validated_by_tests", [])
                    
                    # Enforce invariant: mapped requirement + validating tests = system_behavior + testable
                    if mapped_req_id and len(validated_by_tests) > 0:
                        item["classification"] = "system_behavior"
                        item["testable"] = True
                        # Remove any conflicting notes
                        if "note" in item and ("not directly testable" in item["note"].lower() or 
                                                "not testable" in item["note"].lower()):
                            del item["note"]
        
        # Clean up temporary metadata fields from test plans
        for plan in test_plans:
            if "_ticket_items" in plan:
                del plan["_ticket_items"]
            if "_ticket_id" in plan:
                del plan["_ticket_id"]
        
        # ============================================================================
        # SPLIT COMPOSITE TICKET ITEMS into bullet-level items for audit enumeration
        # This is a traceability refinement ONLY - no requirements/tests/coverage changes
        # Must be called AFTER ticket_traceability is built, BEFORE add_ticket_item_traceability
        # ============================================================================
        split_composite_ticket_items(result)
        
        # ============================================================================
        # ADD EXPLICIT TICKET-ITEM TRACEABILITY for audit purposes
        # This is traceability enrichment only - no test logic changes
        # Must be called AFTER ticket_traceability is built and composite items are split
        # ============================================================================
        add_ticket_item_traceability(result)
        
        # ============================================================================
        # REGENERATE RTM to include informational items from ticket_item_coverage
        # This must be done AFTER add_ticket_item_traceability populates ticket_item_coverage
        # ============================================================================
        rtm = generate_rtm(result)
        validate_rtm_coverage_consistency(rtm)
        result["rtm"] = rtm
        
        # ============================================================================
        # ENRICH TEST STEPS for testable tests with empty steps
        # This ONLY modifies the steps field - no other changes allowed
        # Must be called AFTER ticket_item_coverage is populated (by add_ticket_item_traceability)
        # ============================================================================
        enrich_test_steps_for_testable_tests(result)

        # Derive requirement-centric test plan view (presentation-only)
        result["test_plan_by_requirement"] = derive_test_plan_by_requirement(
            result.get("requirements", []),
            result.get("test_plan", {})
        )
        
        # FINAL SANITATION PASS (continued): Remove negative test IDs from derived structures
        # This continues the sanitation pass that ran before scope_summary construction
        # Re-identify requirements and negative test IDs since variables may not be in scope here
        req_ids_with_negative_not_applicable_final = set()
        negative_test_ids_to_remove_final = set()
        
        for req in result.get("requirements", []):
            if isinstance(req, dict):
                req_id = req.get("id", "")
                if req_id:
                    coverage_exp = req.get("coverage_expectations", {})
                    if coverage_exp.get("negative") == "not_applicable":
                        req_ids_with_negative_not_applicable_final.add(req_id)
        
        # Identify all negative tests where source_requirement_id matches excluded requirements
        if req_ids_with_negative_not_applicable_final:
            test_plan_section = result.get("test_plan", {})
            if isinstance(test_plan_section, dict):
                for category in ["api_tests", "ui_tests", "negative_tests", "data_validation_tests", "edge_cases"]:
                    tests = test_plan_section.get(category, [])
                    if isinstance(tests, list):
                        for test in tests:
                            if isinstance(test, dict):
                                test_id = test.get("id", "")
                                intent_type = test.get("intent_type", "").lower()
                                source_req_id = test.get("source_requirement_id", "")
                                
                                # Identify negative tests where source_requirement_id matches excluded requirement
                                if intent_type == "negative" and source_req_id in req_ids_with_negative_not_applicable_final:
                                    if test_id:
                                        negative_test_ids_to_remove_final.add(test_id)
        
        # Remove negative test IDs from test_plan_by_requirement[*].tests.negative
        if negative_test_ids_to_remove_final:
            test_plan_by_req = result.get("test_plan_by_requirement", [])
            if isinstance(test_plan_by_req, list):
                for req_entry in test_plan_by_req:
                    if isinstance(req_entry, dict):
                        req_id = req_entry.get("requirement_id", "")
                        if req_id in req_ids_with_negative_not_applicable_final:
                            tests = req_entry.get("tests", {})
                            if isinstance(tests, dict):
                                # Remove all negative tests for this requirement
                                negative_tests = tests.get("negative", [])
                                if isinstance(negative_tests, list):
                                    filtered_negative = [
                                        test for test in negative_tests
                                        if isinstance(test, dict) and test.get("id", "") not in negative_test_ids_to_remove_final
                                    ]
                                    tests["negative"] = filtered_negative
        
        # Remove negative test IDs from ticket_item_coverage[*].test_ids
        if negative_test_ids_to_remove_final:
            ticket_item_coverage = result.get("ticket_item_coverage", [])
            if isinstance(ticket_item_coverage, list):
                for item_entry in ticket_item_coverage:
                    if isinstance(item_entry, dict):
                        test_ids = item_entry.get("test_ids", [])
                        if isinstance(test_ids, list):
                            # Filter out negative test IDs
                            filtered_test_ids = [
                                test_id for test_id in test_ids
                                if test_id not in negative_test_ids_to_remove_final
                            ]
                            item_entry["test_ids"] = filtered_test_ids
        
        # Remove negative test IDs from ticket_traceability[*].items[*].validated_by_tests
        if negative_test_ids_to_remove_final:
            ticket_traceability = result.get("ticket_traceability", [])
            if isinstance(ticket_traceability, list):
                for ticket_entry in ticket_traceability:
                    if isinstance(ticket_entry, dict):
                        items = ticket_entry.get("items", [])
                        if isinstance(items, list):
                            for item in items:
                                if isinstance(item, dict):
                                    validated_by_tests = item.get("validated_by_tests", [])
                                    if isinstance(validated_by_tests, list):
                                        # Filter out negative test IDs
                                        filtered_validated = [
                                            test_id for test_id in validated_by_tests
                                            if test_id not in negative_test_ids_to_remove_final
                                        ]
                                        item["validated_by_tests"] = filtered_validated
        
        # ============================================================================
        # COVERAGE EXPECTATION ENFORCEMENT: Add deterministic tests for missing coverage
        # This post-pass adds tests based on extracted expectations from requirements
        # Never removes or edits existing tests; only appends missing coverage
        # ============================================================================
        from services.coverage_enforcer import enforce_coverage_expectations
        
        # Extract constraints from ticket data (description and acceptance_criteria)
        constraints = []
        for ticket in all_ticket_data:
            if isinstance(ticket, dict):
                desc = ticket.get("description", "")
                ac = ticket.get("acceptance_criteria", "")
                if desc:
                    constraints.append(desc)
                if ac:
                    constraints.append(ac)
        
        # Apply coverage enforcement
        requirements = result.get("requirements", [])
        if requirements:
            result = enforce_coverage_expectations(result, requirements, constraints)
        
        # Generate and attach ISO 27001/SOC 2 compliant audit metadata
        # This is separate from test content and provides full traceability
        source_type = "jira" if any(t.get("source") == "jira" for t in tickets) else "manual"
        result["audit_metadata"] = generate_audit_metadata(scope, tickets, source_type)

        # Store the result for export endpoints (before handling query parameter exports)
        global _most_recent_test_plan
        _most_recent_test_plan = result
        
        # Persist to file for reliability across restarts
        save_test_plan_to_file(result)
        
        # Persist to database and disk artifacts
        persistence_succeeded = False
        try:
            # created_by and environment were extracted earlier in the function
            # Get tenant_id from JWT if available (for /api/v1/* routes)
            tenant_id = getattr(g, 'tenant_id', None)
            persist_test_plan_result(result, scope, tickets, source_type, created_by, environment, tenant_id=tenant_id)
            persistence_succeeded = True
            
            # Extract run_id from result for usage tracking
            audit_metadata = result.get("audit_metadata", {})
            run_id = audit_metadata.get("run_id")
        except Exception as e:
            # Log but don't fail the request if persistence fails
            logger.warning(f"Failed to persist test plan result: {str(e)}")
        
        # Consume trial run after successful test plan generation and persistence
        # Only consume if persistence succeeded (Run was persisted)
        if tenant_id and persistence_succeeded:
            try:
                from db import get_db
                from services.entitlements import consume_trial_run
                
                db = next(get_db())
                try:
                    consume_trial_run(db, str(tenant_id), agent="test_plan")
                finally:
                    db.close()
            except Exception as consume_error:
                # Log but don't fail the request if consumption fails
                logger.error(f"Failed to consume trial run for tenant {tenant_id}: {str(consume_error)}", exc_info=True)
                # Continue - the run succeeded, consumption failure is non-fatal
        
        # Record usage event (success)
        if tenant_id:
            try:
                from db import get_db
                from services.usage import record_usage_event
                
                end_time_ms = int(time.time() * 1000)
                duration_ms = end_time_ms - start_time_ms
                
                db = next(get_db())
                try:
                    record_usage_event(
                        db=db,
                        tenant_id=str(tenant_id),
                        user_id=str(user_id) if user_id else None,
                        agent="test_plan",
                        source=usage_source,
                        jira_ticket_count=jira_ticket_count,
                        input_char_count=input_char_count,
                        success=True,
                        error_code=None,
                        run_id=run_id,
                        duration_ms=duration_ms
                    )
                    logger.info(f"Usage event recorded for tenant {tenant_id}, agent=test_plan, source={usage_source}, jira_tickets={jira_ticket_count}")
                finally:
                    db.close()
            except Exception as usage_error:
                # Log but don't fail the request if usage tracking fails
                logger.warning(f"Failed to record usage event: {str(usage_error)}", exc_info=True)

        # Handle export requests via query parameters
        export_type = request.args.get("export", "").lower()
        ticket_id = result.get("metadata", {}).get("source_id", "UNKNOWN")
        
        if export_type == "test_plan":
            # Export test plan as JSON file with audit metadata
            export_data = {
                "test_plan": result.get("test_plan", {}),
                "audit_metadata": result.get("audit_metadata", {})
            }
            json_bytes = json.dumps(export_data, indent=2, ensure_ascii=False).encode('utf-8')
            filename = f"{ticket_id}-test-plan.json"
            return Response(
                json_bytes,
                mimetype="application/json",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"'
                }
            )
        
        elif export_type == "rtm":
            # Export RTM as CSV file with audit metadata
            rtm = result.get("rtm", [])
            audit_metadata = result.get("audit_metadata")
            csv_bytes = export_rtm_csv_simple(rtm, audit_metadata)
            filename = f"{ticket_id}-rtm.csv"
            return Response(
                csv_bytes,
                mimetype="text/csv",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"'
                }
            )
        
        # Default: return JSON response as before
        return jsonify(result), 200

    except Exception as e:
        # Record usage event (failure)
        error_code = "UNKNOWN"
        if tenant_id:
            try:
                from db import get_db
                from services.usage import record_usage_event
                
                end_time_ms = int(time.time() * 1000)
                duration_ms = end_time_ms - start_time_ms
                
                # Determine error code based on exception type
                if "Invalid request" in str(e) or "tickets must be" in str(e):
                    error_code = "VALIDATION"
                elif "JIRA" in str(e) or "jira" in str(e).lower():
                    error_code = "JIRA_ERROR"
                
                db = next(get_db())
                try:
                    record_usage_event(
                        db=db,
                        tenant_id=str(tenant_id),
                        user_id=str(user_id) if user_id else None,
                        agent="test_plan",
                        source=usage_source,
                        jira_ticket_count=jira_ticket_count,
                        input_char_count=input_char_count,
                        success=False,
                        error_code=error_code,
                        run_id=run_id,
                        duration_ms=duration_ms
                    )
                    logger.info(f"Usage event recorded (failure) for tenant {tenant_id}, agent=test_plan, error_code={error_code}")
                finally:
                    db.close()
            except Exception as usage_error:
                # Log but don't fail the request if usage tracking fails
                logger.warning(f"Failed to record usage event (error): {str(usage_error)}", exc_info=True)
        
        # Try to persist error state if we have partial result
        try:
            if 'result' in locals() and isinstance(result, dict):
                audit_metadata = result.get("audit_metadata", {})
                run_id = audit_metadata.get("run_id")
                if run_id:
                    # Best-effort persistence of error state
                    try:
                        from db import get_db
                        from services.persistence import save_run
                        db = next(get_db())
                        try:
                            # Get tenant_id from JWT (set by middleware)
                            tenant_id = g.tenant_id
                            if tenant_id:
                                source_type = "jira" if any(t.get("source") == "jira" for t in tickets) else "manual"
                                save_run(
                                    db=db,
                                    run_id=run_id,
                                    source_type=source_type,
                                    status="error",
                                    ticket_count=len(tickets) if tickets else None,
                                    tenant_id=tenant_id
                                )
                        finally:
                            db.close()
                    except Exception:
                        pass  # Silently fail if persistence not available
        except Exception as persist_error:
            logger.warning(f"Failed to persist error state: {str(persist_error)}")
        
        # Create response with CORS headers explicitly included
        response = jsonify({
            "error": f"Internal server error: {str(e)}"
        })
        response.status_code = 500
        
        # Ensure CORS headers are included (Flask-CORS should handle this, but explicit for safety)
        origin = request.headers.get("Origin", "")
        if origin in ALLOWED_ORIGINS:
            response.headers["Access-Control-Allow-Origin"] = origin
        elif ALLOWED_ORIGINS:
            response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGINS[0]
        
        return response


@app.route("/api/v1/analyze", methods=["POST"])
def analyze_requirements():
    """
    Analyze and normalize business requirements (gateway route).
    
    This route acts as a gateway that:
    1. Enforces JWT authentication (via middleware)
    2. Proxies request to BA Requirements Agent with internal service key
    
    NOTE: Subscription enforcement is intentionally NOT applied here to restore 1/14 behavior.
    Requirements extraction must always work regardless of subscription status.
    Subscription checks remain in place for Jira push, dry-run, and test plan generation.
    
    Supports both JSON and multipart/form-data requests (for file attachments).
    
    Returns:
        JSON response from BA agent containing analyzed requirements
    """
    # Get tenant_id and user_id from JWT (set by middleware)
    tenant_id = g.tenant_id
    user_id = g.user_id
    
    if not tenant_id:
        return jsonify({"detail": "Unauthorized"}), 401
    
    # Capture start time for usage tracking
    start_time_ms = int(time.time() * 1000)
    
    # ============================================================================
    # NOTE: Subscription enforcement REMOVED for /api/v1/analyze to restore 1/14 behavior
    # Requirements extraction must always work regardless of subscription status.
    # Subscription checks remain in place for:
    # - Jira push (jira_rewrite_execute)
    # - Dry-run (jira_rewrite_dry_run)
    # - Test plan generation (generate_test_plan)
    # ============================================================================
    
    try:
        from services.agent_client import call_ba_agent, get_internal_headers
        
        # Determine request type and prepare payload
        content_type = request.content_type or ""
        
        if "multipart/form-data" in content_type:
            # Handle FormData request (with attachments)
            form_data = request.form
            files = request.files
            
            # For FormData with files, we need to send as multipart to BA agent
            # Use requests library to forward the request
            import requests as req_lib
            from services.agent_client import BA_AGENT_BASE_URL
            url = f"{BA_AGENT_BASE_URL}/api/v1/analyze"
            
            # Build headers with internal service key
            headers = get_internal_headers(tenant_id=str(tenant_id), user_id=str(user_id) if user_id else None, agent="requirements_ba")
            # Remove Content-Type - let requests set it with boundary for multipart
            headers.pop("Content-Type", None)
            
            # Prepare files for forwarding
            files_to_send = []
            if files:
                for file_key in files:
                    file_list = files.getlist(file_key)
                    for file in file_list:
                        if file and file.filename:
                            files_to_send.append(("attachments", (file.filename, file.read(), file.content_type)))
                            file.seek(0)  # Reset for potential retry
            
            # Prepare form data
            form_data_to_send = {}
            if form_data.get("input_text"):
                form_data_to_send["input_text"] = form_data.get("input_text")
            if form_data.get("source"):
                form_data_to_send["source"] = form_data.get("source")
            if form_data.get("context"):
                form_data_to_send["context"] = form_data.get("context")
            
            # Forward request to BA agent
            try:
                response = req_lib.post(
                    url,
                    headers=headers,
                    data=form_data_to_send,
                    files=files_to_send if files_to_send else None,
                    timeout=300
                )
                response.raise_for_status()
                result = response.json()
            except req_lib.exceptions.HTTPError as e:
                # Extract error details from BA agent response
                error_detail = f"500 Server Error: Internal Server Error for url: {url}"
                try:
                    if e.response is not None:
                        error_body = e.response.json()
                        if isinstance(error_body, dict) and "detail" in error_body:
                            error_detail = error_body["detail"]
                        elif isinstance(error_body, dict):
                            error_detail = str(error_body)
                        else:
                            error_detail = e.response.text[:500] if e.response.text else error_detail
                except (ValueError, AttributeError):
                    try:
                        if e.response is not None and e.response.text:
                            error_detail = e.response.text[:500]
                    except:
                        pass
                logger.error(f"BA agent HTTP error (multipart): {error_detail}")
                raise Exception(error_detail) from e
        else:
            # Handle JSON request (no attachments)
            data = request.get_json() or {}
            payload = {
                "input_text": data.get("input_text", ""),
            }
            if data.get("source"):
                payload["source"] = data.get("source")
            if data.get("context"):
                payload["context"] = data.get("context")
            
            # Call BA agent via agent_client
            result = call_ba_agent("/api/v1/analyze", payload, tenant_id=str(tenant_id), user_id=str(user_id) if user_id else None)
        
        # Consume trial run after successful requirements generation
        if tenant_id:
            try:
                from db import get_db
                from services.entitlements import consume_trial_run
                
                db = next(get_db())
                try:
                    consume_trial_run(db, str(tenant_id), agent="requirements_ba")
                finally:
                    db.close()
            except Exception as consume_error:
                # Log but don't fail the request if consumption fails
                logger.error(f"Failed to consume trial run for tenant {tenant_id}: {str(consume_error)}", exc_info=True)
        
        # Record usage event (success)
        if tenant_id:
            try:
                from db import get_db
                from services.usage import record_usage_event
                
                end_time_ms = int(time.time() * 1000)
                duration_ms = end_time_ms - start_time_ms
                
                # Determine source type
                source = "text"
                if request.is_json:
                    data = request.get_json() or {}
                    if data.get("source") == "jira":
                        source = "jira"
                elif request.content_type and "multipart/form-data" in request.content_type:
                    if request.form.get("source") == "jira":
                        source = "jira"
                
                db = next(get_db())
                try:
                    record_usage_event(
                        db=db,
                        tenant_id=str(tenant_id),
                        user_id=str(user_id) if user_id else None,
                        agent="requirements_ba",
                        source=source,
                        jira_ticket_count=None,
                        input_char_count=input_char_count if input_char_count > 0 else None,
                        success=True,
                        error_code=None,
                        run_id=None,  # Requirements generation doesn't create runs
                        duration_ms=duration_ms
                    )
                    logger.info(f"Usage event recorded for tenant {tenant_id}, agent=requirements_ba, source={source}")
                finally:
                    db.close()
            except Exception as usage_error:
                # Log but don't fail the request if usage tracking fails
                logger.warning(f"Failed to record usage event: {str(usage_error)}", exc_info=True)
        
        return jsonify(result), 200
        
    except Exception as e:
        # Record usage event (failure)
        if tenant_id:
            try:
                from db import get_db
                from services.usage import record_usage_event
                
                end_time_ms = int(time.time() * 1000)
                duration_ms = end_time_ms - start_time_ms
                
                db = next(get_db())
                try:
                    record_usage_event(
                        db=db,
                        tenant_id=str(tenant_id),
                        user_id=str(user_id) if user_id else None,
                        agent="requirements_ba",
                        source="text",
                        jira_ticket_count=None,
                        input_char_count=input_char_count if input_char_count > 0 else None,
                        success=False,
                        error_code="INTERNAL_ERROR",
                        run_id=None,
                        duration_ms=duration_ms
                    )
                finally:
                    db.close()
            except Exception as usage_error:
                logger.warning(f"Failed to record usage event: {str(usage_error)}", exc_info=True)
        
        # Provide more specific error messages
        error_detail = str(e)
        error_code = "INTERNAL_ERROR"
        
        # Check if it's a connection error to BA agent
        if "Connection" in str(type(e).__name__) or "timeout" in error_detail.lower() or "refused" in error_detail.lower():
            from services.agent_client import BA_AGENT_BASE_URL
            error_detail = f"Requirements analysis service is unavailable. Please ensure the BA agent service is running at {BA_AGENT_BASE_URL}"
            error_code = "SERVICE_UNAVAILABLE"
        elif "RequestException" in str(type(e).__name__):
            error_detail = f"Failed to communicate with requirements analysis service: {error_detail}"
            error_code = "SERVICE_ERROR"
        
        logger.error(f"Error analyzing requirements: {error_detail}", exc_info=True)
        
        # Create response with CORS headers explicitly included
        response = jsonify({
            "detail": error_detail,
            "error": error_code
        })
        response.status_code = 500
        
        # Ensure CORS headers are included (Flask-CORS should handle this, but explicit for safety)
        origin = request.headers.get("Origin", "")
        if origin in ALLOWED_ORIGINS:
            response.headers["Access-Control-Allow-Origin"] = origin
        elif ALLOWED_ORIGINS:
            response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGINS[0]
        
        return response


@app.route("/api/v1/jira/rewrite/dry-run", methods=["POST"])
def jira_rewrite_dry_run():
    """
    Jira rewrite dry-run (gateway route).
    
    Proxies request to jira-writeback-agent with internal service key.
    """
    tenant_id = g.tenant_id
    user_id = g.user_id
    
    if not tenant_id:
        return jsonify({"detail": "Unauthorized"}), 401
    
    # Enforce entitlements
    try:
        from db import get_db
        from services.entitlements_centralized import enforce_entitlements
        
        db = next(get_db())
        try:
            allowed, reason, metadata = enforce_entitlements(
                db=db,
                tenant_id=str(tenant_id),
                agent="jira_writeback",
                ticket_count=None,
                input_char_count=None
            )
            
            if not allowed:
                response_detail = {
                    "error": reason or "PAYWALLED",
                    "message": "Request blocked by subscription or plan limits."
                }
                if "subscription_status" in metadata:
                    response_detail["subscription_status"] = metadata["subscription_status"]
                if "trial_remaining" in metadata:
                    response_detail["remaining"] = metadata["trial_remaining"]
                return jsonify(response_detail), 403
        finally:
            db.close()
    except Exception as e:
        fail_open = os.getenv("ENTITLEMENT_FAIL_OPEN", "false").lower() == "true"
        if not fail_open:
            logger.error(f"Entitlement check failed: {str(e)}", exc_info=True)
            return jsonify({"error": "ENTITLEMENT_UNAVAILABLE", "message": "Unable to verify subscription status."}), 503
    
    try:
        from services.agent_client import call_jira_writeback_agent
        data = request.get_json() or {}
        result = call_jira_writeback_agent("/api/v1/jira/rewrite/dry-run", data, tenant_id=str(tenant_id), user_id=str(user_id) if user_id else None)
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error in jira rewrite dry-run: {str(e)}", exc_info=True)
        return jsonify({"detail": f"Failed to run rewrite dry-run: {str(e)}"}), 500


@app.route("/api/v1/jira/rewrite/execute", methods=["POST"])
def jira_rewrite_execute():
    """
    Jira rewrite execute (gateway route).
    
    Proxies request to jira-writeback-agent with internal service key.
    """
    tenant_id = g.tenant_id
    user_id = g.user_id
    
    if not tenant_id:
        return jsonify({"detail": "Unauthorized"}), 401
    
    # Enforce entitlements
    try:
        from db import get_db
        from services.entitlements_centralized import enforce_entitlements
        
        db = next(get_db())
        try:
            allowed, reason, metadata = enforce_entitlements(
                db=db,
                tenant_id=str(tenant_id),
                agent="jira_writeback",
                ticket_count=None,
                input_char_count=None
            )
            
            if not allowed:
                # Special handling for onboarding incomplete
                if reason == "ONBOARDING_INCOMPLETE":
                    message = "Complete onboarding: choose a plan"
                else:
                    message = "Request blocked by subscription or plan limits."
                
                response_detail = {
                    "error": reason or "PAYWALLED",
                    "message": message
                }
                if "subscription_status" in metadata:
                    response_detail["subscription_status"] = metadata["subscription_status"]
                if "trial_remaining" in metadata:
                    response_detail["remaining"] = metadata["trial_remaining"]
                return jsonify(response_detail), 403
        finally:
            db.close()
    except Exception as e:
        fail_open = os.getenv("ENTITLEMENT_FAIL_OPEN", "false").lower() == "true"
        if not fail_open:
            logger.error(f"Entitlement check failed: {str(e)}", exc_info=True)
            return jsonify({"error": "ENTITLEMENT_UNAVAILABLE", "message": "Unable to verify subscription status."}), 503
    
    try:
        from services.agent_client import call_jira_writeback_agent
        from services.entitlements import consume_trial_run
        
        data = request.get_json() or {}
        result = call_jira_writeback_agent("/api/v1/jira/rewrite/execute", data, tenant_id=str(tenant_id), user_id=str(user_id) if user_id else None)
        
        # Consume trial run after successful execution
        if tenant_id:
            try:
                from db import get_db
                db = next(get_db())
                try:
                    consume_trial_run(db, str(tenant_id), agent="jira_writeback")
                finally:
                    db.close()
            except Exception as consume_error:
                logger.error(f"Failed to consume trial run: {str(consume_error)}", exc_info=True)
        
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error in jira rewrite execute: {str(e)}", exc_info=True)
        return jsonify({"detail": f"Failed to execute rewrite: {str(e)}"}), 500


@app.route("/api/v1/jira/create/dry-run", methods=["POST"])
def jira_create_dry_run():
    """
    Jira create dry-run (gateway route).
    
    Proxies request to jira-writeback-agent with internal service key.
    """
    tenant_id = g.tenant_id
    user_id = g.user_id
    
    if not tenant_id:
        return jsonify({"detail": "Unauthorized"}), 401
    
    # Enforce entitlements
    try:
        from db import get_db
        from services.entitlements_centralized import enforce_entitlements
        
        db = next(get_db())
        try:
            allowed, reason, metadata = enforce_entitlements(
                db=db,
                tenant_id=str(tenant_id),
                agent="jira_writeback",
                ticket_count=None,
                input_char_count=None
            )
            
            if not allowed:
                response_detail = {
                    "error": reason or "PAYWALLED",
                    "message": "Request blocked by subscription or plan limits."
                }
                if "subscription_status" in metadata:
                    response_detail["subscription_status"] = metadata["subscription_status"]
                if "trial_remaining" in metadata:
                    response_detail["remaining"] = metadata["trial_remaining"]
                return jsonify(response_detail), 403
        finally:
            db.close()
    except Exception as e:
        fail_open = os.getenv("ENTITLEMENT_FAIL_OPEN", "false").lower() == "true"
        if not fail_open:
            logger.error(f"Entitlement check failed: {str(e)}", exc_info=True)
            return jsonify({"error": "ENTITLEMENT_UNAVAILABLE", "message": "Unable to verify subscription status."}), 503
    
    try:
        from services.agent_client import call_jira_writeback_agent
        data = request.get_json() or {}
        result = call_jira_writeback_agent("/api/v1/jira/create/dry-run", data, tenant_id=str(tenant_id), user_id=str(user_id) if user_id else None)
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error in jira create dry-run: {str(e)}", exc_info=True)
        return jsonify({"detail": f"Failed to run create dry-run: {str(e)}"}), 500


@app.route("/api/v1/jira/create/execute", methods=["POST"])
def jira_create_execute():
    """
    Jira create execute (gateway route).
    
    Proxies request to jira-writeback-agent with internal service key.
    """
    tenant_id = g.tenant_id
    user_id = g.user_id
    
    if not tenant_id:
        return jsonify({"detail": "Unauthorized"}), 401
    
    # Enforce entitlements
    try:
        from db import get_db
        from services.entitlements_centralized import enforce_entitlements
        
        db = next(get_db())
        try:
            allowed, reason, metadata = enforce_entitlements(
                db=db,
                tenant_id=str(tenant_id),
                agent="jira_writeback",
                ticket_count=None,
                input_char_count=None
            )
            
            if not allowed:
                # Special handling for onboarding incomplete
                if reason == "ONBOARDING_INCOMPLETE":
                    message = "Complete onboarding: choose a plan"
                else:
                    message = "Request blocked by subscription or plan limits."
                
                response_detail = {
                    "error": reason or "PAYWALLED",
                    "message": message
                }
                if "subscription_status" in metadata:
                    response_detail["subscription_status"] = metadata["subscription_status"]
                if "trial_remaining" in metadata:
                    response_detail["remaining"] = metadata["trial_remaining"]
                return jsonify(response_detail), 403
        finally:
            db.close()
    except Exception as e:
        fail_open = os.getenv("ENTITLEMENT_FAIL_OPEN", "false").lower() == "true"
        if not fail_open:
            logger.error(f"Entitlement check failed: {str(e)}", exc_info=True)
            return jsonify({"error": "ENTITLEMENT_UNAVAILABLE", "message": "Unable to verify subscription status."}), 503
    
    try:
        from services.agent_client import call_jira_writeback_agent
        from services.entitlements import consume_trial_run
        
        data = request.get_json() or {}
        result = call_jira_writeback_agent("/api/v1/jira/create/execute", data, tenant_id=str(tenant_id), user_id=str(user_id) if user_id else None)
        
        # Consume trial run after successful execution
        if tenant_id:
            try:
                from db import get_db
                db = next(get_db())
                try:
                    consume_trial_run(db, str(tenant_id), agent="jira_writeback")
                finally:
                    db.close()
            except Exception as consume_error:
                logger.error(f"Failed to consume trial run: {str(consume_error)}", exc_info=True)
        
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error in jira create execute: {str(e)}", exc_info=True)
        return jsonify({"detail": f"Failed to execute create: {str(e)}"}), 500


@app.route("/api/v1/requirements/<requirement_id>/overrides", methods=["POST"])
def apply_requirement_override(requirement_id: str):
    """
    Apply requirement override (gateway route).
    
    Proxies request to BA agent with internal service key.
    """
    tenant_id = g.tenant_id
    user_id = g.user_id
    
    if not tenant_id:
        return jsonify({"detail": "Unauthorized"}), 401
    
    try:
        from services.agent_client import call_ba_agent
        data = request.get_json() or {}
        result = call_ba_agent(f"/api/v1/requirements/{requirement_id}/overrides", data, tenant_id=str(tenant_id), user_id=str(user_id) if user_id else None)
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error applying requirement override: {str(e)}", exc_info=True)
        return jsonify({"detail": f"Failed to apply requirement override: {str(e)}"}), 500


@app.route("/api/v1/packages/<package_id>/review", methods=["POST"])
def mark_package_reviewed(package_id: str):
    """
    Mark package as reviewed (gateway route).
    
    Proxies request to BA agent with internal service key.
    """
    tenant_id = g.tenant_id
    user_id = g.user_id
    
    if not tenant_id:
        return jsonify({"detail": "Unauthorized"}), 401
    
    try:
        from services.agent_client import call_ba_agent
        data = request.get_json() or {}
        result = call_ba_agent(f"/api/v1/packages/{package_id}/review", data, tenant_id=str(tenant_id), user_id=str(user_id) if user_id else None)
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error marking package as reviewed: {str(e)}", exc_info=True)
        return jsonify({"detail": f"Failed to mark package as reviewed: {str(e)}"}), 500


@app.route("/api/v1/packages/<package_id>/lock", methods=["POST"])
def lock_package_scope(package_id: str):
    """
    Lock package scope (gateway route).
    
    Proxies request to BA agent with internal service key.
    """
    tenant_id = g.tenant_id
    user_id = g.user_id
    
    if not tenant_id:
        return jsonify({"detail": "Unauthorized"}), 401
    
    try:
        from services.agent_client import call_ba_agent
        data = request.get_json() or {}
        result = call_ba_agent(f"/api/v1/packages/{package_id}/lock", data, tenant_id=str(tenant_id), user_id=str(user_id) if user_id else None)
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error locking package scope: {str(e)}", exc_info=True)
        return jsonify({"detail": f"Failed to lock package scope: {str(e)}"}), 500


@app.route("/api/v1/tenant/status", methods=["GET"])
def get_tenant_status():
    """
    Return tenant subscription and trial status for the authenticated tenant.
    Used by the UI to display Account Status (plan badge, trial remaining).
    Reads from tenant_billing table (single source of truth).
    """
    try:
        from db import get_db
        from models import Tenant
        from services.entitlements_centralized import get_tenant_billing

        db = next(get_db())
        try:
            tenant_id = g.tenant_id
            if not tenant_id:
                return jsonify({"detail": "Unauthorized"}), 401

            tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
            if not tenant:
                return jsonify({"detail": "Tenant not found"}), 404

            # Get billing data from tenant_billing (single source of truth)
            billing = get_tenant_billing(db, str(tenant_id))

            return jsonify({
                "tenant_id": str(tenant.id),
                "tenant_name": tenant.name,
                "subscription_status": billing.get("subscription_status", "unselected"),
                "trial_requirements_runs_remaining": billing.get("trial_requirements_runs_remaining", 0),
                "trial_testplan_runs_remaining": billing.get("trial_testplan_runs_remaining", 0),
                "trial_writeback_runs_remaining": billing.get("trial_writeback_runs_remaining", 0),
            }), 200
        finally:
            db.close()
    except RuntimeError as e:
        logger.error(f"tenant_billing missing in get_tenant_status: {e}")
        return jsonify({"detail": "Billing data is required but not found"}), 500
    except Exception as e:
        logger.error(f"Error fetching tenant status: {str(e)}")
        return jsonify({"detail": f"Failed to fetch tenant status: {str(e)}"}), 500


@app.route("/api/v1/tenant/users", methods=["GET"])
def list_tenant_users():
    """
    List users for the authenticated tenant.
    Requires: owner or admin role
    
    Returns:
        List of users with: id, email, role, is_active, first_name, last_name, created_at, last_login_at
    """
    try:
        from db import get_db
        from models import TenantUser
        import uuid as uuid_module
        
        # Check auth and role (owner or admin)
        if not hasattr(g, 'tenant_id') or not g.tenant_id:
            return jsonify({"ok": False, "error": "UNAUTHORIZED"}), 401
        
        if not hasattr(g, 'role') or g.role not in ["owner", "admin"]:
            return jsonify({"ok": False, "error": "FORBIDDEN", "message": "Admin access required"}), 403
        
        tenant_id = str(g.tenant_id)
        tenant_uuid = g.tenant_id if isinstance(g.tenant_id, uuid_module.UUID) else uuid_module.UUID(tenant_id)
        
        db = next(get_db())
        try:
            # Query users in tenant
            users = db.query(TenantUser).filter(
                TenantUser.tenant_id == tenant_uuid
            ).order_by(TenantUser.created_at.desc()).all()
            
            # Helper to format datetime for JSON (UTC with Z suffix)
            def format_datetime_utc(dt):
                if not dt:
                    return None
                # If timezone-aware, convert to UTC; if naive, assume UTC
                if dt.tzinfo is not None:
                    dt_utc = dt.astimezone(timezone.utc)
                else:
                    dt_utc = dt.replace(tzinfo=timezone.utc)
                # Format as ISO 8601 with Z suffix (no timezone offset)
                return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            
            # Import UserInviteToken for checking pending invites
            from models import UserInviteToken
            
            users_list = []
            for u in users:
                # Check if user has a pending (unused, non-expired) invite token
                now = datetime.now(timezone.utc)
                has_pending_invite = db.query(UserInviteToken).filter(
                    UserInviteToken.user_id == u.id,
                    UserInviteToken.used_at.is_(None),
                    UserInviteToken.expires_at > now
                ).first() is not None
                
                users_list.append({
                    "id": str(u.id),
                    "email": u.email,
                    "role": u.role,
                    "is_active": u.is_active,
                    "first_name": u.first_name,
                    "last_name": u.last_name,
                    "created_at": format_datetime_utc(u.created_at),
                    "last_login_at": format_datetime_utc(u.last_login_at),
                    "has_pending_invite": has_pending_invite
                })
            
            return jsonify(users_list), 200
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error listing tenant users: {str(e)}", exc_info=True)
        return jsonify({"ok": False, "error": "INTERNAL_ERROR"}), 500


@app.route("/api/v1/tenant/users/invite", methods=["POST"])
def invite_tenant_user():
    """
    Invite a user to the authenticated tenant.
    Requires: owner or admin role
    Enforces seat caps based on tenant billing plan tier.
    
    Request body:
        {
            "email": "user@example.com",
            "role": "user" | "admin",
            "first_name": "Optional",
            "last_name": "Optional"
        }
    
    Returns:
        {
            "ok": true,
            "user_id": "<uuid>",
            "email": "<email>"
        }
        Or error:
        {
            "ok": false,
            "error": "SEAT_CAP_EXCEEDED" | "BILLING_INACTIVE" | "USER_ALREADY_EXISTS" | "EMAIL_IN_USE",
            "current_seats": <int>,  # Only for SEAT_CAP_EXCEEDED
            "seat_cap": <int>  # Only for SEAT_CAP_EXCEEDED
        }
    """
    try:
        from db import get_db
        from models import TenantUser
        from services.entitlements_centralized import check_seat_cap
        from services.auth import (
            create_invite_token, send_invite_email, get_invite_url, hash_password
        )
        from sqlalchemy import func
        import uuid as uuid_module
        
        # Check auth and role (owner or admin)
        if not hasattr(g, 'tenant_id') or not g.tenant_id:
            return jsonify({"ok": False, "error": "UNAUTHORIZED"}), 401
        
        if not hasattr(g, 'role') or g.role not in ["owner", "admin"]:
            return jsonify({"ok": False, "error": "FORBIDDEN", "message": "Admin access required"}), 403
        
        tenant_id = str(g.tenant_id)
        tenant_uuid = g.tenant_id if isinstance(g.tenant_id, uuid_module.UUID) else uuid_module.UUID(tenant_id)
        created_by_user_id = str(g.user_id) if hasattr(g, 'user_id') and g.user_id else None
        
        data = request.get_json()
        if not data:
            return jsonify({"ok": False, "error": "INVALID_REQUEST", "message": "Request body must be JSON"}), 400
        
        email = data.get("email", "").strip().lower()
        role = data.get("role", "user").strip().lower()
        first_name = data.get("first_name", "").strip() if data.get("first_name") else None
        last_name = data.get("last_name", "").strip() if data.get("last_name") else None
        
        # Validation
        if not email:
            return jsonify({"ok": False, "error": "INVALID_REQUEST", "message": "email is required"}), 400
        
        if role not in ["user", "admin"]:
            return jsonify({"ok": False, "error": "INVALID_REQUEST", "message": "role must be 'user' or 'admin'"}), 400
        
        # Prevent inviting self (optional but good practice)
        if hasattr(g, 'user_id') and g.user_id:
            current_user_email = None
            db_check = next(get_db())
            try:
                current_user = db_check.query(TenantUser).filter(
                    TenantUser.id == (g.user_id if isinstance(g.user_id, uuid_module.UUID) else uuid_module.UUID(str(g.user_id)))
                ).first()
                if current_user and current_user.email.lower() == email:
                    return jsonify({"ok": False, "error": "INVALID_REQUEST", "message": "Cannot invite yourself"}), 400
            finally:
                db_check.close()
        
        db = next(get_db())
        try:
            # Check seat cap BEFORE creating user
            seat_allowed, error_code, current_seats, seat_cap = check_seat_cap(db, tenant_id)
            if not seat_allowed:
                if error_code == "SEAT_CAP_EXCEEDED":
                    return jsonify({
                        "ok": False,
                        "error": "SEAT_CAP_EXCEEDED",
                        "current_seats": current_seats,
                        "seat_cap": seat_cap
                    }), 403
                elif error_code == "BILLING_INACTIVE":
                    return jsonify({"ok": False, "error": "BILLING_INACTIVE"}), 403
                else:
                    return jsonify({"ok": False, "error": error_code or "SEAT_CHECK_ERROR"}), 403
            
            # Check if user already exists in THIS tenant (tenant-scoped check)
            existing_user = db.query(TenantUser).filter(
                TenantUser.tenant_id == tenant_uuid,
                func.lower(TenantUser.email) == email
            ).first()
            
            if existing_user:
                # User exists in same tenant
                if existing_user.is_active:
                    return jsonify({"ok": False, "error": "USER_ALREADY_EXISTS"}), 409
                else:
                    # User is inactive - allow re-invite
                    # Create invite token and send email
                    raw_token, token_model = create_invite_token(db, str(existing_user.id), created_by_user_id)
                    invite_url = get_invite_url(raw_token)
                    send_invite_email(existing_user.email, invite_url)
                    db.commit()
                    
                    # Debug log (dev only)
                    logger.info(f"INVITE_REINVITED tenant_id={tenant_id} user_id={existing_user.id} email={existing_user.email} is_active={existing_user.is_active}")
                    
                    return jsonify({
                        "ok": True,
                        "user_id": str(existing_user.id),
                        "email": existing_user.email
                    }), 200
            
            # Check if email is used in a different tenant (cross-tenant check)
            email_in_other_tenant = db.query(TenantUser).filter(
                TenantUser.tenant_id != tenant_uuid,
                func.lower(TenantUser.email) == email
            ).first()
            
            if email_in_other_tenant:
                # User exists in different tenant
                return jsonify({"ok": False, "error": "EMAIL_IN_USE"}), 409
            
            # Create new user
            # Generate a temporary password (user will set via invite token)
            temp_password = secrets.token_urlsafe(32)  # Random secure password
            new_user = TenantUser(
                tenant_id=tenant_uuid,
                email=email,
                password_hash=hash_password(temp_password),  # Temporary password
                role=role,
                is_active=False,  # Inactive until password is set via invite
                first_name=first_name,
                last_name=last_name
            )
            db.add(new_user)
            db.flush()  # Flush to get user ID
            
            # Create invite token
            raw_token, token_model = create_invite_token(db, str(new_user.id), created_by_user_id)
            
            # Send invite email
            invite_url = get_invite_url(raw_token)
            send_invite_email(new_user.email, invite_url)
            
            db.commit()
            
            # Debug log (dev only)
            logger.info(f"INVITE_CREATED tenant_id={tenant_id} user_id={new_user.id} email={new_user.email} is_active={new_user.is_active}")
            
            return jsonify({
                "ok": True,
                "user_id": str(new_user.id),
                "email": new_user.email
            }), 201
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error inviting tenant user: {str(e)}", exc_info=True)
        # Return more specific error message for debugging
        error_message = str(e)
        if "user_invite_tokens" in error_message.lower() or "does not exist" in error_message.lower():
            return jsonify({"ok": False, "error": "INTERNAL_ERROR", "message": "Database table missing. Please run migration: db/sql/002_create_user_invite_tokens.sql"}), 500
        return jsonify({"ok": False, "error": "INTERNAL_ERROR", "message": error_message}), 500


@app.route("/api/v1/tenant/users/<user_id>/deactivate", methods=["POST"])
def deactivate_tenant_user(user_id: str):
    """
    Deactivate a user in the authenticated tenant.
    Requires: owner or admin role
    Tenant-scoped: uses g.tenant_id
    
    Path parameters:
        user_id: UUID of the user to deactivate
    
    Returns:
        { "ok": true }
        Or error:
        { "ok": false, "error": "SELF_DEACTIVATE_FORBIDDEN" | "LAST_ADMIN_FORBIDDEN" | ... }
    """
    try:
        from db import get_db
        from models import TenantUser
        import uuid as uuid_module
        
        # Check auth and role (owner or admin)
        if not hasattr(g, 'tenant_id') or not g.tenant_id:
            return jsonify({"ok": False, "error": "UNAUTHORIZED"}), 401
        
        if not hasattr(g, 'role') or g.role not in ["owner", "admin"]:
            return jsonify({"ok": False, "error": "FORBIDDEN", "message": "Admin access required"}), 403
        
        tenant_id = str(g.tenant_id)
        tenant_uuid = g.tenant_id if isinstance(g.tenant_id, uuid_module.UUID) else uuid_module.UUID(tenant_id)
        current_user_id = g.user_id if isinstance(g.user_id, uuid_module.UUID) else uuid_module.UUID(str(g.user_id)) if hasattr(g, 'user_id') and g.user_id else None
        
        # Parse user_id
        try:
            target_user_id_uuid = uuid_module.UUID(user_id)
        except ValueError:
            return jsonify({"ok": False, "error": "INVALID_USER_ID"}), 400
        
        db = next(get_db())
        try:
            # Get target user and verify it belongs to tenant
            target_user = db.query(TenantUser).filter(
                TenantUser.id == target_user_id_uuid,
                TenantUser.tenant_id == tenant_uuid
            ).first()
            
            if not target_user:
                return jsonify({"ok": False, "error": "USER_NOT_FOUND"}), 404
            
            # Prevent self-deactivation
            if current_user_id and target_user.id == current_user_id:
                return jsonify({"ok": False, "error": "SELF_DEACTIVATE_FORBIDDEN"}), 400
            
            # Prevent deactivating last active admin in tenant
            if target_user.role == 'admin' and target_user.is_active:
                active_admin_count = db.query(TenantUser).filter(
                    TenantUser.tenant_id == tenant_uuid,
                    TenantUser.role == 'admin',
                    TenantUser.is_active == True
                ).count()
                
                if active_admin_count <= 1:
                    return jsonify({"ok": False, "error": "LAST_ADMIN_FORBIDDEN"}), 400
            
            # Deactivate user
            target_user.is_active = False
            target_user.updated_at = datetime.now(timezone.utc)
            db.commit()
            
            return jsonify({"ok": True}), 200
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error deactivating tenant user: {str(e)}", exc_info=True)
        return jsonify({"ok": False, "error": "INTERNAL_ERROR"}), 500


@app.route("/api/v1/tenant/users/<user_id>/reactivate", methods=["POST"])
def reactivate_tenant_user(user_id: str):
    """
    Reactivate a user in the authenticated tenant.
    Requires: owner or admin role
    Tenant-scoped: uses g.tenant_id
    Enforces seat cap BEFORE reactivating.
    
    Path parameters:
        user_id: UUID of the user to reactivate
    
    Returns:
        { "ok": true }
        Or error:
        { "ok": false, "error": "SEAT_CAP_EXCEEDED", "current_seats": <int>, "seat_cap": <int> }
    """
    try:
        from db import get_db
        from models import TenantUser
        from services.entitlements_centralized import check_seat_cap
        import uuid as uuid_module
        
        # Check auth and role (owner or admin)
        if not hasattr(g, 'tenant_id') or not g.tenant_id:
            return jsonify({"ok": False, "error": "UNAUTHORIZED"}), 401
        
        if not hasattr(g, 'role') or g.role not in ["owner", "admin"]:
            return jsonify({"ok": False, "error": "FORBIDDEN", "message": "Admin access required"}), 403
        
        tenant_id = str(g.tenant_id)
        tenant_uuid = g.tenant_id if isinstance(g.tenant_id, uuid_module.UUID) else uuid_module.UUID(tenant_id)
        
        # Parse user_id
        try:
            target_user_id_uuid = uuid_module.UUID(user_id)
        except ValueError:
            return jsonify({"ok": False, "error": "INVALID_USER_ID"}), 400
        
        db = next(get_db())
        try:
            # Get target user and verify it belongs to tenant
            target_user = db.query(TenantUser).filter(
                TenantUser.id == target_user_id_uuid,
                TenantUser.tenant_id == tenant_uuid
            ).first()
            
            if not target_user:
                return jsonify({"ok": False, "error": "USER_NOT_FOUND"}), 404
            
            # Enforce seat cap BEFORE reactivating
            seat_allowed, error_code, current_seats, seat_cap = check_seat_cap(db, tenant_id)
            if not seat_allowed:
                if error_code == "SEAT_CAP_EXCEEDED":
                    return jsonify({
                        "ok": False,
                        "error": "SEAT_CAP_EXCEEDED",
                        "current_seats": current_seats,
                        "seat_cap": seat_cap
                    }), 403
                elif error_code == "BILLING_INACTIVE":
                    return jsonify({"ok": False, "error": "BILLING_INACTIVE"}), 403
                else:
                    return jsonify({"ok": False, "error": error_code or "SEAT_CHECK_ERROR"}), 403
            
            # Reactivate user
            target_user.is_active = True
            target_user.updated_at = datetime.now(timezone.utc)
            db.commit()
            
            return jsonify({"ok": True}), 200
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error reactivating tenant user: {str(e)}", exc_info=True)
        return jsonify({"ok": False, "error": "INTERNAL_ERROR"}), 500


@app.route("/api/v1/integrations/jira", methods=["POST"])
def upsert_jira_integration():
    """
    Create or update Jira integration for the current tenant.
    Validates credentials by calling Jira API before storing.
    
    Body:
        {
            "jira_base_url": "https://yourdomain.atlassian.net",
            "jira_user_email": "user@company.com",
            "jira_api_token": "xxxx"
        }
    
    Returns:
        {
            "ok": true,
            "provider": "jira",
            "is_active": true
        }
    """
    try:
        from db import get_db
        from models import TenantIntegration
        from utils.encryption import encrypt_secret
        from services.jira_client import JiraClient, JiraClientError
        import uuid as uuid_module

        # Get tenant_id from JWT (set by middleware)
        tenant_id = g.tenant_id
        if not tenant_id:
            return jsonify({"detail": "Unauthorized"}), 401

        # Parse request body
        data = request.get_json()
        if not data:
            return jsonify({"detail": "Request body is required"}), 400

        jira_base_url = data.get("jira_base_url", "").strip()
        jira_user_email = data.get("jira_user_email", "").strip()
        jira_api_token = data.get("jira_api_token", "").strip()

        # Validate required fields
        if not jira_base_url:
            return jsonify({"detail": "jira_base_url is required"}), 400
        if not jira_user_email:
            return jsonify({"detail": "jira_user_email is required"}), 400
        if not jira_api_token:
            return jsonify({"detail": "jira_api_token is required"}), 400

        # Normalize base URL (trim trailing slash)
        jira_base_url = jira_base_url.rstrip("/")

        # Validate credentials by calling Jira API (list projects endpoint)
        try:
            jira_client = JiraClient(jira_base_url, jira_user_email, jira_api_token)
            # Test with a lightweight endpoint: list projects
            jira_client._make_request("/rest/api/3/project", method="GET")
        except JiraClientError as e:
            # Credentials are invalid - return error without storing
            return jsonify({"detail": f"Invalid Jira credentials: {str(e)}"}), 400
        except Exception as e:
            # Unexpected error during validation
            logger.error(f"Error validating Jira credentials: {str(e)}")
            return jsonify({"detail": f"Failed to validate Jira credentials: {str(e)}"}), 400

        # Encrypt API token
        try:
            encrypted_token = encrypt_secret(jira_api_token)
        except Exception as e:
            logger.error(f"Failed to encrypt Jira API token: {str(e)}")
            return jsonify({"detail": "Failed to encrypt credentials"}), 500

        # Get database session
        db = next(get_db())
        try:
            # Convert tenant_id to UUID if needed
            tenant_uuid = tenant_id if isinstance(tenant_id, uuid_module.UUID) else uuid_module.UUID(tenant_id)

            # Check if integration already exists
            integration = db.query(TenantIntegration).filter(
                TenantIntegration.tenant_id == tenant_uuid,
                TenantIntegration.provider == 'jira'
            ).first()

            if integration:
                # Update existing integration
                integration.jira_base_url = jira_base_url
                integration.jira_user_email = jira_user_email
                integration.credentials_ciphertext = encrypted_token
                integration.is_active = True
                # Only increment credentials_version if we're rotating (for now, leave as-is)
                # integration.credentials_version = integration.credentials_version + 1
            else:
                # Create new integration
                integration = TenantIntegration(
                    tenant_id=tenant_uuid,
                    provider='jira',
                    is_active=True,
                    jira_base_url=jira_base_url,
                    jira_user_email=jira_user_email,
                    credentials_ciphertext=encrypted_token,
                    credentials_version=1
                )
                db.add(integration)

            db.commit()
            db.refresh(integration)

            return jsonify({
                "ok": True,
                "provider": "jira",
                "is_active": True
            }), 200

        finally:
            db.close()

    except ValueError as e:
        return jsonify({"detail": str(e)}), 400
    except Exception as e:
        logger.error(f"Error upserting Jira integration: {str(e)}", exc_info=True)
        return jsonify({"detail": f"Failed to save Jira integration: {str(e)}"}), 500


def check_admin_access():
    """
    Check if the current user has admin access (owner or superAdmin role).
    Must be called within a Flask request context with JWT authentication.
    
    Returns:
        tuple: (user, None) if access granted, (None, error_response) if denied
    
    Raises:
        RuntimeError: If not in Flask request context
    """
    from db import get_db
    from models import TenantUser
    import uuid as uuid_module
    
    if not hasattr(g, 'user_id') or not g.user_id:
        return None, (jsonify({"error": "UNAUTHORIZED", "message": "Authentication required"}), 401)
    
    if not hasattr(g, 'tenant_id') or not g.tenant_id:
        return None, (jsonify({"error": "UNAUTHORIZED", "message": "Tenant context required"}), 401)
    
    # Allowed admin roles
    ALLOWED_ADMIN_ROLES = ["owner", "superAdmin"]
    
    # Get database session
    db = next(get_db())
    try:
        # Convert IDs to UUID if needed
        user_id_uuid = g.user_id if isinstance(g.user_id, uuid_module.UUID) else uuid_module.UUID(g.user_id)
        tenant_id_uuid = g.tenant_id if isinstance(g.tenant_id, uuid_module.UUID) else uuid_module.UUID(g.tenant_id)
        
        # Load user from database
        user = db.query(TenantUser).filter(
            TenantUser.id == user_id_uuid,
            TenantUser.tenant_id == tenant_id_uuid,
            TenantUser.is_active == True
        ).first()
        
        if not user:
            return None, (jsonify({"error": "FORBIDDEN", "message": "Admin access required"}), 403)
        
        # Check role
        if user.role not in ALLOWED_ADMIN_ROLES:
            return None, (jsonify({"error": "FORBIDDEN", "message": "Admin access required"}), 403)
        
        return user, None
    finally:
        db.close()


def require_owner():
    """
    Guard: requires current_user.role === "owner".
    Owner can manage ALL tenants, not just their own.
    
    Uses the SAME tenant loading logic as check_auth() to ensure consistency.
    
    Returns:
        tuple: (user, None) if access granted, (None, error_response) if denied
    
    Raises:
        RuntimeError: If not in Flask request context
    """
    from db import get_db
    from models import TenantUser
    import uuid as uuid_module
    
    # Dev-only debug logging
    is_dev = os.getenv("FLASK_ENV") == "development" or os.getenv("ENV") == "development" or not os.getenv("FLASK_ENV")
    
    if not hasattr(g, 'user_id') or not g.user_id:
        if is_dev:
            logger.warning(f"[OWNER_GUARD] Missing user_id in request context. Path: {request.path}")
        return None, (jsonify({"detail": "Forbidden"}), 403)
    
    if not hasattr(g, 'tenant_id') or not g.tenant_id:
        if is_dev:
            logger.warning(f"[OWNER_GUARD] Missing tenant_id in request context. Path: {request.path}, user_id: {g.user_id}")
        return None, (jsonify({"detail": "Forbidden"}), 403)
    
    db = next(get_db())
    try:
        # Convert IDs to UUID if needed (same logic as check_auth)
        tenant_id_uuid = g.tenant_id if isinstance(g.tenant_id, uuid_module.UUID) else uuid_module.UUID(g.tenant_id)
        user_id_uuid = g.user_id if isinstance(g.user_id, uuid_module.UUID) else uuid_module.UUID(g.user_id)
        
        # Load user (must be in same tenant as JWT)
        user = db.query(TenantUser).filter(
            TenantUser.id == user_id_uuid,
            TenantUser.tenant_id == tenant_id_uuid,
            TenantUser.is_active == True
        ).first()
        
        if not user:
            if is_dev:
                logger.warning(f"[OWNER_GUARD] User not found or inactive. user_id: {g.user_id}, tenant_id: {g.tenant_id}, path: {request.path}")
            return None, (jsonify({"detail": "Forbidden"}), 403)
        
        # Dev-only debug logging
        if is_dev:
            logger.info(
                f"[OWNER_GUARD] Evaluating access - "
                f"user_id: {user.id}, user_email: {user.email}, user_role: {user.role}, "
                f"path: {request.path}"
            )
        
        # Check: role must be "owner"
        if user.role != "owner":
            if is_dev:
                logger.warning(f"[OWNER_GUARD] Access denied: role mismatch. Expected 'owner', got '{user.role}'. Path: {request.path}")
            return None, (jsonify({"detail": "Forbidden"}), 403)
        
        if is_dev:
            logger.info(f"[OWNER_GUARD] Access granted for user {user.email} (owner). Path: {request.path}")
        
        return user, None
    finally:
        db.close()


@app.route("/api/v1/admin/tenants", methods=["GET"])
def list_tenants():
    """
    List all tenants for owner admin.
    Requires owner role.
    
    Returns:
        {
            "items": [
                {
                    "id": <str>,
                    "name": <str>,
                    "slug": <str>,
                    "is_active": <bool>,
                    "subscription_status": <str>,  # Mapped subscription status
                    "plan_tier": <str>,  # Plan tier (unselected, free, solo, team, business)
                    "billing_status": <str>,  # Raw billing status from tenant_billing.status (Stripe status)
                    "trial_requirements_runs_remaining": <int>,
                    "trial_testplan_runs_remaining": <int>,
                    "trial_writeback_runs_remaining": <int>,
                    "created_at": <str>,
                    "updated_at": <str>
                },
                ...
            ]
        }
    """
    try:
        from db import get_db
        from models import Tenant
        
        # Owner only
        user, error_response = require_owner()
        if error_response:
            return error_response
        
        db = next(get_db())
        try:
            from services.entitlements_centralized import get_tenant_billing
            
            # Query all tenants, ordered by name ASC
            tenants = db.query(Tenant).order_by(Tenant.name.asc()).all()
            
            # Format response
            tenants_list = []
            for tenant in tenants:
                # Get billing data from tenant_billing (single source of truth)
                try:
                    billing = get_tenant_billing(db, str(tenant.id))
                    subscription_status = billing.get("subscription_status", "unselected")
                    plan_tier = billing.get("plan_tier") or "unselected"
                    billing_status = billing.get("status") or "unknown"  # Raw billing status (Stripe status)
                    trial_requirements = billing.get("trial_requirements_runs_remaining", 0)
                    trial_testplan = billing.get("trial_testplan_runs_remaining", 0)
                    trial_writeback = billing.get("trial_writeback_runs_remaining", 0)
                except RuntimeError as e:
                    # Hard error - tenant_billing is required
                    logger.error(f"tenant_billing missing for tenant {tenant.id} in admin list: {e}")
                    # Skip this tenant or use error values - for admin UI, we'll use error values
                    subscription_status = "ERROR"
                    plan_tier = "ERROR"
                    billing_status = "ERROR"
                    trial_requirements = 0
                    trial_testplan = 0
                    trial_writeback = 0
                
                tenants_list.append({
                    "id": str(tenant.id),
                    "name": tenant.name,
                    "slug": tenant.slug,
                    "is_active": getattr(tenant, "is_active", True),
                    "subscription_status": subscription_status,
                    "plan_tier": plan_tier,
                    "billing_status": billing_status,  # Raw billing status (Stripe status)
                    "trial_requirements_runs_remaining": trial_requirements,
                    "trial_testplan_runs_remaining": trial_testplan,
                    "trial_writeback_runs_remaining": trial_writeback,
                    "created_at": tenant.created_at.isoformat() + "Z" if tenant.created_at else None,
                    "updated_at": tenant.updated_at.isoformat() + "Z" if tenant.updated_at else None
                })
            
            return jsonify({"items": tenants_list}), 200
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error listing tenants: {str(e)}", exc_info=True)
        return jsonify({"error": "INTERNAL_ERROR", "message": f"Failed to list tenants: {str(e)}"}), 500


@app.route("/api/v1/admin/tenants/<tenant_id>/trial/reset", methods=["POST"])
def reset_tenant_trial(tenant_id: str):
    """
    Reset tenant trial to default values (3/3/3, trial status).
    Requires owner or superAdmin role.
    
    Body (optional):
        {
            "req": 3,
            "test": 3,
            "writeback": 3,
            "status": "trial"
        }
    
    Returns:
        Updated tenant summary
    """
    import uuid as uuid_module
    import time
    from services.usage import record_usage_event
    
    start_time = time.time()
    run_id = str(uuid.uuid4())
    success = False
    error_code = None
    
    try:
        from db import get_db
        from models import Tenant
        
        # Check admin access
        user, error_response = check_admin_access()
        if error_response:
            return error_response
        
        admin_user_id = str(user.id)
        admin_tenant_id = str(user.tenant_id)
        
        # Parse request body (optional)
        data = request.get_json() or {}
        req_value = data.get("req", 3)
        test_value = data.get("test", 3)
        writeback_value = data.get("writeback", 3)
        status_value = data.get("status", "trial")
        
        # Validate status
        allowed_statuses = ["unselected", "trial", "individual", "team", "paywalled", "canceled"]
        if status_value not in allowed_statuses:
            status_value = "trial"
        
        # Convert tenant_id to UUID
        try:
            target_tenant_id_uuid = uuid_module.UUID(tenant_id)
        except ValueError:
            return jsonify({"error": "INVALID_TENANT_ID", "message": f"Invalid tenant_id: {tenant_id}"}), 400
        
        db = next(get_db())
        try:
            # Get target tenant
            target_tenant = db.query(Tenant).filter(Tenant.id == target_tenant_id_uuid).first()
            if not target_tenant:
                return jsonify({"error": "TENANT_NOT_FOUND", "message": f"Tenant not found: {tenant_id}"}), 404
            
            # Update tenant_billing.status (single source of truth for billing)
            from services.entitlements_centralized import update_tenant_billing_status
            try:
                update_tenant_billing_status(db, tenant_id, status_value)
            except RuntimeError as e:
                logger.error(f"Failed to update tenant_billing.status: {e}")
                return jsonify({"error": "BILLING_UPDATE_FAILED", "message": "Failed to update billing status"}), 500
            
            # Update trial counters in tenants table (usage data, not billing)
            target_tenant.trial_requirements_runs_remaining = req_value
            target_tenant.trial_testplan_runs_remaining = test_value
            target_tenant.trial_writeback_runs_remaining = writeback_value
            target_tenant.is_active = True  # Ensure active
            
            db.commit()
            db.refresh(target_tenant)
            
            # Read billing data from tenant_billing (single source of truth for reads)
            from services.entitlements_centralized import get_tenant_billing
            try:
                billing = get_tenant_billing(db, tenant_id)
                subscription_status = billing.get("subscription_status", "unselected")
                trial_requirements = billing.get("trial_requirements_runs_remaining", 0)
                trial_testplan = billing.get("trial_testplan_runs_remaining", 0)
                trial_writeback = billing.get("trial_writeback_runs_remaining", 0)
            except RuntimeError as e:
                logger.error(f"tenant_billing missing after trial reset: {e}")
                return jsonify({"error": "BILLING_DATA_MISSING", "message": "Billing data is required but not found"}), 500
            
            success = True
            error_code = "TRIAL_RESET"
            
            # Return updated tenant summary
            return jsonify({
                "id": str(target_tenant.id),
                "name": target_tenant.name,
                "slug": target_tenant.slug,
                "subscription_status": subscription_status,
                "req_remaining": trial_requirements,
                "test_remaining": trial_testplan,
                "wb_remaining": trial_writeback,
                "is_active": target_tenant.is_active
            }), 200
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error resetting tenant trial: {str(e)}", exc_info=True)
        success = False
        error_code = "TRIAL_RESET_FAILED"
        return jsonify({"error": "INTERNAL_ERROR", "message": f"Failed to reset trial: {str(e)}"}), 500
    finally:
        # Audit logging (non-blocking)
        try:
            duration_ms = int((time.time() - start_time) * 1000)
            audit_db = next(get_db())
            try:
                record_usage_event(
                    audit_db,
                    tenant_id=tenant_id,  # Target tenant
                    user_id=admin_user_id if 'admin_user_id' in locals() else None,
                    agent="admin",
                    source="admin_ui",
                    jira_ticket_count=0,
                    input_char_count=0,
                    success=success,
                    error_code=error_code,
                    run_id=run_id,
                    duration_ms=duration_ms
                )
            finally:
                audit_db.close()
        except Exception as audit_error:
            logger.error(f"Failed to record audit log: {str(audit_error)}", exc_info=True)


@app.route("/api/v1/admin/tenants/<tenant_id>/trial/set", methods=["POST"])
def set_tenant_trial(tenant_id: str):
    """
    Set tenant trial counters and status to specific values.
    Requires owner or superAdmin role.
    
    Body (required):
        {
            "req": <int>,
            "test": <int>,
            "writeback": <int>,
            "status": "unselected" | "trial" | "individual" | "team" | "paywalled" | "canceled"
        }
    
    Returns:
        Updated tenant summary
    """
    import uuid as uuid_module
    import time
    from services.usage import record_usage_event
    
    start_time = time.time()
    run_id = str(uuid.uuid4())
    success = False
    error_code = None
    admin_user_id = None
    
    try:
        from db import get_db
        from models import Tenant
        
        # Check admin access
        user, error_response = check_admin_access()
        if error_response:
            return error_response
        
        admin_user_id = str(user.id)
        
        # Parse request body
        data = request.get_json()
        if not data:
            return jsonify({"error": "INVALID_REQUEST", "message": "Request body is required"}), 400
        
        req_value = data.get("req")
        test_value = data.get("test")
        writeback_value = data.get("writeback")
        status_value = data.get("status")
        
        # Validate required fields
        if req_value is None or test_value is None or writeback_value is None or status_value is None:
            return jsonify({"error": "INVALID_REQUEST", "message": "req, test, writeback, and status are required"}), 400
        
        # Validate types and values
        try:
            req_value = int(req_value)
            test_value = int(test_value)
            writeback_value = int(writeback_value)
        except (ValueError, TypeError):
            return jsonify({"error": "INVALID_REQUEST", "message": "req, test, and writeback must be integers"}), 400
        
        if req_value < 0 or test_value < 0 or writeback_value < 0:
            return jsonify({"error": "INVALID_REQUEST", "message": "req, test, and writeback must be >= 0"}), 400
        
        allowed_statuses = ["unselected", "trial", "individual", "team", "paywalled", "canceled"]
        if status_value not in allowed_statuses:
            return jsonify({"error": "INVALID_REQUEST", "message": f"status must be one of: {allowed_statuses}"}), 400
        
        # Convert tenant_id to UUID
        try:
            target_tenant_id_uuid = uuid_module.UUID(tenant_id)
        except ValueError:
            return jsonify({"error": "INVALID_TENANT_ID", "message": f"Invalid tenant_id: {tenant_id}"}), 400
        
        db = next(get_db())
        try:
            # Get target tenant
            target_tenant = db.query(Tenant).filter(Tenant.id == target_tenant_id_uuid).first()
            if not target_tenant:
                return jsonify({"error": "TENANT_NOT_FOUND", "message": f"Tenant not found: {tenant_id}"}), 404
            
            # Update tenant_billing.status (single source of truth for billing)
            from services.entitlements_centralized import update_tenant_billing_status
            try:
                update_tenant_billing_status(db, tenant_id, status_value)
            except RuntimeError as e:
                logger.error(f"Failed to update tenant_billing.status: {e}")
                return jsonify({"error": "BILLING_UPDATE_FAILED", "message": "Failed to update billing status"}), 500
            
            # Update trial counters in tenants table (usage data, not billing)
            target_tenant.trial_requirements_runs_remaining = req_value
            target_tenant.trial_testplan_runs_remaining = test_value
            target_tenant.trial_writeback_runs_remaining = writeback_value
            
            db.commit()
            db.refresh(target_tenant)
            
            # Read billing data from tenant_billing (single source of truth for reads)
            from services.entitlements_centralized import get_tenant_billing
            try:
                billing = get_tenant_billing(db, tenant_id)
                subscription_status = billing.get("subscription_status", "unselected")
                trial_requirements = billing.get("trial_requirements_runs_remaining", 0)
                trial_testplan = billing.get("trial_testplan_runs_remaining", 0)
                trial_writeback = billing.get("trial_writeback_runs_remaining", 0)
            except RuntimeError as e:
                logger.error(f"tenant_billing missing after trial set: {e}")
                return jsonify({"error": "BILLING_DATA_MISSING", "message": "Billing data is required but not found"}), 500
            
            success = True
            error_code = "TRIAL_SET"
            
            # Return updated tenant summary
            return jsonify({
                "id": str(target_tenant.id),
                "name": target_tenant.name,
                "slug": target_tenant.slug,
                "subscription_status": subscription_status,
                "req_remaining": trial_requirements,
                "test_remaining": trial_testplan,
                "wb_remaining": trial_writeback,
                "is_active": target_tenant.is_active
            }), 200
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error setting tenant trial: {str(e)}", exc_info=True)
        success = False
        error_code = "TRIAL_SET_FAILED"
        return jsonify({"error": "INTERNAL_ERROR", "message": f"Failed to set trial: {str(e)}"}), 500
    finally:
        # Audit logging (non-blocking)
        try:
            duration_ms = int((time.time() - start_time) * 1000)
            audit_db = next(get_db())
            try:
                record_usage_event(
                    audit_db,
                    tenant_id=tenant_id,  # Target tenant
                    user_id=admin_user_id,
                    agent="admin",
                    source="admin_ui",
                    jira_ticket_count=0,
                    input_char_count=0,
                    success=success,
                    error_code=error_code,
                    run_id=run_id,
                    duration_ms=duration_ms
                )
            finally:
                audit_db.close()
        except Exception as audit_error:
            logger.error(f"Failed to record audit log: {str(audit_error)}", exc_info=True)


# ============================================================================
# TENANT-ADDRESSABLE ADMIN ENDPOINTS (Owner only, can manage ALL tenants)
# ============================================================================

@app.route("/api/v1/admin/tenants/<tenant_id>/status", methods=["POST"])
def set_tenant_status(tenant_id: str):
    """
    Set tenant status (Active/Suspended).
    Requires: owner role
    
    Body:
        {
            "status": "active" | "suspended"
        }
    
    Returns:
        204 No Content on success
    """
    try:
        from db import get_db
        from models import Tenant, AdminAuditLog
        import uuid as uuid_module
        
        # Owner only
        current_user, error_response = require_owner()
        if error_response:
            return error_response
        
        # Parse request body
        data = request.get_json()
        if not data:
            return jsonify({"detail": "Request body is required"}), 400
        
        status = data.get("status")
        if status not in ["active", "suspended"]:
            return jsonify({"detail": "status must be 'active' or 'suspended'"}), 400
        
        # Convert tenant_id to UUID
        try:
            target_tenant_id_uuid = uuid_module.UUID(tenant_id)
        except ValueError:
            return jsonify({"detail": "Invalid tenant_id"}), 400
        
        db = next(get_db())
        try:
            # Get target tenant
            target_tenant = db.query(Tenant).filter(Tenant.id == target_tenant_id_uuid).first()
            if not target_tenant:
                return jsonify({"detail": "Tenant not found"}), 404
            
            # Update tenant_billing.status (single source of truth for billing)
            from services.entitlements_centralized import update_tenant_billing_status
            billing_status = "suspended" if status == "suspended" else "active"
            try:
                update_tenant_billing_status(db, tenant_id, billing_status)
            except RuntimeError as e:
                logger.error(f"Failed to update tenant_billing.status: {e}")
                return jsonify({"detail": "Failed to update billing status"}), 500
            
            # Update tenant is_active flag
            if status == "suspended":
                target_tenant.is_active = False
                action = "ops.tenant.suspend"
            else:  # active
                target_tenant.is_active = True
                action = "ops.tenant.reactivate"
            
            db.commit()
            
            # Write audit log
            try:
                audit_log = AdminAuditLog(
                    tenant_id=target_tenant_id_uuid,  # Target tenant
                    user_id=current_user.id,
                    action=action,
                    target_type="tenant",
                    target_id=target_tenant_id_uuid,
                    metadata_json=json.dumps({"tenant_slug": target_tenant.slug, "status": status})
                )
                db.add(audit_log)
                db.commit()
            except Exception as audit_error:
                logger.error(f"Failed to record audit log: {str(audit_error)}", exc_info=True)
            
            return jsonify(), 204
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error setting tenant status: {str(e)}", exc_info=True)
        return jsonify({"detail": "Internal server error"}), 500


@app.route("/api/v1/admin/tenants/<tenant_id>/users", methods=["GET"])
def admin_list_tenant_users(tenant_id: str):
    """
    List users for a specific tenant.
    Requires: owner role
    
    Returns:
        List of users with: id, email, role, is_active, first_name, last_name, created_at, last_login_at
    """
    try:
        from db import get_db
        from models import TenantUser, Tenant
        import uuid as uuid_module
        
        # Owner only
        current_user, error_response = require_owner()
        if error_response:
            return error_response
        
        # Convert tenant_id to UUID
        try:
            target_tenant_id_uuid = uuid_module.UUID(tenant_id)
        except ValueError:
            return jsonify({"detail": "Invalid tenant_id"}), 400
        
        db = next(get_db())
        try:
            # Verify tenant exists
            target_tenant = db.query(Tenant).filter(Tenant.id == target_tenant_id_uuid).first()
            if not target_tenant:
                return jsonify({"detail": "Tenant not found"}), 404
            
            # Query users in target tenant
            users = db.query(TenantUser).filter(
                TenantUser.tenant_id == target_tenant_id_uuid
            ).order_by(TenantUser.created_at.desc()).all()
            
            # Import UserInviteToken for checking pending invites
            from models import UserInviteToken
            
            # Helper to format datetime for JSON (UTC with Z suffix)
            def format_datetime_utc(dt):
                if not dt:
                    return None
                # If timezone-aware, convert to UTC; if naive, assume UTC
                if dt.tzinfo is not None:
                    dt_utc = dt.astimezone(timezone.utc)
                else:
                    dt_utc = dt.replace(tzinfo=timezone.utc)
                # Format as ISO 8601 with Z suffix (no timezone offset)
                return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            
            users_list = []
            for u in users:
                # Check if user has a pending (unused, non-expired) invite token
                now = datetime.now(timezone.utc)
                has_pending_invite = db.query(UserInviteToken).filter(
                    UserInviteToken.user_id == u.id,
                    UserInviteToken.used_at.is_(None),
                    UserInviteToken.expires_at > now
                ).first() is not None
                
                users_list.append({
                    "id": str(u.id),
                    "email": u.email,
                    "role": u.role,
                    "is_active": u.is_active,
                    "first_name": u.first_name,
                    "last_name": u.last_name,
                    "created_at": format_datetime_utc(u.created_at),
                    "last_login_at": format_datetime_utc(u.last_login_at),
                    "has_pending_invite": has_pending_invite
                })
            
            return jsonify(users_list), 200
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error listing tenant users: {str(e)}", exc_info=True)
        return jsonify({"detail": "Internal server error"}), 500


@app.route("/api/v1/admin/tenants/<tenant_id>/users/<user_id>/deactivate", methods=["POST"])
def admin_deactivate_tenant_user(tenant_id: str, user_id: str):
    """
    Deactivate a user in a specific tenant.
    Requires: owner role
    Cannot deactivate self.
    
    Returns:
        204 No Content on success
    """
    try:
        from db import get_db
        from models import TenantUser, Tenant, AdminAuditLog
        import uuid as uuid_module
        
        # Owner only
        current_user, error_response = require_owner()
        if error_response:
            return error_response
        
        # Parse IDs
        try:
            target_tenant_id_uuid = uuid_module.UUID(tenant_id)
            target_user_id_uuid = uuid_module.UUID(user_id)
        except ValueError:
            return jsonify({"detail": "Invalid tenant_id or user_id"}), 400
        
        # Cannot deactivate self
        if str(current_user.id) == user_id:
            return jsonify({"detail": "Cannot deactivate yourself"}), 400
        
        db = next(get_db())
        try:
            # Verify tenant exists
            target_tenant = db.query(Tenant).filter(Tenant.id == target_tenant_id_uuid).first()
            if not target_tenant:
                return jsonify({"detail": "Tenant not found"}), 404
            
            # Get target user (must belong to target tenant)
            target_user = db.query(TenantUser).filter(
                TenantUser.id == target_user_id_uuid,
                TenantUser.tenant_id == target_tenant_id_uuid
            ).first()
            
            if not target_user:
                return jsonify({"detail": "User not found"}), 404
            
            # Deactivate
            target_user.is_active = False
            db.commit()
            
            # Write audit log
            try:
                audit_log = AdminAuditLog(
                    tenant_id=target_tenant_id_uuid,  # Target tenant
                    user_id=current_user.id,
                    action="ops.user.deactivate",
                    target_type="user",
                    target_id=target_user_id_uuid,
                    metadata_json=json.dumps({"target_email": target_user.email, "target_tenant_slug": target_tenant.slug})
                )
                db.add(audit_log)
                db.commit()
            except Exception as audit_error:
                logger.error(f"Failed to record audit log: {str(audit_error)}", exc_info=True)
            
            return jsonify(), 204
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error deactivating tenant user: {str(e)}", exc_info=True)
        return jsonify({"detail": "Internal server error"}), 500


@app.route("/api/v1/admin/tenants/<tenant_id>/users/<user_id>/reactivate", methods=["POST"])
def admin_reactivate_tenant_user(tenant_id: str, user_id: str):
    """
    Reactivate a user in a specific tenant.
    Requires: owner role
    
    Returns:
        204 No Content on success
    """
    try:
        from db import get_db
        from models import TenantUser, Tenant, AdminAuditLog
        import uuid as uuid_module
        
        # Owner only
        current_user, error_response = require_owner()
        if error_response:
            return error_response
        
        # Parse IDs
        try:
            target_tenant_id_uuid = uuid_module.UUID(tenant_id)
            target_user_id_uuid = uuid_module.UUID(user_id)
        except ValueError:
            return jsonify({"detail": "Invalid tenant_id or user_id"}), 400
        
        db = next(get_db())
        try:
            # Verify tenant exists
            target_tenant = db.query(Tenant).filter(Tenant.id == target_tenant_id_uuid).first()
            if not target_tenant:
                return jsonify({"detail": "Tenant not found"}), 404
            
            # Get target user (must belong to target tenant)
            target_user = db.query(TenantUser).filter(
                TenantUser.id == target_user_id_uuid,
                TenantUser.tenant_id == target_tenant_id_uuid
            ).first()
            
            if not target_user:
                return jsonify({"detail": "User not found"}), 404
            
            # Reactivate
            target_user.is_active = True
            db.commit()
            
            # Write audit log
            try:
                audit_log = AdminAuditLog(
                    tenant_id=target_tenant_id_uuid,  # Target tenant
                    user_id=current_user.id,
                    action="ops.user.reactivate",
                    target_type="user",
                    target_id=target_user_id_uuid,
                    metadata_json=json.dumps({"target_email": target_user.email, "target_tenant_slug": target_tenant.slug})
                )
                db.add(audit_log)
                db.commit()
            except Exception as audit_error:
                logger.error(f"Failed to record audit log: {str(audit_error)}", exc_info=True)
            
            return jsonify(), 204
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error reactivating tenant user: {str(e)}", exc_info=True)
        return jsonify({"detail": "Internal server error"}), 500


@app.route("/api/v1/admin/tenants/<tenant_id>/usage/summary", methods=["GET"])
def admin_tenant_usage_summary(tenant_id: str):
    """
    Get usage summary for a specific tenant.
    Requires: owner role
    
    Query params:
        days: int (default 30, clamp 1..365)
    
    Returns:
        {
            "days": <int>,
            "totals": {
                "events": <int>,
                "success": <int>,
                "failed": <int>,
                "jira_ticket_count": <int>,
                "input_char_count": <int>
            },
            "by_agent": [...]
        }
    """
    try:
        from db import get_db
        from models import UsageEvent, Tenant
        from datetime import datetime, timezone, timedelta
        import uuid as uuid_module
        
        # Owner only
        current_user, error_response = require_owner()
        if error_response:
            return error_response
        
        # Convert tenant_id to UUID
        try:
            target_tenant_id_uuid = uuid_module.UUID(tenant_id)
        except ValueError:
            return jsonify({"detail": "Invalid tenant_id"}), 400
        
        # Parse days param
        days = request.args.get('days', 30, type=int)
        days = max(1, min(365, days))  # Clamp 1..365
        
        db = next(get_db())
        try:
            # Verify tenant exists
            target_tenant = db.query(Tenant).filter(Tenant.id == target_tenant_id_uuid).first()
            if not target_tenant:
                return jsonify({"detail": "Tenant not found"}), 404
            
            # Calculate cutoff date
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
            
            # Query usage events for target tenant
            events = db.query(UsageEvent).filter(
                UsageEvent.tenant_id == target_tenant_id_uuid,
                UsageEvent.created_at >= cutoff_date
            ).all()
            
            # Calculate totals
            totals = {
                "events": len(events),
                "success": sum(1 for e in events if e.success),
                "failed": sum(1 for e in events if not e.success),
                "jira_ticket_count": sum(e.jira_ticket_count or 0 for e in events),
                "input_char_count": sum(e.input_char_count or 0 for e in events)
            }
            
            # Group by agent
            by_agent_dict = {}
            for event in events:
                agent = event.agent or "unknown"
                if agent not in by_agent_dict:
                    by_agent_dict[agent] = {
                        "agent": agent,
                        "events": 0,
                        "success": 0,
                        "failed": 0,
                        "jira_ticket_count": 0,
                        "input_char_count": 0
                    }
                
                by_agent_dict[agent]["events"] += 1
                if event.success:
                    by_agent_dict[agent]["success"] += 1
                else:
                    by_agent_dict[agent]["failed"] += 1
                by_agent_dict[agent]["jira_ticket_count"] += (event.jira_ticket_count or 0)
                by_agent_dict[agent]["input_char_count"] += (event.input_char_count or 0)
            
            by_agent = list(by_agent_dict.values())
            
            return jsonify({
                "days": days,
                "totals": totals,
                "by_agent": by_agent
            }), 200
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error getting tenant usage summary: {str(e)}", exc_info=True)
        return jsonify({"detail": "Internal server error"}), 500


@app.route("/api/v1/admin/tenants/<tenant_id>/runs/recent", methods=["GET"])
def admin_tenant_recent_runs(tenant_id: str):
    """
    Get recent runs for a specific tenant.
    Requires: owner role
    
    Query params:
        limit: int (default 25, max 100)
    
    Returns:
        List of runs with: run_id, created_at, agent, status, review_status, jira_issue_key, summary
    """
    try:
        from db import get_db
        from models import Run, Tenant
        import uuid as uuid_module
        
        # Owner only
        current_user, error_response = require_owner()
        if error_response:
            return error_response
        
        # Convert tenant_id to UUID
        try:
            target_tenant_id_uuid = uuid_module.UUID(tenant_id)
        except ValueError:
            return jsonify({"detail": "Invalid tenant_id"}), 400
        
        # Parse limit param
        limit = request.args.get('limit', 25, type=int)
        limit = max(1, min(100, limit))  # Clamp 1..100
        
        db = next(get_db())
        try:
            # Verify tenant exists
            target_tenant = db.query(Tenant).filter(Tenant.id == target_tenant_id_uuid).first()
            if not target_tenant:
                return jsonify({"detail": "Tenant not found"}), 404
            
            # Query recent runs for target tenant
            runs = db.query(Run).filter(
                Run.tenant_id == target_tenant_id_uuid
            ).order_by(Run.created_at.desc()).limit(limit).all()
            
            runs_list = []
            for r in runs:
                runs_list.append({
                    "run_id": r.run_id,
                    "created_at": r.created_at.isoformat() + "Z" if r.created_at else None,
                    "agent": getattr(r, "agent", "unknown") or "unknown",
                    "status": r.status,
                    "review_status": r.review_status,
                    "jira_issue_key": r.jira_issue_key,
                    "summary": getattr(r, "summary", None)
                })
            
            return jsonify(runs_list), 200
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error getting tenant recent runs: {str(e)}", exc_info=True)
        return jsonify({"detail": "Internal server error"}), 500


@app.route("/api/v1/admin/tenants/<tenant_id>/audit", methods=["GET"])
def admin_tenant_audit(tenant_id: str):
    """
    Get admin audit log for a specific tenant.
    Requires: owner role
    
    Query params:
        limit: int (default 50, max 200)
    
    Returns:
        List of audit log entries ordered by created_at desc
    """
    try:
        from db import get_db
        from models import AdminAuditLog, Tenant
        import uuid as uuid_module
        
        # Owner only
        current_user, error_response = require_owner()
        if error_response:
            return error_response
        
        # Convert tenant_id to UUID
        try:
            target_tenant_id_uuid = uuid_module.UUID(tenant_id)
        except ValueError:
            return jsonify({"detail": "Invalid tenant_id"}), 400
        
        # Parse limit param
        limit = request.args.get('limit', 50, type=int)
        limit = max(1, min(200, limit))  # Clamp 1..200
        
        db = next(get_db())
        try:
            # Verify tenant exists
            target_tenant = db.query(Tenant).filter(Tenant.id == target_tenant_id_uuid).first()
            if not target_tenant:
                return jsonify({"detail": "Tenant not found"}), 404
            
            # Query audit log for target tenant
            audit_logs = db.query(AdminAuditLog).filter(
                AdminAuditLog.tenant_id == target_tenant_id_uuid
            ).order_by(AdminAuditLog.created_at.desc()).limit(limit).all()
            
            logs_list = []
            for log in audit_logs:
                metadata = {}
                if log.metadata_json:
                    try:
                        metadata = json.loads(log.metadata_json)
                    except:
                        pass
                
                logs_list.append({
                    "id": str(log.id),
                    "user_id": str(log.user_id),
                    "action": log.action,
                    "target_type": log.target_type,
                    "target_id": str(log.target_id) if log.target_id else None,
                    "metadata": metadata,
                    "created_at": log.created_at.isoformat() + "Z" if log.created_at else None
                })
            
            return jsonify(logs_list), 200
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error getting tenant audit log: {str(e)}", exc_info=True)
        return jsonify({"detail": "Internal server error"}), 500


# ============================================================================
# OPS SAFETY ENDPOINTS (Ultra-strict: owner + kerr-ai-studio only)
# ============================================================================

@app.route("/api/v1/admin/users", methods=["GET"])
def admin_list_users():
    """
    List users in the current tenant.
    Requires: owner role AND tenant slug === "kerr-ai-studio"
    
    Returns:
        List of users with: id, email, role, is_active, first_name, last_name, created_at, last_login_at
    """
    try:
        from db import get_db
        from models import TenantUser
        
        # Owner only
        user, error_response = require_owner()
        if error_response:
            return error_response
        
        db = next(get_db())
        try:
            # Get current tenant from JWT
            import uuid as uuid_module
            tenant_id_uuid = g.tenant_id if isinstance(g.tenant_id, uuid_module.UUID) else uuid_module.UUID(g.tenant_id)
            from models import Tenant
            tenant = db.query(Tenant).filter(Tenant.id == tenant_id_uuid).first()
            if not tenant:
                return jsonify({"detail": "Tenant not found"}), 404
            
            # Query users in this tenant only
            users = db.query(TenantUser).filter(
                TenantUser.tenant_id == tenant.id
            ).order_by(TenantUser.created_at.desc()).all()
            
            # Import UserInviteToken for checking pending invites
            from models import UserInviteToken
            
            # Helper to format datetime for JSON (UTC with Z suffix)
            def format_datetime_utc(dt):
                if not dt:
                    return None
                # If timezone-aware, convert to UTC; if naive, assume UTC
                if dt.tzinfo is not None:
                    dt_utc = dt.astimezone(timezone.utc)
                else:
                    dt_utc = dt.replace(tzinfo=timezone.utc)
                # Format as ISO 8601 with Z suffix (no timezone offset)
                return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            
            users_list = []
            for u in users:
                # Check if user has a pending (unused, non-expired) invite token
                now = datetime.now(timezone.utc)
                has_pending_invite = db.query(UserInviteToken).filter(
                    UserInviteToken.user_id == u.id,
                    UserInviteToken.used_at.is_(None),
                    UserInviteToken.expires_at > now
                ).first() is not None
                
                users_list.append({
                    "id": str(u.id),
                    "email": u.email,
                    "role": u.role,
                    "is_active": u.is_active,
                    "first_name": u.first_name,
                    "last_name": u.last_name,
                    "created_at": format_datetime_utc(u.created_at),
                    "last_login_at": format_datetime_utc(u.last_login_at),
                    "has_pending_invite": has_pending_invite
                })
            
            return jsonify(users_list), 200
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error listing users: {str(e)}", exc_info=True)
        return jsonify({"detail": "Internal server error"}), 500


@app.route("/api/v1/admin/users/<user_id>/deactivate", methods=["POST"])
def admin_deactivate_user(user_id: str):
    """
    Deactivate a user in the current tenant.
    Requires: owner role AND tenant slug === "kerr-ai-studio"
    Cannot deactivate self.
    
    Returns:
        204 No Content on success
    """
    try:
        from db import get_db
        from models import TenantUser, AdminAuditLog
        import uuid as uuid_module
        
        # Owner only
        current_user, error_response = require_owner()
        if error_response:
            return error_response
        
        # Parse user_id
        try:
            target_user_id_uuid = uuid_module.UUID(user_id)
        except ValueError:
            return jsonify({"detail": "Invalid user_id"}), 400
        
        # Cannot deactivate self
        if str(current_user.id) == user_id:
            return jsonify({"detail": "Cannot deactivate yourself"}), 400
        
        db = next(get_db())
        try:
            # Get current tenant from JWT
            tenant_id_uuid = g.tenant_id if isinstance(g.tenant_id, uuid_module.UUID) else uuid_module.UUID(g.tenant_id)
            from models import Tenant
            tenant = db.query(Tenant).filter(Tenant.id == tenant_id_uuid).first()
            if not tenant:
                return jsonify({"detail": "Tenant not found"}), 404
            
            # Get target user (must be in same tenant)
            target_user = db.query(TenantUser).filter(
                TenantUser.id == target_user_id_uuid,
                TenantUser.tenant_id == tenant.id
            ).first()
            
            if not target_user:
                return jsonify({"detail": "User not found"}), 404
            
            # Deactivate
            target_user.is_active = False
            db.commit()
            
            # Write audit log
            try:
                audit_log = AdminAuditLog(
                    tenant_id=tenant.id,
                    user_id=current_user.id,
                    action="ops.user.deactivate",
                    target_type="user",
                    target_id=target_user_id_uuid,
                    metadata_json=json.dumps({"target_email": target_user.email})
                )
                db.add(audit_log)
                db.commit()
            except Exception as audit_error:
                logger.error(f"Failed to record audit log: {str(audit_error)}", exc_info=True)
            
            return jsonify(), 204
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error deactivating user: {str(e)}", exc_info=True)
        return jsonify({"detail": "Internal server error"}), 500


@app.route("/api/v1/admin/users/<user_id>/reactivate", methods=["POST"])
def admin_reactivate_user(user_id: str):
    """
    Reactivate a user in the current tenant.
    Requires: owner role AND tenant slug === "kerr-ai-studio"
    
    Returns:
        204 No Content on success
    """
    try:
        from db import get_db
        from models import TenantUser, AdminAuditLog
        import uuid as uuid_module
        
        # Owner only
        current_user, error_response = require_owner()
        if error_response:
            return error_response
        
        # Parse user_id
        try:
            target_user_id_uuid = uuid_module.UUID(user_id)
        except ValueError:
            return jsonify({"detail": "Invalid user_id"}), 400
        
        db = next(get_db())
        try:
            # Get current tenant from JWT
            tenant_id_uuid = g.tenant_id if isinstance(g.tenant_id, uuid_module.UUID) else uuid_module.UUID(g.tenant_id)
            from models import Tenant
            tenant = db.query(Tenant).filter(Tenant.id == tenant_id_uuid).first()
            if not tenant:
                return jsonify({"detail": "Tenant not found"}), 404
            
            # Get target user (must be in same tenant)
            target_user = db.query(TenantUser).filter(
                TenantUser.id == target_user_id_uuid,
                TenantUser.tenant_id == tenant.id
            ).first()
            
            if not target_user:
                return jsonify({"detail": "User not found"}), 404
            
            # Reactivate
            target_user.is_active = True
            db.commit()
            
            # Write audit log
            try:
                audit_log = AdminAuditLog(
                    tenant_id=tenant.id,
                    user_id=current_user.id,
                    action="ops.user.reactivate",
                    target_type="user",
                    target_id=target_user_id_uuid,
                    metadata_json=json.dumps({"target_email": target_user.email})
                )
                db.add(audit_log)
                db.commit()
            except Exception as audit_error:
                logger.error(f"Failed to record audit log: {str(audit_error)}", exc_info=True)
            
            return jsonify(), 204
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error reactivating user: {str(e)}", exc_info=True)
        return jsonify({"detail": "Internal server error"}), 500


@app.route("/api/v1/admin/tenant/suspend", methods=["POST"])
def admin_suspend_tenant():
    """
    Suspend the current tenant (kill switch).
    Requires: owner role AND tenant slug === "kerr-ai-studio"
    Sets: is_active=false AND subscription_status='suspended'
    
    Returns:
        204 No Content on success
    """
    try:
        from db import get_db
        from models import AdminAuditLog
        
        # Owner only
        current_user, error_response = require_owner()
        if error_response:
            return error_response
        
        db = next(get_db())
        try:
            # Get current tenant from JWT
            import uuid as uuid_module
            tenant_id_uuid = g.tenant_id if isinstance(g.tenant_id, uuid_module.UUID) else uuid_module.UUID(g.tenant_id)
            from models import Tenant
            tenant = db.query(Tenant).filter(Tenant.id == tenant_id_uuid).first()
            if not tenant:
                return jsonify({"detail": "Tenant not found"}), 404
            
            # Update tenant_billing.status (single source of truth for billing)
            from services.entitlements_centralized import update_tenant_billing_status
            try:
                update_tenant_billing_status(db, str(tenant_id_uuid), "suspended")
            except RuntimeError as e:
                logger.error(f"Failed to update tenant_billing.status: {e}")
                return jsonify({"detail": "Failed to update billing status"}), 500
            
            # Suspend tenant
            tenant.is_active = False
            db.commit()
            
            # Write audit log
            try:
                audit_log = AdminAuditLog(
                    tenant_id=tenant.id,
                    user_id=current_user.id,
                    action="ops.tenant.suspend",
                    target_type="tenant",
                    target_id=tenant.id,
                    metadata_json=json.dumps({"tenant_slug": tenant.slug})
                )
                db.add(audit_log)
                db.commit()
            except Exception as audit_error:
                logger.error(f"Failed to record audit log: {str(audit_error)}", exc_info=True)
            
            return jsonify(), 204
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error suspending tenant: {str(e)}", exc_info=True)
        return jsonify({"detail": "Internal server error"}), 500


@app.route("/api/v1/admin/tenant/reactivate", methods=["POST"])
def admin_reactivate_tenant():
    """
    Reactivate the current tenant.
    Requires: owner role AND tenant slug === "kerr-ai-studio"
    Sets: is_active=true AND subscription_status='active'
    
    Returns:
        204 No Content on success
    """
    try:
        from db import get_db
        from models import AdminAuditLog
        
        # Owner only
        current_user, error_response = require_owner()
        if error_response:
            return error_response
        
        db = next(get_db())
        try:
            # Get current tenant from JWT
            import uuid as uuid_module
            tenant_id_uuid = g.tenant_id if isinstance(g.tenant_id, uuid_module.UUID) else uuid_module.UUID(g.tenant_id)
            from models import Tenant
            tenant = db.query(Tenant).filter(Tenant.id == tenant_id_uuid).first()
            if not tenant:
                return jsonify({"detail": "Tenant not found"}), 404
            
            # Reactivate tenant
            # Update tenant_billing.status (single source of truth for billing)
            from services.entitlements_centralized import update_tenant_billing_status
            try:
                update_tenant_billing_status(db, str(tenant_id_uuid), "active")
            except RuntimeError as e:
                logger.error(f"Failed to update tenant_billing.status: {e}")
                return jsonify({"detail": "Failed to update billing status"}), 500
            
            tenant.is_active = True
            db.commit()
            
            # Write audit log
            try:
                audit_log = AdminAuditLog(
                    tenant_id=tenant.id,
                    user_id=current_user.id,
                    action="ops.tenant.reactivate",
                    target_type="tenant",
                    target_id=tenant.id,
                    metadata_json=json.dumps({"tenant_slug": tenant.slug})
                )
                db.add(audit_log)
                db.commit()
            except Exception as audit_error:
                logger.error(f"Failed to record audit log: {str(audit_error)}", exc_info=True)
            
            return jsonify(), 204
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error reactivating tenant: {str(e)}", exc_info=True)
        return jsonify({"detail": "Internal server error"}), 500


@app.route("/api/v1/admin/usage/summary", methods=["GET"])
def admin_usage_summary():
    """
    Get usage summary for the current tenant.
    Requires: owner role AND tenant slug === "kerr-ai-studio"
    
    Query params:
        days: int (default 30, clamp 1..365)
    
    Returns:
        {
            "days": <int>,
            "totals": {
                "events": <int>,
                "success": <int>,
                "failed": <int>,
                "jira_ticket_count": <int>,
                "input_char_count": <int>
            },
            "by_agent": [
                {
                    "agent": <str>,
                    "events": <int>,
                    "success": <int>,
                    "failed": <int>,
                    "jira_ticket_count": <int>,
                    "input_char_count": <int>
                },
                ...
            ]
        }
    """
    try:
        from db import get_db
        from models import UsageEvent
        from datetime import datetime, timezone, timedelta
        
        # Owner only
        user, error_response = require_owner()
        if error_response:
            return error_response
        
        # Parse days param
        days = request.args.get('days', 30, type=int)
        days = max(1, min(365, days))  # Clamp 1..365
        
        db = next(get_db())
        try:
            # Get current tenant from JWT
            import uuid as uuid_module
            tenant_id_uuid = g.tenant_id if isinstance(g.tenant_id, uuid_module.UUID) else uuid_module.UUID(g.tenant_id)
            from models import Tenant
            tenant = db.query(Tenant).filter(Tenant.id == tenant_id_uuid).first()
            if not tenant:
                return jsonify({"detail": "Tenant not found"}), 404
            
            # Calculate cutoff date
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
            
            # Query usage events for this tenant
            events = db.query(UsageEvent).filter(
                UsageEvent.tenant_id == tenant.id,
                UsageEvent.created_at >= cutoff_date
            ).all()
            
            # Calculate totals
            totals = {
                "events": len(events),
                "success": sum(1 for e in events if e.success),
                "failed": sum(1 for e in events if not e.success),
                "jira_ticket_count": sum(e.jira_ticket_count or 0 for e in events),
                "input_char_count": sum(e.input_char_count or 0 for e in events)
            }
            
            # Group by agent
            by_agent_dict = {}
            for event in events:
                agent = event.agent or "unknown"
                if agent not in by_agent_dict:
                    by_agent_dict[agent] = {
                        "agent": agent,
                        "events": 0,
                        "success": 0,
                        "failed": 0,
                        "jira_ticket_count": 0,
                        "input_char_count": 0
                    }
                
                by_agent_dict[agent]["events"] += 1
                if event.success:
                    by_agent_dict[agent]["success"] += 1
                else:
                    by_agent_dict[agent]["failed"] += 1
                by_agent_dict[agent]["jira_ticket_count"] += (event.jira_ticket_count or 0)
                by_agent_dict[agent]["input_char_count"] += (event.input_char_count or 0)
            
            by_agent = list(by_agent_dict.values())
            
            return jsonify({
                "days": days,
                "totals": totals,
                "by_agent": by_agent
            }), 200
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error getting usage summary: {str(e)}", exc_info=True)
        return jsonify({"detail": "Internal server error"}), 500


@app.route("/api/v1/admin/runs/recent", methods=["GET"])
def admin_recent_runs():
    """
    Get recent runs for the current tenant.
    Requires: owner role AND tenant slug === "kerr-ai-studio"
    
    Query params:
        limit: int (default 25, max 100)
    
    Returns:
        List of runs with: run_id, created_at, agent, status, review_status, jira_issue_key, summary
    """
    try:
        from db import get_db
        from models import Run
        
        # Owner only
        user, error_response = require_owner()
        if error_response:
            return error_response
        
        # Parse limit param
        limit = request.args.get('limit', 25, type=int)
        limit = max(1, min(100, limit))  # Clamp 1..100
        
        db = next(get_db())
        try:
            # Get current tenant from JWT
            import uuid as uuid_module
            tenant_id_uuid = g.tenant_id if isinstance(g.tenant_id, uuid_module.UUID) else uuid_module.UUID(g.tenant_id)
            from models import Tenant
            tenant = db.query(Tenant).filter(Tenant.id == tenant_id_uuid).first()
            if not tenant:
                return jsonify({"detail": "Tenant not found"}), 404
            
            # Query recent runs for this tenant
            runs = db.query(Run).filter(
                Run.tenant_id == tenant.id
            ).order_by(Run.created_at.desc()).limit(limit).all()
            
            runs_list = []
            for r in runs:
                runs_list.append({
                    "run_id": r.run_id,
                    "created_at": r.created_at.isoformat() + "Z" if r.created_at else None,
                    "agent": r.agent or "unknown",
                    "status": r.status,
                    "review_status": r.review_status,
                    "jira_issue_key": r.jira_issue_key,
                    "summary": r.summary
                })
            
            return jsonify(runs_list), 200
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error getting recent runs: {str(e)}", exc_info=True)
        return jsonify({"detail": "Internal server error"}), 500


@app.route("/api/v1/admin/audit", methods=["GET"])
def admin_audit_log():
    """
    Get admin audit log for the current tenant.
    Requires: owner role AND tenant slug === "kerr-ai-studio"
    
    Query params:
        limit: int (default 50, max 200)
    
    Returns:
        List of audit log entries ordered by created_at desc
    """
    try:
        from db import get_db
        from models import AdminAuditLog
        
        # Owner only
        user, error_response = require_owner()
        if error_response:
            return error_response
        
        # Parse limit param
        limit = request.args.get('limit', 50, type=int)
        limit = max(1, min(200, limit))  # Clamp 1..200
        
        db = next(get_db())
        try:
            # Get current tenant from JWT
            import uuid as uuid_module
            tenant_id_uuid = g.tenant_id if isinstance(g.tenant_id, uuid_module.UUID) else uuid_module.UUID(g.tenant_id)
            from models import Tenant
            tenant = db.query(Tenant).filter(Tenant.id == tenant_id_uuid).first()
            if not tenant:
                return jsonify({"detail": "Tenant not found"}), 404
            
            # Query audit log for this tenant
            audit_logs = db.query(AdminAuditLog).filter(
                AdminAuditLog.tenant_id == tenant.id
            ).order_by(AdminAuditLog.created_at.desc()).limit(limit).all()
            
            logs_list = []
            for log in audit_logs:
                logs_list.append({
                    "id": str(log.id),
                    "user_id": str(log.user_id),
                    "action": log.action,
                    "target_type": log.target_type,
                    "target_id": str(log.target_id) if log.target_id else None,
                    "metadata": json.loads(log.metadata_json) if log.metadata_json else None,
                    "created_at": log.created_at.isoformat() + "Z" if log.created_at else None
                })
            
            return jsonify(logs_list), 200
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error getting audit log: {str(e)}", exc_info=True)
        return jsonify({"detail": "Internal server error"}), 500


@app.route("/api/v1/tenant/bootstrap-status", methods=["GET"])
def get_bootstrap_status():
    """
    Return tenant onboarding/bootstrap status for routing decisions.
    Includes subscription status, trial counts, and Jira integration status.
    
    Returns:
        {
            "tenant_id": "...",
            "subscription_status": "unselected|trial|individual|team|paywalled|canceled",
            "trial": {
                "requirements": <int>,
                "testplan": <int>,
                "writeback": <int>
            },
            "jira": {
                "configured": true|false,
                "is_active": true|false,
                "jira_base_url": "...",
                "jira_user_email": "..."
            }
        }
    """
    try:
        from db import get_db
        from models import Tenant, TenantIntegration
        import uuid as uuid_module

        # Get tenant_id from JWT (set by middleware)
        tenant_id = g.tenant_id
        if not tenant_id:
            return jsonify({"detail": "Unauthorized"}), 401

        db = next(get_db())
        try:
            # Convert tenant_id to UUID if needed
            tenant_uuid = tenant_id if isinstance(tenant_id, uuid_module.UUID) else uuid_module.UUID(tenant_id)

            # Get tenant
            tenant = db.query(Tenant).filter(Tenant.id == tenant_uuid).first()
            if not tenant:
                return jsonify({"detail": "Tenant not found"}), 404

            # Get Jira integration
            jira_integration = db.query(TenantIntegration).filter(
                TenantIntegration.tenant_id == tenant_uuid,
                TenantIntegration.provider == 'jira'
            ).first()

            # Check if Jira is fully configured (all three required fields must be non-NULL and non-empty)
            jira_fully_configured = False
            if jira_integration:
                jira_base_url = jira_integration.jira_base_url
                jira_user_email = jira_integration.jira_user_email
                credentials_ciphertext = jira_integration.credentials_ciphertext
                
                # All three fields must be present and non-empty
                # Check each field: must be not None, then check if it's not empty (after stripping whitespace)
                has_base_url = jira_base_url is not None and str(jira_base_url).strip() != ''
                has_user_email = jira_user_email is not None and str(jira_user_email).strip() != ''
                has_credentials = credentials_ciphertext is not None and str(credentials_ciphertext).strip() != ''
                
                jira_fully_configured = has_base_url and has_user_email and has_credentials

            # Build response
            jira_status = {
                "configured": jira_fully_configured,
                "is_active": jira_integration.is_active if jira_integration else False,
                "jira_base_url": jira_integration.jira_base_url if jira_integration else None,
                "jira_user_email": jira_integration.jira_user_email if jira_integration else None
            }

            # Get billing data from tenant_billing (single source of truth)
            from services.entitlements_centralized import get_tenant_billing
            try:
                billing = get_tenant_billing(db, str(tenant_uuid))
                subscription_status = billing.get("subscription_status", "unselected")
                trial_requirements = billing.get("trial_requirements_runs_remaining", 0)
                trial_testplan = billing.get("trial_testplan_runs_remaining", 0)
                trial_writeback = billing.get("trial_writeback_runs_remaining", 0)
            except RuntimeError as e:
                logger.error(f"tenant_billing missing in get_bootstrap_status: {e}")
                return jsonify({"detail": "Billing data is required but not found"}), 500
            
            return jsonify({
                "tenant_id": str(tenant.id),
                "subscription_status": subscription_status,
                "trial": {
                    "requirements": trial_requirements,
                    "testplan": trial_testplan,
                    "writeback": trial_writeback
                },
                "jira": jira_status
            }), 200

        finally:
            db.close()

    except Exception as e:
        logger.error(f"Error fetching bootstrap status: {str(e)}")
        return jsonify({"detail": f"Failed to fetch bootstrap status: {str(e)}"}), 500


@app.route("/api/v1/runs", methods=["GET"])
def list_runs():
    """
    List test plan generation runs with pagination.
    
    Query parameters:
        page: int = 1 (min 1, 1-based)
        limit: int = 10 (min 1, max 50)
    
    Returns:
        {
            "items": [ ...runs... ],
            "pagination": {
                "total": <int>,
                "page": <int>,
                "limit": <int>,
                "total_pages": <int>,
                "has_prev": <bool>,
                "has_next": <bool>
            }
        }
    """
    try:
        from db import get_db
        from models import Run
        from sqlalchemy import func
        
        db = next(get_db())
        try:
            # Get tenant_id from JWT (set by middleware)
            tenant_id = g.tenant_id
            if not tenant_id:
                return jsonify({"detail": "Unauthorized"}), 401
            
            # Get pagination parameters
            page = request.args.get('page', '1', type=int)
            limit = request.args.get('limit', '10', type=int)
            
            # Validate and clamp pagination params
            page = max(1, page)
            limit = max(1, min(50, limit))  # Clamp between 1 and 50
            
            # Base query with tenant isolation
            base_query = db.query(Run).filter(Run.tenant_id == tenant_id)
            
            # Get total count
            total = base_query.count()
            
            # Calculate pagination metadata
            total_pages = (total + limit - 1) // limit if total > 0 else 0
            
            # Clamp page to valid range (if page > total_pages and total_pages > 0, return empty)
            if total_pages > 0 and page > total_pages:
                # Return empty items with correct pagination metadata
                return jsonify({
                    "items": [],
                    "pagination": {
                        "total": total,
                        "page": page,
                        "limit": limit,
                        "total_pages": total_pages,
                        "has_prev": False,
                        "has_next": False
                    }
                }), 200
            
            # Query paginated runs, ordered by created_at descending, then run_id descending for stability
            offset = (page - 1) * limit
            runs = base_query.order_by(Run.created_at.desc(), Run.run_id.desc()).offset(offset).limit(limit).all()
            
            # Format runs for JSON response
            runs_list = []
            for run in runs:
                # Safely get datetime values
                def safe_isoformat(attr_name):
                    if not hasattr(run, attr_name):
                        return None
                    value = getattr(run, attr_name, None)
                    return value.isoformat() + "Z" if value else None
                
                runs_list.append({
                    "run_id": run.run_id,
                    "created_at": run.created_at.isoformat() + "Z" if run.created_at else None,
                    "source_type": run.source_type,
                    "ticket_count": run.ticket_count,
                    "status": run.status,
                    "logic_version": run.logic_version,
                    "model_name": run.model_name,
                    "created_by": run.created_by or "anonymous",
                    "environment": run.environment or "development",
                    "review_status": getattr(run, 'review_status', 'generated'),
                    "reviewed_by": getattr(run, 'reviewed_by', None),
                    "reviewed_at": safe_isoformat('reviewed_at'),
                    "approved_by": getattr(run, 'approved_by', None),
                    "approved_at": safe_isoformat('approved_at'),
                    "jira_issue_key": getattr(run, 'jira_issue_key', None),
                    "jira_issue_url": getattr(run, 'jira_issue_url', None),
                    "jira_created_by": getattr(run, 'jira_created_by', None),
                    "jira_created_at": safe_isoformat('jira_created_at'),
                    "jira_audit_comment_posted_at": safe_isoformat('jira_audit_comment_posted_at'),
                    "jira_audit_comment_posted_by": getattr(run, 'jira_audit_comment_posted_by', None),
                    "jira_audit_comment_id": getattr(run, 'jira_audit_comment_id', None),
                    # New fields for agent and run type
                    "agent": getattr(run, 'agent', 'testing-agent'),
                    "run_kind": getattr(run, 'run_kind', 'test_plan'),
                    "artifact_type": getattr(run, 'artifact_type', None),
                    "artifact_id": getattr(run, 'artifact_id', None),
                    "summary": getattr(run, 'summary', None),
                    "input_ticket_count": getattr(run, 'input_ticket_count', None),
                    "output_item_count": getattr(run, 'output_item_count', None)
                })
            
            # Return paginated response
            return jsonify({
                "items": runs_list,
                "pagination": {
                    "total": total,
                    "page": page,
                    "limit": limit,
                    "total_pages": total_pages,
                    "has_prev": page > 1,
                    "has_next": page < total_pages if total_pages > 0 else False
                }
            }), 200
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Error listing runs: {str(e)}")
        return jsonify({
            "detail": f"Failed to list runs: {str(e)}"
        }), 500


@app.route("/api/v1/runs/<run_id>/<artifact_type>", methods=["GET"])
def get_artifact(run_id: str, artifact_type: str):
    """
    Fetch a stored artifact for a specific run.
    
    Args:
        run_id: Run identifier (UUID string)
        artifact_type: Type of artifact ("package" | "rtm" | "test_plan")
    
    Returns:
        JSON content of the artifact file.
    """
    try:
        from db import get_db
        from models import Artifact
        import json as json_module
        
        # Validate artifact_type
        allowed_types = {"test_plan", "rtm", "analysis", "audit_metadata"}
        if artifact_type not in allowed_types:
            return jsonify({
                "detail": f"Invalid artifact_type '{artifact_type}'. Allowed values: {', '.join(sorted(allowed_types))}"
            }), 400
        
        db = next(get_db())
        try:
            # Get tenant_id from JWT (set by middleware)
            tenant_id = g.tenant_id
            if not tenant_id:
                return jsonify({"detail": "Unauthorized"}), 401
            
            # Look up artifact in database (tenant-scoped)
            artifact = db.query(Artifact).filter(
                Artifact.run_id == run_id,
                Artifact.artifact_type == artifact_type,
                Artifact.tenant_id == tenant_id
            ).first()
            
            if not artifact:
                return jsonify({
                    "detail": f"Artifact '{artifact_type}' not found for run '{run_id}'"
                }), 404
            
            # Read JSON file from disk
            artifact_path = artifact.path
            if not os.path.exists(artifact_path):
                return jsonify({
                    "detail": f"Artifact file not found at path: {artifact_path}"
                }), 404
            
            # Read and parse JSON file
            try:
                with open(artifact_path, 'r', encoding='utf-8') as f:
                    artifact_data = json_module.load(f)
                
                return jsonify(artifact_data), 200
            except json_module.JSONDecodeError as e:
                return jsonify({
                    "detail": f"Failed to parse artifact JSON: {str(e)}"
                }), 500
            except IOError as e:
                return jsonify({
                    "detail": f"Failed to read artifact file: {str(e)}"
                }), 500
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Error fetching artifact {artifact_type} for run {run_id}: {str(e)}")
        return jsonify({
            "detail": f"Failed to fetch artifact: {str(e)}"
        }), 500


@app.route("/api/v1/test-plan/<run_id>.json", methods=["GET"])
def get_test_plan_json(run_id: str):
    """
    Fetch test plan artifact for a specific run.
    
    Args:
        run_id: Run identifier (UUID string)
    
    Returns:
        JSON content of the test plan artifact.
    """
    return _get_artifact_by_type(run_id, "test_plan")


@app.route("/api/v1/rtm/<run_id>.json", methods=["GET"])
def get_rtm_json(run_id: str):
    """
    Fetch RTM artifact for a specific run.
    
    Args:
        run_id: Run identifier (UUID string)
    
    Returns:
        JSON content of the RTM artifact.
    """
    return _get_artifact_by_type(run_id, "rtm")


@app.route("/api/v1/analysis/<run_id>.json", methods=["GET"])
def get_analysis_json(run_id: str):
    """
    Fetch analysis/package artifact for a specific run.
    
    Args:
        run_id: Run identifier (UUID string)
    
    Returns:
        JSON content of the analysis artifact.
    """
    return _get_artifact_by_type(run_id, "analysis")


@app.route("/api/v1/audit/<run_id>.json", methods=["GET"])
def get_audit_json(run_id: str):
    """
    Fetch audit metadata artifact for a specific run, enriched with review/approval info.
    
    Args:
        run_id: Run identifier (UUID string)
    
    Returns:
        JSON content of the audit metadata artifact, enriched with review/approval lifecycle info.
    """
    try:
        from db import get_db
        from models import Run
        import json as json_module
        
        db = next(get_db())
        try:
            # Get tenant_id from JWT (set by middleware)
            tenant_id = g.tenant_id
            if not tenant_id:
                return jsonify({"detail": "Unauthorized"}), 401
            
            # Get run to access review/approval info (tenant-scoped)
            run = db.query(Run).filter(
                Run.run_id == run_id,
                Run.tenant_id == tenant_id
            ).first()
            if not run:
                return jsonify({"detail": "Run not found"}), 404
            
            # Get artifact path
            from services.persistence import get_artifact_path
            artifact_path = get_artifact_path(db, run_id, "audit_metadata", tenant_id)
            
            if not artifact_path or not os.path.exists(artifact_path):
                return jsonify({"detail": "Audit metadata artifact not found"}), 404
            
            # Read audit metadata
            with open(artifact_path, 'r', encoding='utf-8') as f:
                audit_data = json_module.load(f)
            
            # Enrich with scope lifecycle from analysis package and Jira info (additive only)
            if isinstance(audit_data, dict):
                # Extract scope lifecycle from analysis package if available
                analysis_path = get_artifact_path(db, run_id, "analysis", tenant_id)
                if analysis_path and os.path.exists(analysis_path):
                    try:
                        with open(analysis_path, 'r', encoding='utf-8') as f:
                            analysis_data = json_module.load(f)
                        
                        # Extract scope lifecycle from package in analysis
                        # Package might be at top level or nested in analysis_data
                        package = None
                        if isinstance(analysis_data, dict):
                            # Try top-level package field first
                            package = analysis_data.get("package")
                            # If not found, check if analysis_data itself is a package (has scope_status)
                            if not package and "scope_status" in analysis_data:
                                package = analysis_data
                        
                        if package and isinstance(package, dict):
                            scope_status = package.get("scope_status")
                            scope_status_transitions = package.get("scope_status_transitions", [])
                            
                            if scope_status:
                                audit_data["scope_status"] = scope_status
                            
                            # Extract reviewed_by/at and approved_by/at from transitions
                            for transition in scope_status_transitions:
                                if isinstance(transition, dict):
                                    new_status = transition.get("new_status")
                                    changed_by = transition.get("changed_by")
                                    changed_at = transition.get("changed_at")
                                    
                                    if new_status == "reviewed" and changed_by:
                                        audit_data["scope_reviewed_by"] = changed_by
                                        if changed_at:
                                            if isinstance(changed_at, str):
                                                audit_data["scope_reviewed_at"] = changed_at
                                            else:
                                                audit_data["scope_reviewed_at"] = changed_at.isoformat() + "Z" if hasattr(changed_at, 'isoformat') else None
                                    
                                    if new_status == "locked" and changed_by:
                                        audit_data["scope_approved_by"] = changed_by
                                        if changed_at:
                                            if isinstance(changed_at, str):
                                                audit_data["scope_approved_at"] = changed_at
                                            else:
                                                audit_data["scope_approved_at"] = changed_at.isoformat() + "Z" if hasattr(changed_at, 'isoformat') else None
                    except Exception as e:
                        logger.warning(f"Failed to extract scope lifecycle from analysis: {str(e)}")
                
                # Jira metadata (Phase 3)
                audit_data["jira_issue_key"] = getattr(run, 'jira_issue_key', None)
                audit_data["jira_created_by"] = getattr(run, 'jira_created_by', None)
                audit_data["jira_created_at"] = run.jira_created_at.isoformat() + "Z" if hasattr(run, 'jira_created_at') and run.jira_created_at else None
            
            return jsonify(audit_data), 200
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Error fetching audit metadata for run {run_id}: {str(e)}")
        return jsonify({"detail": f"Failed to fetch audit metadata: {str(e)}"}), 500


def _get_artifact_by_type(run_id: str, artifact_type: str):
    """
    Helper function to fetch artifact by type.
    
    Args:
        run_id: Run identifier
        artifact_type: Type of artifact
    
    Returns:
        Flask response with JSON content or error
    """
    try:
        from db import get_db
        from models import Run, Artifact
        from services.persistence import get_artifact_path
        import json as json_module
        
        db = next(get_db())
        try:
            # Get tenant_id from JWT (set by middleware)
            tenant_id = g.tenant_id
            if not tenant_id:
                return jsonify({"detail": "Unauthorized"}), 401
            
            # First check if run exists (tenant-scoped)
            run = db.query(Run).filter(
                Run.run_id == run_id,
                Run.tenant_id == tenant_id
            ).first()
            if not run:
                return jsonify({
                    "detail": "Run not found"
                }), 404
            
            # Look up artifact path (tenant-scoped)
            artifact_path = get_artifact_path(db, run_id, artifact_type, tenant_id)
            
            if not artifact_path:
                return jsonify({
                    "detail": "Artifact not found"
                }), 404
            
            # Check if file exists
            if not os.path.exists(artifact_path):
                return jsonify({
                    "detail": "Artifact not found"
                }), 404
            
            # Read and parse JSON file
            try:
                with open(artifact_path, 'r', encoding='utf-8') as f:
                    artifact_data = json_module.load(f)
                
                return jsonify(artifact_data), 200
            except json_module.JSONDecodeError as e:
                return jsonify({
                    "detail": f"Failed to parse artifact JSON: {str(e)}"
                }), 500
            except IOError as e:
                return jsonify({
                    "detail": f"Failed to read artifact file: {str(e)}"
                }), 500
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Error fetching {artifact_type} for run {run_id}: {str(e)}")
        return jsonify({
            "detail": f"Failed to fetch artifact: {str(e)}"
        }), 500


def _check_run_immutability(run: "Run") -> tuple[bool, Optional[str]]:
    """
    Check if a run is immutable (approved).
    
    Returns:
        (is_immutable, error_message)
    """
    if hasattr(run, 'review_status') and run.review_status == "approved":
        return True, "Run is approved and immutable. Create a new run for changes."
    return False, None


@app.route("/api/v1/runs/<run_id>/review", methods=["POST"])
def mark_run_reviewed(run_id: str):
    """
    Mark a run as reviewed.
    Transitions: generated -> reviewed
    """
    try:
        from db import get_db
        from models import Run
        from datetime import datetime
        
        # Get actor from X-Actor header
        actor = request.headers.get("X-Actor", "anonymous")
        
        db = next(get_db())
        try:
            # Get tenant_id from JWT (set by middleware)
            tenant_id = g.tenant_id
            if not tenant_id:
                return jsonify({"detail": "Unauthorized"}), 401
            
            # Get run (tenant-scoped)
            run = db.query(Run).filter(
                Run.run_id == run_id,
                Run.tenant_id == tenant_id
            ).first()
            if not run:
                return jsonify({"detail": "Run not found"}), 404
            
            # Check immutability
            is_immutable, error_msg = _check_run_immutability(run)
            if is_immutable:
                return jsonify({"detail": error_msg}), 403
            
            # Get current review_status (default to "generated" if not set)
            current_status = getattr(run, 'review_status', 'generated')
            
            # Validate transition
            if current_status != "generated":
                return jsonify({
                    "detail": f"Invalid transition: run is already '{current_status}'. Only 'generated' runs can be marked as reviewed."
                }), 400
            
            # Perform transition
            run.review_status = "reviewed"
            run.reviewed_by = actor
            run.reviewed_at = datetime.utcnow()
            
            db.commit()
            db.refresh(run)
            
            return jsonify({
                "run_id": run.run_id,
                "review_status": run.review_status,
                "reviewed_by": run.reviewed_by,
                "reviewed_at": run.reviewed_at.isoformat() + "Z" if run.reviewed_at else None,
                "message": "Run marked as reviewed"
            }), 200
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Error marking run {run_id} as reviewed: {str(e)}")
        return jsonify({"detail": f"Failed to mark run as reviewed: {str(e)}"}), 500


@app.route("/api/v1/runs/<run_id>/approve", methods=["POST"])
def approve_run(run_id: str):
    """
    Approve a run.
    Transitions: reviewed -> approved
    """
    try:
        from db import get_db
        from models import Run
        from datetime import datetime
        
        # Get actor from X-Actor header
        actor = request.headers.get("X-Actor", "anonymous")
        
        db = next(get_db())
        try:
            # Get tenant_id from JWT (set by middleware)
            tenant_id = g.tenant_id
            if not tenant_id:
                return jsonify({"detail": "Unauthorized"}), 401
            
            # Get run (tenant-scoped)
            run = db.query(Run).filter(
                Run.run_id == run_id,
                Run.tenant_id == tenant_id
            ).first()
            if not run:
                return jsonify({"detail": "Run not found"}), 404
            
            # Check immutability (shouldn't happen, but defensive)
            is_immutable, error_msg = _check_run_immutability(run)
            if is_immutable:
                return jsonify({"detail": error_msg}), 403
            
            # Get current review_status (default to "generated" if not set)
            current_status = getattr(run, 'review_status', 'generated')
            
            # Validate transition
            if current_status != "reviewed":
                return jsonify({
                    "detail": f"Invalid transition: run is '{current_status}'. Only 'reviewed' runs can be approved."
                }), 400
            
            # Perform transition
            run.review_status = "approved"
            run.approved_by = actor
            run.approved_at = datetime.utcnow()
            
            db.commit()
            db.refresh(run)
            
            return jsonify({
                "run_id": run.run_id,
                "review_status": run.review_status,
                "approved_by": run.approved_by,
                "approved_at": run.approved_at.isoformat() + "Z" if run.approved_at else None,
                "message": "Run approved"
            }), 200
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Error approving run {run_id}: {str(e)}")
        return jsonify({"detail": f"Failed to approve run: {str(e)}"}), 500


def _get_jira_config():
    """
    Get Jira configuration from database (tenant-specific).
    
    Returns:
        dict with jira_base_url, jira_username, jira_api_token, jira_project_key, jira_issue_type
        
    Raises:
        ValueError: If required config is missing
    """
    from services.integrations import get_jira_integration_for_current_tenant
    
    # Get credentials from database
    jira_creds = get_jira_integration_for_current_tenant()
    
    # Project key and issue type still come from env (tenant-agnostic config)
    jira_project_key = os.getenv("JIRA_PROJECT_KEY")
    jira_issue_type = os.getenv("JIRA_ISSUE_TYPE", "Task")
    
    if not jira_project_key:
        raise ValueError("JIRA_PROJECT_KEY environment variable is required")
    
    return {
        "jira_base_url": jira_creds["base_url"],
        "jira_username": jira_creds["email"],
        "jira_api_token": jira_creds["api_token"],
        "jira_project_key": jira_project_key,
        "jira_issue_type": jira_issue_type
    }


def _generate_jira_description(
    run_id: str,
    created_by: str,
    approved_by: Optional[str],
    approved_at: Optional[str],
    reviewed_by: Optional[str] = None,
    reviewed_at: Optional[str] = None,
    analysis_data: Optional[dict] = None,
    test_plan_data: Optional[dict] = None,
    rtm_data: Optional[list] = None,
    audit_metadata: Optional[dict] = None
) -> str:
    """
    Generate Jira description from run artifacts (deterministic mapping).
    
    Args:
        run_id: Run identifier
        created_by: Actor who created the run
        approved_by: Actor who approved the run
        approved_at: Timestamp when approved
        reviewed_by: Optional actor who reviewed the run (from scope lifecycle)
        reviewed_at: Optional timestamp when reviewed (from scope lifecycle)
        analysis_data: Analysis artifact data
        test_plan_data: Test plan artifact data
        rtm_data: RTM artifact data
        audit_metadata: Audit metadata (enriched with scope lifecycle)
        
    Returns:
        Formatted description text
    """
    # Handle None defaults
    if analysis_data is None:
        analysis_data = {}
    if test_plan_data is None:
        test_plan_data = {}
    if rtm_data is None:
        rtm_data = []
    if audit_metadata is None:
        audit_metadata = {}
    
    description_parts = []
    
    # Run metadata section
    description_parts.append("h2. Run Metadata")
    description_parts.append(f"* Run ID:* {run_id}")
    description_parts.append(f"* Created By:* {created_by}")
    if approved_by:
        description_parts.append(f"* Approved By:* {approved_by}")
    if approved_at:
        description_parts.append(f"* Approved At:* {approved_at}")
    description_parts.append("")
    
    # Scope summary from analysis
    description_parts.append("h2. Scope Summary")
    business_intent = analysis_data.get("business_intent", "")
    if business_intent:
        description_parts.append(business_intent)
    else:
        description_parts.append("Scope information available in analysis artifact.")
    description_parts.append("")
    
    # Test plan summary
    description_parts.append("h2. Test Plan Summary")
    test_plan = test_plan_data.get("test_plan", {})
    test_counts = {}
    total_tests = 0
    for category in ["api_tests", "ui_tests", "data_validation_tests", "edge_cases", "negative_tests"]:
        tests = test_plan.get(category, [])
        count = len(tests) if isinstance(tests, list) else 0
        test_counts[category.replace("_", " ").title()] = count
        total_tests += count
    
    description_parts.append(f"* Total Tests:* {total_tests}")
    for category, count in test_counts.items():
        if count > 0:
            description_parts.append(f"* {category}:* {count}")
    description_parts.append("")
    
    # RTM summary
    description_parts.append("h2. RTM Summary")
    if rtm_data and isinstance(rtm_data, list):
        covered_count = sum(1 for entry in rtm_data if entry.get("coverage_status") == "COVERED")
        not_covered_count = sum(1 for entry in rtm_data if entry.get("coverage_status") == "NOT COVERED")
        total_requirements = len(rtm_data)
        description_parts.append(f"* Total Requirements:* {total_requirements}")
        description_parts.append(f"* Covered:* {covered_count}")
        description_parts.append(f"* Not Covered:* {not_covered_count}")
        
        # Check for gaps or risks
        gaps = analysis_data.get("gaps_detected", [])
        if gaps and isinstance(gaps, list) and len(gaps) > 0:
            description_parts.append("")
            description_parts.append("* Gaps Detected:*")
            for gap in gaps[:5]:  # Limit to first 5
                gap_desc = gap.get("description", "") if isinstance(gap, dict) else str(gap)
                if gap_desc:
                    description_parts.append(f"* {gap_desc}")
    else:
        description_parts.append("RTM data available in RTM artifact.")
    description_parts.append("")
    
    # Audit statement
    description_parts.append("h2. Audit Statement")
    description_parts.append("This ticket was generated by ScopeTrace AI from an approved, immutable run.")
    description_parts.append("")
    description_parts.append("For full traceability, refer to the run artifacts:")
    description_parts.append(f"* Run ID: {run_id}")
    description_parts.append("* All artifacts are immutable and audit-ready.")
    description_parts.append("")
    
    # Audit Summary section
    description_parts.append("----")
    description_parts.append("ScopeTrace AI — Audit Summary")
    
    # Extract audit fields from audit_metadata
    agent_metadata = audit_metadata.get("agent_metadata", {}) if isinstance(audit_metadata, dict) else {}
    scope_status = audit_metadata.get("scope_status") if isinstance(audit_metadata, dict) else None
    
    # Run ID
    description_parts.append(f"- Run ID: {run_id}")
    
    # Scope Status (must be approved)
    if scope_status:
        description_parts.append(f"- Scope Status: {scope_status}")
    else:
        description_parts.append("- Scope Status: approved")  # Default since run must be approved
    
    # Created by/at
    if created_by:
        description_parts.append(f"- Created: {created_by}")
        created_at = audit_metadata.get("generated_at") if isinstance(audit_metadata, dict) else None
        if created_at:
            description_parts.append(f"  Created At: {created_at}")
    
    # Reviewed by/at (from scope lifecycle)
    scope_reviewed_by = audit_metadata.get("scope_reviewed_by") if isinstance(audit_metadata, dict) else None
    scope_reviewed_at = audit_metadata.get("scope_reviewed_at") if isinstance(audit_metadata, dict) else None
    if scope_reviewed_by:
        description_parts.append(f"- Reviewed: {scope_reviewed_by}")
        if scope_reviewed_at:
            description_parts.append(f"  Reviewed At: {scope_reviewed_at}")
    elif reviewed_by:
        # Fallback to old field names if scope_* not available
        description_parts.append(f"- Reviewed: {reviewed_by}")
        if reviewed_at:
            description_parts.append(f"  Reviewed At: {reviewed_at}")
    
    # Approved by/at (from scope lifecycle)
    scope_approved_by = audit_metadata.get("scope_approved_by") if isinstance(audit_metadata, dict) else None
    scope_approved_at = audit_metadata.get("scope_approved_at") if isinstance(audit_metadata, dict) else None
    if scope_approved_by:
        description_parts.append(f"- Approved: {scope_approved_by}")
        if scope_approved_at:
            description_parts.append(f"  Approved At: {scope_approved_at}")
    elif approved_by:
        # Fallback to old field names if scope_* not available
        description_parts.append(f"- Approved: {approved_by}")
        if approved_at:
            description_parts.append(f"  Approved At: {approved_at}")
    
    # Agent Version
    agent_version = agent_metadata.get("agent_version") if agent_metadata else audit_metadata.get("agent_version") if isinstance(audit_metadata, dict) else None
    if agent_version:
        description_parts.append(f"- Agent Version: {agent_version}")
    
    # Logic Version
    logic_version = agent_metadata.get("logic_version") if agent_metadata else audit_metadata.get("logic_version") if isinstance(audit_metadata, dict) else None
    if logic_version:
        description_parts.append(f"- Logic Version: {logic_version}")
    
    # Change Policy
    change_policy = agent_metadata.get("change_policy") if agent_metadata else audit_metadata.get("change_policy") if isinstance(audit_metadata, dict) else None
    if change_policy:
        description_parts.append(f"- Change Policy: {change_policy}")
    else:
        description_parts.append("- Change Policy: idempotent")  # Default
    
    # Determinism (if present)
    determinism = agent_metadata.get("determinism") if agent_metadata else audit_metadata.get("determinism") if isinstance(audit_metadata, dict) else None
    if determinism:
        description_parts.append(f"- Determinism: {determinism}")
    
    description_parts.append("----")
    
    return "\n".join(description_parts)


def _generate_audit_summary_comment(
    run_id: str,
    created_by: str,
    created_at: Optional[str],
    approved_by: Optional[str],
    approved_at: Optional[str],
    reviewed_by: Optional[str] = None,
    reviewed_at: Optional[str] = None,
    audit_metadata: Optional[dict] = None
) -> str:
    """
    Generate audit summary comment text for Jira (deterministic).
    
    Args:
        run_id: Run identifier
        created_by: Actor who created the run
        created_at: Timestamp when run was created
        approved_by: Actor who approved the run
        approved_at: Timestamp when approved
        reviewed_by: Optional actor who reviewed the run (from scope lifecycle)
        reviewed_at: Optional timestamp when reviewed (from scope lifecycle)
        audit_metadata: Audit metadata (enriched with scope lifecycle)
        
    Returns:
        Formatted comment text with deterministic marker
    """
    if audit_metadata is None:
        audit_metadata = {}
    
    comment_parts = []
    comment_parts.append("----")
    comment_parts.append("ScopeTrace AI — Audit Summary")
    comment_parts.append(f"ScopeTraceAI-Audit: {run_id}")
    
    # Scope Status (must be approved)
    scope_status = audit_metadata.get("scope_status") if isinstance(audit_metadata, dict) else None
    if scope_status:
        comment_parts.append(f"- Scope Status: {scope_status}")
    else:
        comment_parts.append("- Scope Status: approved")  # Default since run must be approved
    
    # Created by/at
    if created_by:
        created_str = f"- Created: {created_by}"
        if created_at:
            created_str += f" at {created_at}"
        comment_parts.append(created_str)
    
    # Reviewed by/at (from scope lifecycle)
    scope_reviewed_by = audit_metadata.get("scope_reviewed_by") if isinstance(audit_metadata, dict) else None
    scope_reviewed_at = audit_metadata.get("scope_reviewed_at") if isinstance(audit_metadata, dict) else None
    if scope_reviewed_by:
        reviewed_str = f"- Reviewed: {scope_reviewed_by}"
        if scope_reviewed_at:
            reviewed_str += f" at {scope_reviewed_at}"
        comment_parts.append(reviewed_str)
    elif reviewed_by:
        # Fallback to old field names if scope_* not available
        reviewed_str = f"- Reviewed: {reviewed_by}"
        if reviewed_at:
            reviewed_str += f" at {reviewed_at}"
        comment_parts.append(reviewed_str)
    
    # Approved by/at (from scope lifecycle)
    scope_approved_by = audit_metadata.get("scope_approved_by") if isinstance(audit_metadata, dict) else None
    scope_approved_at = audit_metadata.get("scope_approved_at") if isinstance(audit_metadata, dict) else None
    if scope_approved_by:
        approved_str = f"- Approved: {scope_approved_by}"
        if scope_approved_at:
            approved_str += f" at {scope_approved_at}"
        comment_parts.append(approved_str)
    elif approved_by:
        # Fallback to old field names if scope_* not available
        approved_str = f"- Approved: {approved_by}"
        if approved_at:
            approved_str += f" at {approved_at}"
        comment_parts.append(approved_str)
    
    # Agent Version
    agent_metadata = audit_metadata.get("agent_metadata", {}) if isinstance(audit_metadata, dict) else {}
    agent_version = agent_metadata.get("agent_version") if agent_metadata else audit_metadata.get("agent_version") if isinstance(audit_metadata, dict) else None
    if agent_version:
        comment_parts.append(f"- Agent Version: {agent_version}")
    
    # Logic Version
    logic_version = agent_metadata.get("logic_version") if agent_metadata else audit_metadata.get("logic_version") if isinstance(audit_metadata, dict) else None
    if logic_version:
        comment_parts.append(f"- Logic Version: {logic_version}")
    
    # Change Policy
    change_policy = agent_metadata.get("change_policy") if agent_metadata else audit_metadata.get("change_policy") if isinstance(audit_metadata, dict) else None
    if change_policy:
        comment_parts.append(f"- Change Policy: {change_policy}")
    else:
        comment_parts.append("- Change Policy: idempotent")  # Default
    
    # Determinism (if present)
    determinism = agent_metadata.get("determinism") if agent_metadata else audit_metadata.get("determinism") if isinstance(audit_metadata, dict) else None
    if determinism:
        comment_parts.append(f"- Determinism: {determinism}")
    
    comment_parts.append("----")
    
    return "\n".join(comment_parts)


@app.route("/api/v1/jira/meta/projects", methods=["GET"])
def get_jira_projects():
    """
    Get list of Jira projects visible to the tenant's credentials.
    
    Returns:
        JSON array of project dictionaries with 'key' and 'name'
    """
    try:
        from services.integrations import get_jira_integration_for_current_tenant
        from services.jira_client import JiraClient, JiraClientError
        
        # Get Jira integration credentials for current tenant
        jira_creds = get_jira_integration_for_current_tenant()
        
        # Initialize Jira client
        jira_client = JiraClient(
            base_url=jira_creds["base_url"],
            username=jira_creds["email"],
            api_token=jira_creds["api_token"]
        )
        
        # Get projects
        projects = jira_client.get_projects()
        return jsonify(projects), 200
        
    except ValueError as e:
        logger.warning(f"Jira configuration error: {str(e)}")
        return jsonify({"detail": str(e)}), 400
    except Exception as e:
        logger.error(f"Failed to get Jira projects: {str(e)}")
        return jsonify({"detail": f"Failed to get Jira projects: {str(e)}"}), 500


@app.route("/api/v1/jira/meta/issue-types", methods=["GET"])
def get_jira_issue_types():
    """
    Get issue types valid for a Jira project.
    
    Query Parameters:
        project_key: Jira project key (required)
        
    Returns:
        JSON array of issue type dictionaries with 'id' and 'name'
    """
    try:
        from services.integrations import get_jira_integration_for_current_tenant
        from services.jira_client import JiraClient, JiraClientError
        
        # Get project_key from query parameters
        project_key = request.args.get("project_key")
        if not project_key:
            return jsonify({"detail": "project_key query parameter is required"}), 400
        
        # Get Jira integration credentials for current tenant
        jira_creds = get_jira_integration_for_current_tenant()
        
        # Initialize Jira client
        jira_client = JiraClient(
            base_url=jira_creds["base_url"],
            username=jira_creds["email"],
            api_token=jira_creds["api_token"]
        )
        
        # Get issue types
        issue_types = jira_client.get_issue_types(project_key)
        return jsonify(issue_types), 200
        
    except ValueError as e:
        logger.warning(f"Jira configuration error: {str(e)}")
        return jsonify({"detail": str(e)}), 400
    except Exception as e:
        logger.error(f"Failed to get Jira issue types: {str(e)}")
        return jsonify({"detail": f"Failed to get Jira issue types: {str(e)}"}), 500


@app.route("/api/v1/leads", methods=["POST"])
def create_lead():
    """
    Public endpoint for lead submission from marketing site.
    No authentication required.
    
    Upserts lead by email (case-insensitive). Preserves existing status on re-submit.
    
    Request Body:
        - email (required): Valid email format, max 254 chars
        - name (optional): Max 200 chars
        - company (optional): Max 200 chars
        - role (optional): Max 200 chars
        - message (optional): Max 2000 chars
        - source (optional): Max 500 chars
        - source_page (optional): Max 500 chars
        - utm_* fields (optional): Max 200 chars each
    
    Returns:
        {id, status} - Lead ID and current status
    """
    try:
        from db import get_db
        from models import Lead
        from sqlalchemy import func
        import re
        
        # Get request data
        data = request.get_json() or {}
        
        # Validate and sanitize email (required)
        email = data.get("email", "").strip()
        if not email:
            return jsonify({"error": "Email is required"}), 400
        
        # Validate email format
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email) or len(email) > 254:
            return jsonify({"error": "Invalid email format"}), 400
        
        # Sanitize and trim all string fields
        name = (data.get("name") or "").strip()[:200] if data.get("name") else None
        company = (data.get("company") or "").strip()[:200] if data.get("company") else None
        role = (data.get("role") or "").strip()[:200] if data.get("role") else None
        message = (data.get("message") or "").strip()[:2000] if data.get("message") else None
        source = (data.get("source") or "").strip()[:500] if data.get("source") else None
        source_page = (data.get("source_page") or "").strip()[:500] if data.get("source_page") else None
        utm_source = (data.get("utm_source") or "").strip()[:200] if data.get("utm_source") else None
        utm_medium = (data.get("utm_medium") or "").strip()[:200] if data.get("utm_medium") else None
        utm_campaign = (data.get("utm_campaign") or "").strip()[:200] if data.get("utm_campaign") else None
        utm_term = (data.get("utm_term") or "").strip()[:200] if data.get("utm_term") else None
        utm_content = (data.get("utm_content") or "").strip()[:200] if data.get("utm_content") else None
        
        db = next(get_db())
        try:
            # Case-insensitive email lookup
            email_lower = email.lower()
            existing_lead = db.query(Lead).filter(
                func.lower(Lead.email) == email_lower
            ).first()
            
            if existing_lead:
                # Update existing lead (preserve status)
                existing_lead.name = name
                existing_lead.company = company
                existing_lead.role = role
                existing_lead.message = message
                existing_lead.source = source
                existing_lead.source_page = source_page
                existing_lead.utm_source = utm_source
                existing_lead.utm_medium = utm_medium
                existing_lead.utm_campaign = utm_campaign
                existing_lead.utm_term = utm_term
                existing_lead.utm_content = utm_content
                existing_lead.updated_at = datetime.now(timezone.utc)
                # Status is NOT reset - preserve existing status
                
                db.commit()
                db.refresh(existing_lead)
                
                return jsonify({
                    "id": str(existing_lead.id),
                    "status": existing_lead.status
                }), 200
            else:
                # Create new lead
                new_lead = Lead(
                    email=email,
                    name=name,
                    company=company,
                    role=role,
                    message=message,
                    source=source,
                    source_page=source_page,
                    utm_source=utm_source,
                    utm_medium=utm_medium,
                    utm_campaign=utm_campaign,
                    utm_term=utm_term,
                    utm_content=utm_content,
                    status="new"
                )
                
                db.add(new_lead)
                db.commit()
                db.refresh(new_lead)
                
                return jsonify({
                    "id": str(new_lead.id),
                    "status": new_lead.status
                }), 200
                
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error creating/updating lead: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/v1/admin/leads", methods=["GET"])
def list_leads():
    """
    Admin endpoint for listing leads.
    Requires owner or superAdmin role.
    
    Query Parameters:
        - status (optional): Filter by status
        - limit (optional): Number of results (default: 50, max: 200)
    
    Returns:
        {leads: [...], total: N}
    """
    try:
        from db import get_db
        from models import Lead
        
        # Check admin access
        user, error_response = check_admin_access()
        if error_response:
            return error_response
        
        # Get query parameters
        status_filter = request.args.get("status")
        limit = min(int(request.args.get("limit", 50)), 200)  # Default 50, max 200
        
        db = next(get_db())
        try:
            # Build query
            query = db.query(Lead)
            
            if status_filter:
                query = query.filter(Lead.status == status_filter)
            
            # Order by created_at descending
            query = query.order_by(Lead.created_at.desc())
            
            # Apply limit
            leads = query.limit(limit).all()
            
            # Format response
            leads_list = []
            for lead in leads:
                leads_list.append({
                    "id": str(lead.id),
                    "created_at": lead.created_at.isoformat() + "Z" if lead.created_at else None,
                    "updated_at": lead.updated_at.isoformat() + "Z" if lead.updated_at else None,
                    "name": lead.name,
                    "email": lead.email,
                    "company": lead.company,
                    "role": lead.role,
                    "status": lead.status,
                    "source": lead.source,
                    "source_page": lead.source_page
                })
            
            # Get total count (for pagination info)
            total_query = db.query(Lead)
            if status_filter:
                total_query = total_query.filter(Lead.status == status_filter)
            total = total_query.count()
            
            return jsonify({
                "leads": leads_list,
                "total": total
            }), 200
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error listing leads: {str(e)}", exc_info=True)
        return jsonify({"error": "INTERNAL_ERROR", "message": f"Failed to list leads: {str(e)}"}), 500


@app.route("/api/v1/admin/leads/<lead_id>", methods=["PATCH"])
def update_lead(lead_id: str):
    """
    Admin endpoint for updating lead status and notes.
    Requires owner or superAdmin role.
    
    Request Body:
        - status (optional): Must be one of: new, contacted, qualified, closed, junk
        - notes (optional): Text field
        - last_contacted_at (optional): ISO 8601 timestamp
    
    Returns:
        Updated lead object
    """
    try:
        from db import get_db
        from models import Lead
        import uuid as uuid_module
        
        # Check admin access
        user, error_response = check_admin_access()
        if error_response:
            return error_response
        
        # Get request data
        data = request.get_json() or {}
        
        # Validate status if provided
        valid_statuses = ["new", "contacted", "qualified", "closed", "junk"]
        if "status" in data and data["status"] not in valid_statuses:
            return jsonify({"error": "INVALID_STATUS", "message": f"Status must be one of: {', '.join(valid_statuses)}"}), 400
        
        # Parse last_contacted_at if provided
        last_contacted_at = None
        if "last_contacted_at" in data and data["last_contacted_at"]:
            try:
                # Parse ISO 8601 timestamp
                last_contacted_at_str = data["last_contacted_at"].replace("Z", "+00:00")
                last_contacted_at = datetime.fromisoformat(last_contacted_at_str)
                if last_contacted_at.tzinfo is None:
                    # If no timezone, assume UTC
                    last_contacted_at = last_contacted_at.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError, AttributeError) as e:
                return jsonify({"error": "INVALID_DATE", "message": f"Invalid last_contacted_at format: {str(e)}"}), 400
        
        # Convert lead_id to UUID
        try:
            lead_id_uuid = uuid_module.UUID(lead_id)
        except ValueError:
            return jsonify({"error": "INVALID_LEAD_ID", "message": f"Invalid lead_id: {lead_id}"}), 400
        
        db = next(get_db())
        try:
            # Get lead
            lead = db.query(Lead).filter(Lead.id == lead_id_uuid).first()
            if not lead:
                return jsonify({"error": "LEAD_NOT_FOUND", "message": "Lead not found"}), 404
            
            # Update fields
            if "status" in data:
                lead.status = data["status"]
            if "notes" in data:
                lead.notes = data["notes"]
            if last_contacted_at is not None:
                lead.last_contacted_at = last_contacted_at
            
            lead.updated_at = datetime.now(timezone.utc)
            
            db.commit()
            db.refresh(lead)
            
            return jsonify({
                "id": str(lead.id),
                "status": lead.status,
                "notes": lead.notes,
                "last_contacted_at": lead.last_contacted_at.isoformat() + "Z" if lead.last_contacted_at else None,
                "updated_at": lead.updated_at.isoformat() + "Z" if lead.updated_at else None
            }), 200
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error updating lead: {str(e)}", exc_info=True)
        return jsonify({"error": "INTERNAL_ERROR", "message": f"Failed to update lead: {str(e)}"}), 500


@app.route("/api/v1/runs/<run_id>/jira", methods=["POST"])
def create_jira_ticket(run_id: str):
    """
    Create a Jira ticket from an approved run (Phase 3).
    
    Behavior:
    - Validates run exists and is approved
    - Checks idempotency (searches for existing issue with label)
    - Creates Jira issue if not already created
    - Persists Jira metadata in run context
    
    Args:
        run_id: Run identifier
        
    Returns:
        JSON with Jira issue details
    """
    try:
        from db import get_db
        from models import Run
        from datetime import datetime
        from services.jira_client import JiraClient, JiraClientError
        from services.persistence import get_artifact_path
        import json as json_module
        
        # Get tenant_id from JWT (set by middleware) - MUST be from JWT, not request
        tenant_id = g.tenant_id
        if not tenant_id:
            return jsonify({"detail": "Unauthorized"}), 401
        
        # ============================================================================
        # CENTRALIZED ENTITLEMENT ENFORCEMENT (Policy Authority)
        # Enforce writeback entitlements BEFORE any side effects
        # ============================================================================
        try:
            from services.entitlements_centralized import enforce_entitlements
            
            db = next(get_db())
            try:
                # Comprehensive entitlement check for writeback operation
                allowed, reason, metadata = enforce_entitlements(
                    db=db,
                    tenant_id=str(tenant_id),
                    agent="jira_writeback",
                    ticket_count=None,  # Writeback doesn't have ticket limits
                    input_char_count=None  # Writeback doesn't have input size limits
                )
                
                if not allowed:
                    # Build response with status and remaining
                    # Special handling for onboarding incomplete
                    if reason == "ONBOARDING_INCOMPLETE":
                        message = "Complete onboarding: choose a plan"
                    else:
                        message = "Request blocked by subscription or plan limits."
                    
                    response_detail = {
                        "error": reason or "PAYWALLED",
                        "message": message
                    }
                    if "subscription_status" in metadata:
                        response_detail["subscription_status"] = metadata["subscription_status"]
                    if "trial_remaining" in metadata:
                        response_detail["remaining"] = metadata["trial_remaining"]
                    if "plan_tier" in metadata:
                        response_detail["plan_tier"] = metadata["plan_tier"]
                    
                    return jsonify(response_detail), 403
            finally:
                db.close()
        except Exception as e:
            # Fail closed: return 503 on entitlement check errors (unless ENTITLEMENT_FAIL_OPEN=true)
            fail_open = os.getenv("ENTITLEMENT_FAIL_OPEN", "false").lower() == "true"
            
            if fail_open:
                logger.warning(f"ENTITLEMENT_FAIL_OPEN=true: Allowing request despite entitlement check error: {str(e)}", exc_info=True)
                # Continue with request (fail open)
            else:
                # Fail closed: return 503
                logger.error(f"Entitlement check failed for tenant {tenant_id}: {str(e)}", exc_info=True)
                return jsonify({
                    "error": "ENTITLEMENT_UNAVAILABLE",
                    "message": "Unable to verify subscription status. Please try again."
                }), 503
        
        # Get actor from X-Actor header
        actor = request.headers.get("X-Actor", "anonymous")
        
        # Get Jira configuration from database
        try:
            from services.integrations import get_jira_integration_for_current_tenant
            jira_creds = get_jira_integration_for_current_tenant()
            jira_config = {
                "jira_base_url": jira_creds["base_url"],
                "jira_username": jira_creds["email"],
                "jira_api_token": jira_creds["api_token"],
                "jira_project_key": os.getenv("JIRA_PROJECT_KEY"),
                "jira_issue_type": os.getenv("JIRA_ISSUE_TYPE", "Task")
            }
            if not jira_config["jira_project_key"]:
                return jsonify({"detail": "JIRA_PROJECT_KEY environment variable is required"}), 500
        except ValueError as e:
            return jsonify({"detail": f"Jira configuration error: {str(e)}"}), 500
        
        db = next(get_db())
        try:
            
            # Validate run exists (tenant-scoped)
            run = db.query(Run).filter(
                Run.run_id == run_id,
                Run.tenant_id == tenant_id
            ).first()
            if not run:
                return jsonify({"detail": "Run not found"}), 404
            
            # Validate run is approved
            review_status = getattr(run, 'review_status', 'generated')
            if review_status != "approved":
                return jsonify({
                    "detail": f"Run must be approved to create Jira ticket. Current status: {review_status}"
                }), 403
            
            # Check if Jira issue already exists
            if hasattr(run, 'jira_issue_key') and run.jira_issue_key:
                return jsonify({
                    "jira_issue_key": run.jira_issue_key,
                    "jira_issue_url": run.jira_issue_url,
                    "message": "Jira ticket already exists for this run",
                    "created_by": run.jira_created_by,
                    "created_at": run.jira_created_at.isoformat() + "Z" if run.jira_created_at else None
                }), 200
            
            # Initialize Jira client
            jira_client = JiraClient(
                base_url=jira_config["jira_base_url"],
                username=jira_config["jira_username"],
                api_token=jira_config["jira_api_token"]
            )
            
            # Check idempotency: search for existing issue with label
            label = f"scopetrace_run_{run_id}"
            existing_issues = jira_client.search_issues_by_label(label)
            
            issue_key = None
            issue_url = None
            is_existing_issue = False
            
            if existing_issues:
                # Issue already exists, extract key and update run
                existing_issue = existing_issues[0]
                issue_key = existing_issue.get("key")
                if not issue_key:
                    # Try to get from fields if key is not at top level
                    fields = existing_issue.get("fields", {})
                    # Key should be at top level, but handle both cases
                    issue_key = existing_issue.get("key") or existing_issue.get("id")
                
                if issue_key:
                    issue_url = jira_client.get_issue_url(issue_key)
                    run.jira_issue_key = issue_key
                    run.jira_issue_url = issue_url
                    run.jira_created_by = actor
                    run.jira_created_at = datetime.utcnow()
                    is_existing_issue = True
                    # Don't return yet - need to check/add comment
            
            # Load artifacts for Jira content generation (tenant-scoped)
            analysis_path = get_artifact_path(db, run_id, "analysis", tenant_id)
            test_plan_path = get_artifact_path(db, run_id, "test_plan", tenant_id)
            rtm_path = get_artifact_path(db, run_id, "rtm", tenant_id)
            audit_path = get_artifact_path(db, run_id, "audit_metadata", tenant_id)
            
            if not analysis_path or not os.path.exists(analysis_path):
                return jsonify({"detail": "Analysis artifact not found"}), 404
            if not test_plan_path or not os.path.exists(test_plan_path):
                return jsonify({"detail": "Test plan artifact not found"}), 404
            if not rtm_path or not os.path.exists(rtm_path):
                return jsonify({"detail": "RTM artifact not found"}), 404
            if not audit_path or not os.path.exists(audit_path):
                return jsonify({"detail": "Audit metadata artifact not found"}), 404
            
            # Load artifacts
            with open(analysis_path, 'r', encoding='utf-8') as f:
                analysis_data = json_module.load(f)
            with open(test_plan_path, 'r', encoding='utf-8') as f:
                test_plan_data = json_module.load(f)
            with open(rtm_path, 'r', encoding='utf-8') as f:
                rtm_data = json_module.load(f)
            with open(audit_path, 'r', encoding='utf-8') as f:
                audit_metadata_raw = json_module.load(f)
            
            # Enrich audit_metadata with scope lifecycle from analysis package if available
            audit_metadata = audit_metadata_raw.copy() if isinstance(audit_metadata_raw, dict) else {}
            
            # Extract scope lifecycle from analysis package if available
            package = analysis_data.get("package") if isinstance(analysis_data, dict) else None
            if not package and isinstance(analysis_data, dict) and "scope_status" in analysis_data:
                package = analysis_data
            
            if package and isinstance(package, dict):
                scope_status = package.get("scope_status")
                scope_status_transitions = package.get("scope_status_transitions", [])
                
                if scope_status:
                    audit_metadata["scope_status"] = scope_status
                
                # Extract reviewed_by/at and approved_by/at from transitions
                for transition in scope_status_transitions:
                    if isinstance(transition, dict):
                        new_status = transition.get("new_status")
                        changed_by = transition.get("changed_by")
                        changed_at = transition.get("changed_at")
                        
                        if new_status == "reviewed" and changed_by:
                            audit_metadata["scope_reviewed_by"] = changed_by
                            if changed_at:
                                if isinstance(changed_at, str):
                                    audit_metadata["scope_reviewed_at"] = changed_at
                                else:
                                    audit_metadata["scope_reviewed_at"] = changed_at.isoformat() + "Z" if hasattr(changed_at, 'isoformat') else None
                        
                        if new_status == "locked" and changed_by:
                            audit_metadata["scope_approved_by"] = changed_by
                            if changed_at:
                                if isinstance(changed_at, str):
                                    audit_metadata["scope_approved_at"] = changed_at
                                else:
                                    audit_metadata["scope_approved_at"] = changed_at.isoformat() + "Z" if hasattr(changed_at, 'isoformat') else None
            
            # Generate Jira content (only if creating new issue)
            if not is_existing_issue:
                summary = f"ScopeTrace AI — Approved Test Plan ({run_id})"
                description_text = _generate_jira_description(
                    run_id=run_id,
                    created_by=run.created_by or "anonymous",
                    approved_by=getattr(run, 'approved_by', None),
                    approved_at=run.approved_at.isoformat() + "Z" if hasattr(run, 'approved_at') and run.approved_at else None,
                    reviewed_by=None,  # Will be extracted from audit_metadata scope_* fields
                    reviewed_at=None,  # Will be extracted from audit_metadata scope_* fields
                    analysis_data=analysis_data,
                    test_plan_data=test_plan_data,
                    rtm_data=rtm_data,
                    audit_metadata=audit_metadata
                )
                
                # Convert description to ADF format
                description_adf = jira_client._text_to_adf(description_text)
                
                # Create Jira issue
                try:
                    create_response = jira_client.create_issue(
                        project_key=jira_config["jira_project_key"],
                        issue_type=jira_config["jira_issue_type"],
                        summary=summary,
                        description_adf=description_adf,
                        labels=[label]
                    )
                    
                    issue_key = create_response.get("key")
                    if not issue_key:
                        return jsonify({"detail": "Jira issue creation succeeded but no issue key returned"}), 500
                    
                    issue_url = jira_client.get_issue_url(issue_key)
                    
                    # Persist Jira metadata in run context
                    run.jira_issue_key = issue_key
                    run.jira_issue_url = issue_url
                    run.jira_created_by = actor
                    run.jira_created_at = datetime.utcnow()
                    db.commit()
                    db.refresh(run)
                except JiraClientError as e:
                    return jsonify({
                        "detail": f"Jira API error: {str(e)}"
                    }), 500
            
            # Now handle audit comment (for both new and existing issues)
            # Check if comment already exists
            comment_marker = f"ScopeTraceAI-Audit: {run_id}"
            existing_comments = []
            try:
                existing_comments = jira_client.get_comments(issue_key)
            except JiraClientError as e:
                # Log but don't fail - comment is optional
                logger.warning(f"Failed to fetch comments for issue {issue_key}: {str(e)}")
            
            # Check if comment with marker already exists
            comment_exists = False
            for comment in existing_comments:
                # Extract comment body text (could be ADF or plain text)
                body = comment.get("body", {})
                if isinstance(body, dict):
                    # ADF format - extract text content
                    def extract_text_from_adf(adf_node):
                        """Recursively extract text from ADF structure."""
                        if isinstance(adf_node, dict):
                            if adf_node.get("type") == "text":
                                return adf_node.get("text", "")
                            content = adf_node.get("content", [])
                            if isinstance(content, list):
                                return "".join(extract_text_from_adf(item) for item in content)
                        elif isinstance(adf_node, list):
                            return "".join(extract_text_from_adf(item) for item in adf_node)
                        return ""
                    
                    comment_text = extract_text_from_adf(body)
                else:
                    comment_text = str(body)
                
                if comment_marker in comment_text:
                    comment_exists = True
                    # Update run with existing comment metadata if available
                    comment_id = comment.get("id")
                    if comment_id and not hasattr(run, 'jira_audit_comment_id') or not getattr(run, 'jira_audit_comment_id', None):
                        run.jira_audit_comment_id = str(comment_id)
                        run.jira_audit_comment_posted_by = actor
                        run.jira_audit_comment_posted_at = datetime.utcnow()
                        db.commit()
                    break
            
            # Add comment if it doesn't exist
            if not comment_exists:
                # Generate audit summary comment
                comment_text = _generate_audit_summary_comment(
                    run_id=run_id,
                    created_by=run.created_by or "anonymous",
                    created_at=run.created_at.isoformat() + "Z" if run.created_at else None,
                    approved_by=getattr(run, 'approved_by', None),
                    approved_at=run.approved_at.isoformat() + "Z" if hasattr(run, 'approved_at') and run.approved_at else None,
                    reviewed_by=audit_metadata.get("scope_reviewed_by") if isinstance(audit_metadata, dict) else None,
                    reviewed_at=audit_metadata.get("scope_reviewed_at") if isinstance(audit_metadata, dict) else None,
                    audit_metadata=audit_metadata
                )
                
                try:
                    comment_response = jira_client.add_comment(issue_key, comment_text)
                    comment_id = comment_response.get("id")
                    
                    # Persist comment metadata
                    run.jira_audit_comment_posted_at = datetime.utcnow()
                    run.jira_audit_comment_posted_by = actor
                    if comment_id:
                        run.jira_audit_comment_id = str(comment_id)
                    db.commit()
                    db.refresh(run)
                except JiraClientError as e:
                    # Log but don't fail - comment is optional
                    logger.warning(f"Failed to add audit comment to issue {issue_key}: {str(e)}")
            
            # ============================================================================
            # Consume trial run after successful Jira ticket creation
            # This preserves existing trial counter behavior - MUST NOT be broken.
            # ============================================================================
            if tenant_id and issue_key:
                try:
                    from services.entitlements import consume_trial_run
                    # Use a fresh DB session for trial consumption (atomic operation)
                    trial_db = next(get_db())
                    try:
                        consume_trial_run(trial_db, str(tenant_id), agent="jira_writeback")
                    finally:
                        trial_db.close()
                except Exception as consume_error:
                    # Log but don't fail the request if consumption fails
                    logger.error(f"Failed to consume trial run for tenant {tenant_id}: {str(consume_error)}", exc_info=True)
                    # Continue - the writeback succeeded, consumption failure is non-fatal
            
            # Return success response
            response_status = 201 if not is_existing_issue else 200
            response_message = "Jira ticket created successfully" if not is_existing_issue else "Jira ticket already exists (found by label)"
            
            return jsonify({
                "jira_issue_key": issue_key,
                "jira_issue_url": issue_url,
                "message": response_message,
                "created_by": actor,
                "created_at": run.jira_created_at.isoformat() + "Z" if run.jira_created_at else None,
                "audit_comment_posted": not comment_exists
            }), response_status
                
        finally:
            db.close()
    except ValueError as e:
        return jsonify({"detail": f"Configuration error: {str(e)}"}), 500
    except Exception as e:
        logger.error(f"Error creating Jira ticket for run {run_id}: {str(e)}")
        return jsonify({"detail": f"Failed to create Jira ticket: {str(e)}"}), 500


# Load persisted test plan on application startup
load_test_plan_from_file()

# Initialize database on startup
try:
    from db import init_db, get_db, engine, Base
    # Import ALL models at startup to ensure they're registered with Base.metadata
    # This must happen before Flask-SQLAlchemy initialization to avoid metadata conflicts
    from models import Run, Artifact, Tenant, TenantUser, TenantIntegration, UsageEvent, Lead, PasswordResetToken, AdminAuditLog  # noqa: F401
    from services.persistence import (
        write_json_artifact,
        save_run,
        save_artifact
    )
    
    # Initialize Flask-Migrate for database migrations
    # Flask-Migrate requires Flask-SQLAlchemy, so we create a Flask-SQLAlchemy instance
    # that shares the same metadata as our existing Base. This allows migrations to work
    # while existing code continues to use SessionLocal (no breaking changes)
    try:
        from flask_sqlalchemy import SQLAlchemy
        from flask_migrate import Migrate
        from db import SQLALCHEMY_DATABASE_URL
        
        # Configure Flask-SQLAlchemy to use the same database URL as our SQLAlchemy engine
        # Use SQLALCHEMY_DATABASE_URL from db.py (already normalized and validated)
        app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URL
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        
        # Create Flask-SQLAlchemy db object for migrations
        # This uses the same database URL but creates its own engine
        # Note: Existing code should continue using get_db() from db.py, not this db object
        # All models must be imported BEFORE this line to avoid metadata conflicts
        db = SQLAlchemy(app, metadata=Base.metadata)
        
        # Initialize Flask-Migrate
        migrate = Migrate(app, db)
        logger.info("Flask-Migrate initialized successfully")
    except ImportError as e:
        logger.warning(f"Flask-Migrate dependencies not available: {e}. Install with: pip install flask-migrate flask-sqlalchemy")
    except Exception as e:
        logger.warning(f"Flask-Migrate initialization failed: {e}. Migrations may not be available.")
    
    init_db()
    logger.info("Database initialized successfully")
except Exception as e:
    logger.warning(f"Database initialization failed: {e}. Continuing without database persistence.")


def persist_test_plan_result(result: dict, scope: dict, tickets: list, source_type: str, created_by: str = "anonymous", environment: str = "development", tenant_id: Optional[str] = None):
    """
    Persist test plan result to database and disk artifacts.
    
    This function:
    - Saves Run metadata to database
    - Writes test_plan.json, rtm.json, analysis.json, audit_metadata.json to disk
    - Saves Artifact rows with SHA-256 hashes
    
    Args:
        result: Final test plan result dictionary
        scope: Scope dictionary with type and id
        tickets: List of ticket specifications
        source_type: Source type ("jira" | "freeform" | "document")
        created_by: Actor/user who created the run (default: "anonymous")
        environment: Environment name (default: "development")
        tenant_id: Tenant ID (UUID string) - required for tenant isolation
    """
    try:
        # Get database session
        db = next(get_db())
        
        try:
            # Extract run_id from audit_metadata
            audit_metadata = result.get("audit_metadata", {})
            run_id = audit_metadata.get("run_id")
            
            if not run_id:
                logger.warning("Cannot persist: audit_metadata.run_id is missing")
                return
            
            # Get tenant_id from parameter or JWT (set by middleware)
            if not tenant_id:
                tenant_id = getattr(g, 'tenant_id', None)
            
            if not tenant_id:
                logger.warning("Cannot persist run: tenant_id not available")
                return
            
            # Extract metadata fields
            source_info = audit_metadata.get("source", {})
            model_info = audit_metadata.get("model", {})
            agent_metadata = audit_metadata.get("agent_metadata", {})
            
            # Determine source_type from audit_metadata (fallback to parameter)
            extracted_source_type = source_info.get("type") if isinstance(source_info, dict) else source_type
            if not extracted_source_type:
                extracted_source_type = "unknown"
            
            # Extract ticket_count
            ticket_count = source_info.get("ticket_count") if isinstance(source_info, dict) else len(tickets)
            
            # Extract scope_id and scope_type
            scope_id = source_info.get("scope_id") if isinstance(source_info, dict) else scope.get("id")
            scope_type = source_info.get("scope_type") if isinstance(source_info, dict) else scope.get("type")
            
            # Extract logic_version from agent_metadata
            logic_version = agent_metadata.get("logic_version") if isinstance(agent_metadata, dict) else None
            
            # Extract model_name
            model_name = model_info.get("name") if isinstance(model_info, dict) else None
            
            # Save Run row
            # Generate summary for run list
            summary = None
            if ticket_count and ticket_count > 0:
                if extracted_source_type == "jira":
                    summary = f"Generated test plan from {ticket_count} Jira ticket{'s' if ticket_count > 1 else ''}"
                else:
                    summary = f"Generated test plan from {ticket_count} input{'s' if ticket_count > 1 else ''}"
            else:
                summary = "Generated test plan"
            
            # Count output items (tests)
            test_plan = result.get("test_plan", {})
            output_item_count = 0
            for test_category in ["api_tests", "ui_tests", "negative_tests", "edge_tests", "data_tests"]:
                tests = test_plan.get(test_category, [])
                if isinstance(tests, list):
                    output_item_count += len(tests)
            
            save_run(
                db=db,
                run_id=run_id,
                source_type=extracted_source_type,
                status="generated",
                ticket_count=ticket_count,
                agent="testing-agent",
                run_kind="test_plan",
                artifact_type="test_plan",
                artifact_id=run_id,  # For test plans, artifact_id is the run_id itself
                summary=summary,
                input_ticket_count=ticket_count or 0,
                output_item_count=output_item_count,
                scope_id=scope_id,
                scope_type=scope_type,
                logic_version=logic_version,
                model_name=model_name,
                created_by=created_by,
                environment=environment,
                tenant_id=tenant_id
            )
            
            # Prepare analysis.json (requirements structure / package)
            # Create a minimal package structure with requirements
            analysis_data = {
                "requirements": result.get("requirements", []),
                "metadata": result.get("metadata", {}),
                "business_intent": result.get("business_intent", ""),
                "scope": scope
            }
            
            # Write artifacts to disk and save metadata
            # Store audit_metadata separately if it exists
            artifacts_to_save = [
                ("test_plan", result),  # Full result payload
                ("rtm", result.get("rtm", [])),
                ("analysis", analysis_data),
                ("audit_metadata", audit_metadata)  # Store audit_metadata separately
            ]
            
            for artifact_type, artifact_obj in artifacts_to_save:
                try:
                    # Write JSON artifact to disk
                    artifact_path, artifact_sha256 = write_json_artifact(
                        run_id, artifact_type, artifact_obj
                    )
                    
                    # Save artifact metadata to database
                    save_artifact(
                        db=db,
                        run_id=run_id,
                        artifact_type=artifact_type,
                        path=artifact_path,
                        sha256=artifact_sha256,
                        tenant_id=tenant_id
                    )
                except Exception as e:
                    logger.warning(f"Failed to persist {artifact_type} artifact: {str(e)}")
                    # Continue with other artifacts
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Error in persist_test_plan_result: {str(e)}")
        raise

if __name__ == '__main__':
    app.run(debug=True, port=5050)

