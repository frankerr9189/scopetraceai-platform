"""
Jira rewrite API endpoints for dry-run and execute operations.
"""
from typing import Dict, Any, Optional, List, Tuple
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
import hashlib
import time
import json
import uuid
import os
from datetime import datetime

from services.jira_client import JiraClient, JiraClientError
from services.audit_logger import AuditLogger
from src.jira_writeback_agent.config import JiraWriteBackConfig
from src.jira_writeback_agent.version import __version__


def _get_allowed_origins() -> List[str]:
    """
    Get list of allowed CORS origins (same logic as main.py).
    Uses base list + CORS_ALLOWED_ORIGINS env var.
    """
    base_origins = [
        "http://localhost:5173",
        "http://localhost:5137",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5137",
        "http://127.0.0.1:3000",
        "https://app.scopetraceai.com",
        "https://scopetraceai-platform.vercel.app",
        "https://scopetraceai.com",
        "https://www.scopetraceai.com",
    ]
    
    # Add additional origins from env var
    production_origins = os.getenv("CORS_ALLOWED_ORIGINS", "").strip()
    if production_origins:
        for origin in production_origins.split(","):
            origin = origin.strip()
            if origin and origin not in base_origins:
                base_origins.append(origin)
    
    return base_origins


def _get_cors_headers(request: Request) -> Dict[str, str]:
    """
    Get CORS headers for error responses.
    Only sets Access-Control-Allow-Origin if origin is in allowed list.
    No hardcoded fallback.
    """
    origin = request.headers.get("Origin")
    allowed = _get_allowed_origins()
    
    headers = {
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "*",
        "Access-Control-Allow-Headers": "*",
    }
    
    if origin and origin in allowed:
        headers["Access-Control-Allow-Origin"] = origin
    
    return headers

# Import local jira-writeback-agent entitlements at module level to ensure we use the correct module
# This prevents accidentally importing from testing agent backend's entitlements
_current_file = os.path.abspath(__file__)
_jira_agent_dir = os.path.dirname(os.path.dirname(_current_file))
_entitlements_path = os.path.join(_jira_agent_dir, "services", "entitlements.py")
if os.path.exists(_entitlements_path):
    import importlib.util
    _spec = importlib.util.spec_from_file_location("jira_writeback_entitlements", _entitlements_path)
    _jira_entitlements_module = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_jira_entitlements_module)
    _local_check_entitlement = _jira_entitlements_module.check_entitlement
    _local_consume_trial_run = _jira_entitlements_module.consume_trial_run
else:
    # Fallback to regular import if file not found (shouldn't happen)
    from services.entitlements import check_entitlement as _local_check_entitlement, consume_trial_run as _local_consume_trial_run


router = APIRouter()


def _extract_tenant_user_from_jwt(request: Request) -> Tuple[str, Optional[str]]:
    """
    Extract tenant_id and user_id from JWT token in Authorization header.
    
    Args:
        request: FastAPI Request object
        
    Returns:
        Tuple of (tenant_id, user_id). tenant_id is always a string (required).
        user_id may be None (optional).
        
    Raises:
        HTTPException(401): If:
            - Authorization header is missing
            - Authorization header does not contain Bearer token
            - JWT token is invalid/expired
            - JWT token is valid but tenant_id is missing in claims
    """
    import os
    import jwt
    import logging
    
    logger = logging.getLogger(__name__)
    
    # Check for Authorization header
    auth_header = request.headers.get("Authorization", "")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Authorization header is required")
    
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization header must contain Bearer token")
    
    token = auth_header.replace("Bearer ", "").strip()
    if not token:
        raise HTTPException(status_code=401, detail="JWT token is required")
    
    jwt_secret = os.getenv("JWT_SECRET")
    if not jwt_secret:
        logger.error("JWT_SECRET not set, cannot decode JWT")
        raise HTTPException(status_code=401, detail="JWT authentication not configured")
    
    try:
        payload = jwt.decode(token, jwt_secret, algorithms=["HS256"])
        tenant_id = payload.get("tenant_id")
        user_id = payload.get("sub")  # user_id is in 'sub' claim
        
        # Enforce tenant_id requirement
        if not tenant_id:
            raise HTTPException(status_code=401, detail="JWT token missing tenant_id claim")
        
        return str(tenant_id), str(user_id) if user_id else None
    except HTTPException:
        # Re-raise HTTP exceptions (our 401 for missing tenant_id)
        raise
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="JWT token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid JWT token: {str(e)}")
    except Exception as e:
        logger.error(f"JWT decode failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=401, detail="JWT authentication failed")


def _record_usage_event(
    tenant_id: str,
    user_id: Optional[str],
    agent: str,
    source: str,
    jira_ticket_count: int,
    input_char_count: int,
    success: bool,
    error_code: Optional[str],
    run_id: str,
    duration_ms: int
) -> None:
    """
    Record usage event to PostgreSQL usage_events table.
    
    This function:
    - Uses already-loaded environment variables (dotenv loaded at startup)
    - Verifies DATABASE_URL is PostgreSQL
    - Records usage event
    - Never raises exceptions (logs warnings only)
    
    Args:
        tenant_id: Tenant ID (required)
        user_id: User ID (optional)
        agent: Agent identifier
        source: Source type
        jira_ticket_count: Number of Jira tickets created
        input_char_count: Input character count
        success: Whether operation succeeded
        error_code: Error code if failed
        run_id: Run ID (UUID string)
        duration_ms: Duration in milliseconds
    """
    import os
    import sys
    import logging
    
    logger = logging.getLogger(__name__)
    
    # Ensure logger is configured (set level if not already set)
    if not logger.handlers:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        logger = logging.getLogger(__name__)
    
    # Set logger level to INFO to ensure messages are shown
    logger.setLevel(logging.INFO)
    
    # Use print as backup to ensure we see the message
    print(f"[USAGE_TRACKING] Attempting to record usage event: tenant_id={tenant_id}, agent={agent}, source={source}, success={success}")
    logger.info(f"Attempting to record usage event: tenant_id={tenant_id}, agent={agent}, source={source}, success={success}")
    
    try:
        # Calculate path to testing agent backend
        current_file = os.path.abspath(__file__)
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
        backend_path = os.path.join(project_root, "ai-testing-agent", "backend")
        
        if not os.path.exists(backend_path):
            logger.error(f"Testing agent backend not found at {backend_path}, skipping usage tracking")
            return
        
        # Verify DATABASE_URL is PostgreSQL (env already loaded at startup)
        db_url = os.getenv("DATABASE_URL")
        if not db_url:
            logger.error("DATABASE_URL not set, skipping usage tracking")
            return
        
        if not (db_url.startswith("postgresql://") or db_url.startswith("postgres://")):
            logger.error(f"DATABASE_URL is not PostgreSQL: {db_url[:50]}..., skipping usage tracking")
            return
        
        logger.debug(f"Connecting to PostgreSQL database for usage tracking")
        
        # Add backend to path and import
        # Save current directory and change to backend for reliable imports
        original_cwd = os.getcwd()
        try:
            # Add backend to path first (before chdir)
            if backend_path not in sys.path:
                sys.path.insert(0, backend_path)
            
            # Change to backend directory - this is critical for relative imports
            os.chdir(backend_path)
            
            # Now import using standard import - should work from backend directory
            # Clear any cached modules to force reload
            modules_to_clear = [k for k in sys.modules.keys() if k.startswith(('db', 'services', 'models'))]
            for mod in modules_to_clear:
                del sys.modules[mod]
            
            from db import get_db
            from services.usage import record_usage_event
        finally:
            # Restore original directory
            os.chdir(original_cwd)
        
        db = next(get_db())
        try:
            record_usage_event(
                db=db,
                tenant_id=tenant_id,
                user_id=user_id,
                agent=agent,
                source=source,
                jira_ticket_count=jira_ticket_count,
                input_char_count=input_char_count,
                success=success,
                error_code=error_code,
                run_id=run_id,
                duration_ms=duration_ms
            )
            print(f"[USAGE_TRACKING] Successfully recorded usage event for tenant {tenant_id}, agent {agent}, source={source}, jira_tickets={jira_ticket_count}, duration_ms={duration_ms}")
            logger.info(f"Successfully recorded usage event for tenant {tenant_id}, agent {agent}, source={source}, jira_tickets={jira_ticket_count}, duration_ms={duration_ms}")
        finally:
            db.close()
    except Exception as e:
        # Never raise - just log error with full traceback
        print(f"[USAGE_TRACKING] ERROR: Failed to record usage event: {str(e)}")
        logger.error(f"Failed to record usage event: {str(e)}", exc_info=True)


class DryRunRequest(BaseModel):
    """Request model for dry-run operation."""
    
    package: Dict[str, Any] = Field(..., description="Requirement package from upstream agent")


class DryRunResponse(BaseModel):
    """Response model for dry-run operation."""
    
    jira_issue: str = Field(..., description="Jira issue key")
    current_snapshot: Dict[str, str] = Field(..., description="Current Jira issue state")
    proposed_changes: Dict[str, str] = Field(..., description="Proposed changes to Jira issue")
    comment_preview: str = Field(..., description="Preview of comment to be added")
    checksum: str = Field(..., description="SHA-256 checksum of proposed changes")


def _validate_package(package: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
    """
    Validate input package structure.
    
    Args:
        package: Package dictionary
        
    Returns:
        Tuple of (issue_key, origin_dict)
        
    Raises:
        HTTPException: If validation fails
    """
    metadata = package.get("metadata", {}) if package.get("metadata") else {}
    
    # Validate scope_status == "locked"
    scope_status = package.get("scope_status")
    if scope_status != "locked":
        raise HTTPException(
            status_code=400,
            detail=f"Package scope_status must be 'locked', got '{scope_status}'"
        )
    
    # Try to get issue_key from metadata.origin.jira.issue_key (preferred)
    origin = metadata.get("origin")
    issue_key = None
    
    if origin and origin.get("type") == "jira":
        jira_info = origin.get("jira")
        if jira_info:
            issue_key = jira_info.get("issue_key")
    
    # Fallback: Try to extract from jira_context (BA agent format)
    if not issue_key:
        jira_context = metadata.get("jira_context")
        if jira_context and isinstance(jira_context, dict):
            # Try to get issue_key from jira_context structure
            # jira_context may have ticket_id or issue_key at top level
            issue_key = jira_context.get("ticket_id") or jira_context.get("issue_key")
            
            # If not found, try parent_ticket.ticket_id (BA agent stores ticket data here)
            if not issue_key:
                parent_ticket = jira_context.get("parent_ticket")
                if parent_ticket and isinstance(parent_ticket, dict):
                    issue_key = parent_ticket.get("ticket_id") or parent_ticket.get("id")
            
            # If still not found, try to extract from requirements (first requirement ID might be ticket-based)
            if not issue_key:
                requirements = package.get("requirements", [])
                if requirements and isinstance(requirements, list) and len(requirements) > 0:
                    first_req_id = requirements[0].get("id", "")
                    # Extract ticket key from requirement ID (e.g., "ATA-41-REQ-001" -> "ATA-41")
                    if "-" in first_req_id:
                        parts = first_req_id.split("-")
                        if len(parts) >= 2:
                            issue_key = f"{parts[0]}-{parts[1]}"
    
    # If still no issue_key, try to get from source field if it looks like a Jira ticket ID
    if not issue_key:
        source = metadata.get("source", "")
        # Check if source looks like a Jira ticket ID (e.g., "ATA-41" or "jira:ATA-41")
        if source and isinstance(source, str):
            if source.startswith("jira:"):
                issue_key = source.replace("jira:", "")
            elif "-" in source and len(source.split("-")) == 2:
                # Might be a Jira ticket ID
                issue_key = source
    
    if not issue_key:
        raise HTTPException(
            status_code=400,
            detail="Package metadata.origin.jira.issue_key is required, or package must have jira_context with ticket_id/issue_key, or source must be a Jira ticket ID"
        )
    
    # Build origin dict for return (construct if not present)
    if not origin:
        origin = {
            "type": "jira",
            "jira": {
                "issue_key": issue_key
            }
        }
    
    return issue_key, origin


def _extract_acceptance_criteria_from_requirements(requirements: list) -> str:
    """
    Extract acceptance criteria from requirements as formatted bullet list.
    
    Aggregates ALL business_requirements statements across ALL requirements
    in deterministic order (requirements in order, BRs in order).
    
    Args:
        requirements: List of requirement dictionaries (already sorted by ID)
        
    Returns:
        Formatted acceptance criteria string with one bullet per statement
    """
    criteria_items = []
    
    # Process requirements in order (they should already be sorted by ID)
    for req in requirements:
        # Extract business requirements as acceptance criteria
        business_requirements = req.get("business_requirements", [])
        # Process BRs in order
        for br in business_requirements:
            statement = br.get("statement", "")
            if statement:
                criteria_items.append(statement)
    
    if not criteria_items:
        return ""
    
    # Format as bullet list with "* " prefix
    return "\n".join(f"* {item}" for item in criteria_items)


def _extract_description_from_requirements(
    requirements: list,
    package_id: str,
    jira_summary: str,
    current_jira_description: str,
    gap_analysis: Optional[Dict[str, Any]] = None,
    risk_analysis: Optional[Dict[str, Any]] = None
) -> str:
    """
    Extract structured combined description from all requirements.
    
    Creates a deterministic template that includes:
    - All requirements with summaries and descriptions
    - Combined scope boundaries (in/out)
    - Identified gaps (if present)
    - Identified risks (if present)
    - Preserved original Jira description
    
    Args:
        requirements: List of requirement dictionaries (already sorted by ID)
        package_id: Package identifier
        jira_summary: Current Jira issue summary
        current_jira_description: Current Jira issue description (to preserve)
        gap_analysis: Optional gap analysis dict with 'gaps' list
        risk_analysis: Optional risk analysis dict with 'risks' list and 'risk_level' string
        
    Returns:
        Structured description string following the template format
    """
    if not requirements:
        # Fallback if no requirements
        description_parts = [
            "No requirements found."
        ]
        
        # Add gaps if present
        if gap_analysis:
            gaps = [g for g in gap_analysis.get("gaps", []) if g and g != "N/A"]
            if gaps:
                description_parts.append("")
                description_parts.append("Identified Gaps:")
                for gap in gaps:
                    description_parts.append(f"- {gap}")
        
        # Add risks if present
        if risk_analysis:
            risks = [r for r in risk_analysis.get("risks", []) if r and r != "N/A"]
            if risks:
                description_parts.append("")
                description_parts.append("Identified Risks:")
                for risk in risks:
                    description_parts.append(f"- {risk}")
                risk_level = risk_analysis.get("risk_level", "")
                if risk_level:
                    description_parts.append(f"Risk Level: {risk_level}")
        
        # Add preserved original description
        description_parts.append("")
        description_parts.append("--- Original Jira Description (preserved) ---")
        description_parts.append(current_jira_description)
        
        return "\n".join(description_parts)
    
    # Build normalized requirements section
    normalized_requirements = []
    for idx, req in enumerate(requirements, start=1):
        summary = req.get("summary", "")
        description = req.get("description", "")
        normalized_requirements.append(f"{idx}) {summary}\n   {description}")
    
    # Collect all in_scope items (union, preserving order)
    in_scope_items = []
    seen_in_scope = set()
    for req in requirements:
        scope_boundaries = req.get("scope_boundaries", {})
        in_scope = scope_boundaries.get("in_scope", [])
        for item in in_scope:
            if item and item not in seen_in_scope:
                in_scope_items.append(item)
                seen_in_scope.add(item)
    
    # Collect all out_of_scope items (union, preserving order)
    out_scope_items = []
    seen_out_scope = set()
    for req in requirements:
        scope_boundaries = req.get("scope_boundaries", {})
        out_of_scope = scope_boundaries.get("out_of_scope", [])
        for item in out_of_scope:
            if item and item not in seen_out_scope:
                out_scope_items.append(item)
                seen_out_scope.add(item)
    
    # Build the structured description
    description_parts = [
        "Normalized Requirements:",
        "\n\n".join(normalized_requirements)
    ]
    
    # Add scope sections if there are items
    if in_scope_items:
        description_parts.append("")
        description_parts.append("Scope (In):")
        for item in in_scope_items:
            description_parts.append(f"- {item}")
    
    if out_scope_items:
        description_parts.append("")
        description_parts.append("Scope (Out):")
        for item in out_scope_items:
            description_parts.append(f"- {item}")
    
    # Add gaps section if present and meaningful
    if gap_analysis:
        gaps = [g for g in gap_analysis.get("gaps", []) if g and g != "N/A"]
        if gaps:
            description_parts.append("")
            description_parts.append("Identified Gaps:")
            for gap in gaps:
                description_parts.append(f"- {gap}")
    
    # Add risks section if present and meaningful
    if risk_analysis:
        risks = [r for r in risk_analysis.get("risks", []) if r and r != "N/A"]
        if risks:
            description_parts.append("")
            description_parts.append("Identified Risks:")
            for risk in risks:
                description_parts.append(f"- {risk}")
            risk_level = risk_analysis.get("risk_level", "")
            if risk_level:
                description_parts.append(f"Risk Level: {risk_level}")
    
    # Add preserved original description
    description_parts.append("")
    description_parts.append("--- Original Jira Description (preserved) ---")
    description_parts.append(current_jira_description)
    
    return "\n".join(description_parts)


def _text_to_adf(text: str) -> Dict[str, Any]:
    """
    Convert plain text to Atlassian Document Format (ADF).
    
    Args:
        text: Plain text with newlines
        
    Returns:
        ADF document structure
    """
    if not text:
        return {
            "type": "doc",
            "version": 1,
            "content": []
        }
    
    lines = text.split('\n')
    content = []
    
    for line in lines:
        if line.strip():
            content.append({
                "type": "paragraph",
                "content": [
                    {
                        "type": "text",
                        "text": line
                    }
                ]
            })
        else:
            # Empty line - add empty paragraph
            content.append({
                "type": "paragraph",
                "content": []
            })
    
    return {
        "type": "doc",
        "version": 1,
        "content": content
    }


def _generate_comment_preview(
    package_id: str,
    approved_by: Optional[str],
    approved_at: Optional[str],
    checksum: str
) -> str:
    """
    Generate Jira comment preview with exact format.
    
    Args:
        package_id: Package identifier
        approved_by: User who approved (from package metadata)
        approved_at: Approval timestamp (from package metadata)
        checksum: SHA-256 checksum
        
    Returns:
        Formatted comment preview
    """
    approved_by_str = approved_by or "Unknown"
    approved_at_str = approved_at or datetime.now().isoformat()
    
    comment = f"""BA Requirements Rewrite Applied

Package: {package_id}
Approved by: {approved_by_str}
Date: {approved_at_str}

[ATA-BA-WB v{__version__} | Hash: {checksum}]"""
    
    return comment


def _compute_checksum(
    jira_issue_key: str,
    proposed_acceptance_criteria: str,
    proposed_description: str,
    package_id: str
) -> str:
    """
    Compute SHA-256 checksum from proposed changes.
    
    Args:
        jira_issue_key: Jira issue key
        proposed_acceptance_criteria: Proposed acceptance criteria
        proposed_description: Proposed description
        package_id: Package identifier
        
    Returns:
        SHA-256 checksum prefixed with "sha256:"
    """
    # Create deterministic string for hashing
    hash_input = f"{jira_issue_key}|{proposed_acceptance_criteria}|{proposed_description}|{package_id}"
    
    # Compute SHA-256 hash
    hash_bytes = hashlib.sha256(hash_input.encode('utf-8')).digest()
    hash_hex = hash_bytes.hex()
    
    return f"sha256:{hash_hex}"


@router.post("/api/v1/jira/rewrite/dry-run", response_model=DryRunResponse)
async def dry_run(dry_run_request: DryRunRequest) -> DryRunResponse:
    """
    Perform dry-run of Jira write-back operation.
    
    This endpoint:
    - Validates the input package
    - Fetches current Jira issue state (read-only)
    - Maps BA output to Jira preview
    - Generates comment preview
    - Computes checksum
    
    No Jira mutations are performed.
    
    Args:
        dry_run_request: Dry-run request containing package
        
    Returns:
        DryRunResponse with current snapshot, proposed changes, and preview
        
    Raises:
        HTTPException: If validation fails or Jira fetch fails
    """
    package = dry_run_request.package
    
    # Validate package
    try:
        issue_key, origin = _validate_package(package)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Package validation failed: {str(e)}"
        )
    
    # Load configuration
    try:
        config = JiraWriteBackConfig.from_env()
    except ValueError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Configuration error: {str(e)}"
        )
    
    # Initialize Jira client
    jira_client = JiraClient(
        base_url=config.JIRA_BASE_URL,
        username=config.JIRA_USERNAME,
        api_token=config.JIRA_API_TOKEN
    )
    
    # Fetch current Jira issue (read-only)
    try:
        current_issue = jira_client.get_issue(
            issue_key=issue_key,
            acceptance_criteria_field_id=config.JIRA_ACCEPTANCE_CRITERIA_FIELD_ID
        )
    except JiraClientError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch Jira issue {issue_key}: {str(e)}"
        )
    
    # Extract BA output from package
    # Requirements should already be sorted by ID, but ensure deterministic order
    requirements = package.get("requirements", [])
    # Sort by ID to ensure deterministic ordering
    requirements = sorted(requirements, key=lambda r: r.get("id", ""))
    package_id = package.get("package_id", "Unknown")
    
    # Get gap and risk analysis from package
    gap_analysis = package.get("gap_analysis")
    risk_analysis = package.get("risk_analysis")
    
    # Get current Jira issue data (from Jira fetch, not package snapshot)
    jira_summary = current_issue.get("summary", "")
    current_jira_description = current_issue.get("description", "")
    
    # Map BA output to Jira preview
    proposed_acceptance_criteria = _extract_acceptance_criteria_from_requirements(requirements)
    proposed_description = _extract_description_from_requirements(
        requirements=requirements,
        package_id=package_id,
        jira_summary=jira_summary,
        current_jira_description=current_jira_description,
        gap_analysis=gap_analysis,
        risk_analysis=risk_analysis
    )
    metadata = package.get("metadata", {})
    approved_by = metadata.get("approved_by")
    approved_at = metadata.get("approved_at")
    
    # Compute checksum
    checksum = _compute_checksum(
        jira_issue_key=issue_key,
        proposed_acceptance_criteria=proposed_acceptance_criteria,
        proposed_description=proposed_description,
        package_id=package_id
    )
    
    # Generate comment preview
    comment_preview = _generate_comment_preview(
        package_id=package_id,
        approved_by=approved_by,
        approved_at=approved_at,
        checksum=checksum
    )
    
    # Build response
    return DryRunResponse(
        jira_issue=issue_key,
        current_snapshot={
            "acceptance_criteria": current_issue.get("acceptance_criteria", ""),
            "description": current_issue.get("description", "")
        },
        proposed_changes={
            "acceptance_criteria": proposed_acceptance_criteria,
            "description": proposed_description
        },
        comment_preview=comment_preview,
        checksum=checksum
    )


class ExecuteRequest(BaseModel):
    """Request model for execute operation."""
    
    package: Dict[str, Any] = Field(..., description="Requirement package from upstream agent")
    checksum: str = Field(..., description="SHA-256 checksum from dry-run")
    approved_by: str = Field(..., description="User who approved the write-back")
    approved_at: str = Field(..., description="ISO timestamp of approval")
    source_revision: Optional[str] = Field(None, description="Jira issue updated_at from dry-run")


class ExecuteResponse(BaseModel):
    """Response model for execute operation."""
    
    jira_issue: str = Field(..., description="Jira issue key")
    result: str = Field(..., description="Result: 'success' or 'skipped'")
    fields_modified: List[str] = Field(..., description="List of fields that were modified")
    comment_id: Optional[str] = Field(None, description="Jira comment ID if comment was added")
    checksum: str = Field(..., description="SHA-256 checksum that was applied")
    usage: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Usage data (runs_used, runs_limit, period_start, period_end) - optional"
    )


def _check_idempotency(jira_client: JiraClient, issue_key: str, checksum: str) -> bool:
    """
    Check if this write-back has already been applied (idempotency check).
    
    Args:
        jira_client: Jira client instance
        issue_key: Jira issue key
        checksum: Checksum to look for
        
    Returns:
        True if comment with same hash exists, False otherwise
    """
    try:
        comments = jira_client.list_comments(issue_key)
        
        # Look for comment footer with matching hash
        hash_pattern = f"[ATA-BA-WB v{__version__} | Hash: {checksum}]"
        
        for comment in comments:
            if hash_pattern in comment.get("body", ""):
                return True
        
        return False
    except JiraClientError:
        # If we can't check comments, proceed (fail-safe)
        return False


@router.post("/api/v1/jira/rewrite/execute", response_model=ExecuteResponse)
async def execute(execute_request: ExecuteRequest, request: Request) -> ExecuteResponse:
    """
    Execute Jira write-back operation.
    
    This endpoint:
    - Validates preconditions
    - Checks revision hasn't changed since dry-run
    - Checks idempotency
    - Applies Jira updates (acceptance criteria, description, comment)
    - Logs audit trail
    - Records usage event for billing/analytics
    
    Args:
        execute_request: Execute request with package, checksum, and approval info
        request: FastAPI Request object (for internal service key validation)
        
    Returns:
        ExecuteResponse with result and details
        
    Raises:
        HTTPException: If validation fails, revision changed, or Jira update fails
    """
    # ============================================================================
    # TRUST BOUNDARY: This agent is a trusted internal executor.
    # All policy enforcement (subscription, plan tiers, trials) happens in Flask app.
    # This agent ONLY validates the internal service key.
    # ============================================================================
    from middleware.internal_auth import verify_internal_service_key, extract_tenant_context_for_logging
    import logging
    logger = logging.getLogger(__name__)
    
    # Verify internal service key (required - this is the ONLY auth enforcement)
    await verify_internal_service_key(request)
    
    # ============================================================================
    # TENANT_ID EXTRACTION (SECURITY)
    # ============================================================================
    # SECURITY NOTE: tenant_id comes from X-Tenant-ID header, which is set by the
    # Flask app (policy authority) after JWT validation. The Flask app extracts
    # tenant_id from the JWT token's 'tenant_id' claim (not from client headers).
    # 
    # Trust boundary:
    # - Client → Flask app: JWT validated, tenant_id extracted from JWT claim
    # - Flask app → Jira agent: Internal service key validated, tenant_id passed in header
    # 
    # The Jira agent trusts tenant_id from Flask app because:
    # 1. Only Flask app can call Jira agent (X-Internal-Service-Key required)
    # 2. Flask app extracts tenant_id from verified JWT (not client-controlled)
    # 3. This is an internal service-to-service call, not client-facing
    # ============================================================================
    tenant_id, user_id = extract_tenant_context_for_logging(request)
    if tenant_id:
        logger.info(f"Processing execute request (tenant={tenant_id}, user={user_id})")
    else:
        # tenant_id should always be present if Flask app called us correctly
        logger.warning("X-Tenant-ID header missing - this should not happen in normal operation")
    
    # ============================================================================
    # NOTE: Entitlement checks (subscription, plan tiers, trials) are REMOVED.
    # Flask app enforces all policy before calling this agent.
    # ============================================================================
    
    # ============================================================================
    # RUN LIMIT ENFORCEMENT (FAIL-CLOSED)
    # Enforce run limits per period based on plan tier BEFORE Jira write operations
    # 
    # FAIL-CLOSED POLICY: If usage metering fails (exception, DB error, etc.),
    # return HTTP 503 and DO NOT proceed with Jira writes. This prevents:
    # - Unmetered runs when metering is unavailable
    # - Billing discrepancies
    # - Resource exhaustion
    # ============================================================================
    usage_data = None
    if not tenant_id:
        # tenant_id is required for run limit enforcement
        # Return 503 (service unavailable) since we cannot meter usage without tenant_id
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=503,
            content={
                "ok": False,
                "error": "USAGE_METER_UNAVAILABLE",
                "message": "Usage metering unavailable. Please try again shortly."
            },
            headers=_get_cors_headers(request)
        )
    
    # tenant_id is present - proceed with run limit enforcement
    # FAIL-CLOSED: All exceptions in usage metering result in 503 (do not proceed)
    try:
        import sys
        import os
        # Calculate absolute path to testing agent backend
        current_file = os.path.abspath(__file__)
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
        backend_path = os.path.join(project_root, "ai-testing-agent", "backend")
        
        if not os.path.exists(backend_path):
            raise RuntimeError(f"Backend path not found: {backend_path}")
        
        # Verify DATABASE_URL is PostgreSQL
        db_url = os.getenv("DATABASE_URL")
        if not db_url:
            raise RuntimeError("DATABASE_URL not set - cannot perform usage metering")
        
        if not (db_url.startswith("postgresql://") or db_url.startswith("postgres://")):
            raise RuntimeError(f"DATABASE_URL is not PostgreSQL: {db_url[:50]}... - cannot perform usage metering")
        
        # Save current directory and change to backend for reliable imports
        original_cwd = os.getcwd()
        try:
            if backend_path not in sys.path:
                sys.path.insert(0, backend_path)
            os.chdir(backend_path)
            
            from db import get_db
            from services.entitlements_centralized import get_tenant_billing
            from services.run_limits import check_and_increment_run_usage
            
            db = next(get_db())
            try:
                # Get billing data to extract plan_tier and period info
                billing = get_tenant_billing(db, str(tenant_id))
                plan_tier = billing.get("plan_tier")
                current_period_start = billing.get("current_period_start")
                current_period_end = billing.get("current_period_end")
                
                # Check and atomically increment run usage
                # Pass user_id for owner bypass check
                run_allowed, run_error, usage_data = check_and_increment_run_usage(
                    db=db,
                    tenant_id=str(tenant_id),
                    plan_tier=plan_tier,
                    current_period_start=current_period_start,
                    current_period_end=current_period_end,
                    user_id=user_id
                )
                
                if not run_allowed:
                    # Determine error type and client-friendly message
                    error_code = run_error or "RUN_LIMIT_REACHED"
                    
                    # Map internal error codes to client-friendly messages
                    if error_code == "RUN_LIMIT_REACHED":
                        client_message = "You've reached your monthly run limit for your current plan. Upgrade your plan or wait until the next billing period to continue."
                        http_status = 402  # Payment Required
                    elif error_code == "USAGE_ROW_MISSING":
                        client_message = "We ran into a temporary system issue while checking usage limits. Please try again in a moment. If the issue persists, contact support."
                        http_status = 500  # Internal Server Error
                    elif error_code == "RUN_LIMIT_CHECK_ERROR":
                        client_message = "We ran into a temporary system issue while checking usage limits. Please try again in a moment. If the issue persists, contact support."
                        http_status = 500  # Internal Server Error
                    else:
                        # Unknown error - use generic message
                        client_message = "We ran into a temporary system issue while checking usage limits. Please try again in a moment. If the issue persists, contact support."
                        http_status = 500
                    
                    # Log internal error code for debugging (not exposed to client)
                    logger.warning(f"Run limit check failed: error_code={error_code} tenant_id={tenant_id} usage_data={usage_data}")
                    
                    from fastapi.responses import JSONResponse
                    error_response = {
                        "ok": False,
                        "error": error_code,  # Internal error code (for debugging/logs)
                        "message": client_message  # Client-friendly message
                    }
                    if usage_data:
                        error_response.update({
                            "runs_used": usage_data.get("runs_used"),
                            "runs_limit": usage_data.get("runs_limit"),
                            "period_start": usage_data.get("period_start"),
                            "period_end": usage_data.get("period_end")
                        })
                    
                    return JSONResponse(
                        status_code=http_status,
                        content=error_response,
                        headers=_get_cors_headers(request)
                    )
            finally:
                db.close()
        finally:
            os.chdir(original_cwd)
    except Exception as run_limit_error:
        # FAIL-CLOSED: If usage metering fails, do NOT proceed with Jira writes
        # This prevents unmetered runs and billing discrepancies
        logger.error(f"Run limit check failed for tenant {tenant_id}: {str(run_limit_error)}", exc_info=True)
        
        # Return 503 (service unavailable) with error details
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=503,
            content={
                "ok": False,
                "error": "USAGE_METER_UNAVAILABLE",
                "message": "Usage metering unavailable. Please try again shortly."
            },
            headers=_get_cors_headers(request)
        )
    
    # Capture start time for usage tracking
    start_time_ms = int(time.time() * 1000)
    
    # Generate run_id for this request
    run_id = str(uuid.uuid4())
    
    # Calculate input_char_count from request payload
    try:
        input_char_count = len(json.dumps(execute_request.dict(), default=str))
    except Exception:
        input_char_count = 0
    
    package = execute_request.package
    expected_checksum = execute_request.checksum
    approved_by = execute_request.approved_by
    approved_at = execute_request.approved_at
    source_revision = execute_request.source_revision
    
    # Validate package structure
    try:
        issue_key, origin = _validate_package(package)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Package validation failed: {str(e)}"
        )
    
    # Validate required fields
    package_id = package.get("package_id")
    if not package_id:
        raise HTTPException(
            status_code=400,
            detail="package_id is required in package"
        )
    
    # Load configuration
    try:
        config = JiraWriteBackConfig.from_env()
    except ValueError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Configuration error: {str(e)}"
        )
    
    # Initialize clients
    jira_client = JiraClient(
        base_url=config.JIRA_BASE_URL,
        username=config.JIRA_USERNAME,
        api_token=config.JIRA_API_TOKEN
    )
    audit_logger = AuditLogger()
    
    # Re-fetch Jira issue to check revision
    try:
        current_issue = jira_client.get_issue(
            issue_key=issue_key,
            acceptance_criteria_field_id=config.JIRA_ACCEPTANCE_CRITERIA_FIELD_ID
        )
    except JiraClientError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch Jira issue {issue_key}: {str(e)}"
        )
    
    current_revision = current_issue.get("updated_at", "")
    
    # Check revision hasn't changed since dry-run
    if source_revision and current_revision != source_revision:
        raise HTTPException(
            status_code=409,
            detail="Jira issue changed since dry-run"
        )
    
    # Extract BA output from package
    # Requirements should already be sorted by ID, but ensure deterministic order
    requirements = package.get("requirements", [])
    # Sort by ID to ensure deterministic ordering
    requirements = sorted(requirements, key=lambda r: r.get("id", ""))
    
    # Get gap and risk analysis from package
    gap_analysis = package.get("gap_analysis")
    risk_analysis = package.get("risk_analysis")
    
    # Get current Jira issue data for description mapping (from Jira fetch, not package snapshot)
    jira_summary = current_issue.get("summary", "")
    current_jira_description = current_issue.get("description", "")
    
    # Map BA output to Jira preview (same logic as dry-run)
    proposed_acceptance_criteria = _extract_acceptance_criteria_from_requirements(requirements)
    proposed_description = _extract_description_from_requirements(
        requirements=requirements,
        package_id=package_id,
        jira_summary=jira_summary,
        current_jira_description=current_jira_description,
        gap_analysis=gap_analysis,
        risk_analysis=risk_analysis
    )
    
    # Recompute checksum to verify it matches
    computed_checksum = _compute_checksum(
        jira_issue_key=issue_key,
        proposed_acceptance_criteria=proposed_acceptance_criteria,
        proposed_description=proposed_description,
        package_id=package_id
    )
    
    if computed_checksum != expected_checksum:
        raise HTTPException(
            status_code=400,
            detail=f"Checksum mismatch. Expected {expected_checksum}, computed {computed_checksum}"
        )
    
    # Check idempotency
    if _check_idempotency(jira_client, issue_key, expected_checksum):
        # Already applied - skip and log
        audit_logger.log_event({
            "package_id": package_id,
            "jira_issue_key": issue_key,
            "fields_modified": [],
            "approved_by": approved_by,
            "executed_at": datetime.now().isoformat(),
            "checksum": expected_checksum,
            "jira_response_id": None,
            "result": "skipped"
        })
        
        # Record usage event (skipped = success, 0 tickets created/updated)
        end_time_ms = int(time.time() * 1000)
        duration_ms = end_time_ms - start_time_ms
        _record_usage_event(
            tenant_id=tenant_id,
            user_id=user_id,
            agent="jira-writeback-agent",
            source="ui_execute",
            jira_ticket_count=0,  # Skipped, no updates
            input_char_count=input_char_count,
            success=True,
            error_code=None,
            run_id=run_id,
            duration_ms=duration_ms
        )
        
        return ExecuteResponse(
            jira_issue=issue_key,
            result="skipped",
            fields_modified=[],
            comment_id=None,
            checksum=expected_checksum,
            usage=usage_data
        )
    
    # Apply Jira updates
    fields_modified = []
    comment_id = None
    
    try:
        # Prepare fields to update
        fields_to_update = {}
        
        if proposed_description:
            fields_to_update["description"] = proposed_description
            fields_modified.append("description")
        
        if proposed_acceptance_criteria and config.JIRA_ACCEPTANCE_CRITERIA_FIELD_ID:
            fields_to_update["acceptance_criteria"] = proposed_acceptance_criteria
            fields_modified.append("acceptance_criteria")
        
        # Update fields if any
        if fields_to_update:
            jira_client.update_issue_fields(
                issue_key=issue_key,
                fields_dict=fields_to_update,
                acceptance_criteria_field_id=config.JIRA_ACCEPTANCE_CRITERIA_FIELD_ID
            )
        
        # Add audit comment
        comment_text = _generate_comment_preview(
            package_id=package_id,
            approved_by=approved_by,
            approved_at=approved_at,
            checksum=expected_checksum
        )
        
        comment_response = jira_client.add_comment(issue_key, comment_text)
        comment_id = comment_response.get("id")
        
        # Log audit event
        audit_logger.log_event({
            "package_id": package_id,
            "jira_issue_key": issue_key,
            "fields_modified": fields_modified,
            "approved_by": approved_by,
            "executed_at": datetime.now().isoformat(),
            "checksum": expected_checksum,
            "jira_response_id": comment_id,
            "result": "success"
        })
        
        # Record usage event (success - 1 ticket updated)
        end_time_ms = int(time.time() * 1000)
        duration_ms = end_time_ms - start_time_ms
        _record_usage_event(
            tenant_id=tenant_id,
            user_id=user_id,
            agent="jira-writeback-agent",
            source="ui_execute",
            jira_ticket_count=1,  # 1 ticket updated
            input_char_count=input_char_count,
            success=True,
            error_code=None,
            run_id=run_id,
            duration_ms=duration_ms
        )
        
        # ============================================================================
        # NOTE: Trial consumption REMOVED - Flask app handles trial consumption
        # after successful agent execution. This agent is execution-only.
        # ============================================================================
        
        return ExecuteResponse(
            jira_issue=issue_key,
            result="success",
            fields_modified=fields_modified,
            comment_id=comment_id,
            checksum=expected_checksum,
            usage=usage_data
        )
        
    except HTTPException:
        # Re-raise HTTP exceptions (validation errors, etc.)
        # Record usage event for HTTP errors
        end_time_ms = int(time.time() * 1000)
        duration_ms = end_time_ms - start_time_ms
        _record_usage_event(
            tenant_id=tenant_id,
            user_id=user_id,
            agent="jira-writeback-agent",
            source="ui_execute",
            jira_ticket_count=0,
            input_char_count=input_char_count,
            success=False,
            error_code="VALIDATION",
            run_id=run_id,
            duration_ms=duration_ms
        )
        raise
    except JiraClientError as e:
        # Record usage event for Jira errors
        end_time_ms = int(time.time() * 1000)
        duration_ms = end_time_ms - start_time_ms
        error_code = "JIRA_5XX"  # Default for JiraClientError
        error_str = str(e).lower()
        if "401" in error_str or "403" in error_str or "unauthorized" in error_str or "forbidden" in error_str:
            error_code = "JIRA_AUTH"
        elif "400" in error_str or "404" in error_str or "422" in error_str:
            error_code = "JIRA_4XX"
        
        _record_usage_event(
            tenant_id=tenant_id,
            user_id=user_id,
            agent="jira-writeback-agent",
            source="ui_execute",
            jira_ticket_count=0,
            input_char_count=input_char_count,
            success=False,
            error_code=error_code,
            run_id=run_id,
            duration_ms=duration_ms
        )
        
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update Jira issue {issue_key}: {str(e)}"
        )
    except Exception as e:
        # Record usage event for unexpected errors
        end_time_ms = int(time.time() * 1000)
        duration_ms = end_time_ms - start_time_ms
        _record_usage_event(
            tenant_id=tenant_id,
            user_id=user_id,
            agent="jira-writeback-agent",
            source="ui_execute",
            jira_ticket_count=0,
            input_char_count=input_char_count,
            success=False,
            error_code="UNKNOWN",
            run_id=run_id,
            duration_ms=duration_ms
        )
        
        raise HTTPException(
            status_code=500,
            detail=f"Unexpected error during Jira update: {str(e)}"
        )


# ============================================================================
# Phase 4B: Create Jira Ticket from Free-Form Package
# ============================================================================

class CreateDryRunRequest(BaseModel):
    """Request model for create dry-run operation."""
    
    package: Dict[str, Any] = Field(..., description="Requirement package from upstream agent")
    project_key: str = Field(..., description="Jira project key")
    issue_type: Optional[str] = Field(None, description="Jira issue type (name or ID) - inferred from package if not provided")
    summary: Optional[str] = Field(None, description="Issue summary (defaults to first requirement summary if not provided)")
    approved_by: Optional[str] = Field(None, description="User who approved (optional for dry-run)")
    approved_at: Optional[str] = Field(None, description="ISO timestamp of approval (optional for dry-run)")


class CreateDryRunResponse(BaseModel):
    """Response model for create dry-run operation."""
    
    proposed_issue: Dict[str, str] = Field(..., description="Proposed issue details")
    proposed_changes: Dict[str, str] = Field(..., description="Proposed issue content")
    comment_preview: str = Field(..., description="Preview of comment to be added")
    checksum: str = Field(..., description="SHA-256 checksum of proposed changes")


class CreateExecuteRequest(BaseModel):
    """Request model for create execute operation."""
    
    package: Dict[str, Any] = Field(..., description="Requirement package from upstream agent")
    project_key: str = Field(..., description="Jira project key")
    issue_type: Optional[str] = Field(None, description="Jira issue type (name or ID) - inferred from package if not provided")
    summary: Optional[str] = Field(None, description="Issue summary")
    checksum: str = Field(..., description="SHA-256 checksum from dry-run")
    approved_by: str = Field(..., description="User who approved the create")
    approved_at: str = Field(..., description="ISO timestamp of approval")


class CreateExecuteResponse(BaseModel):
    """Response model for create execute operation."""
    
    created_issue_key: str = Field(..., description="Created Jira issue key")
    result: str = Field(..., description="Result: 'success' or 'skipped'")
    fields_set: List[str] = Field(..., description="List of fields that were set")
    comment_id: Optional[str] = Field(None, description="Jira comment ID if comment was added")
    checksum: str = Field(..., description="SHA-256 checksum that was applied")
    usage: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Usage data (runs_used, runs_limit, period_start, period_end) - optional"
    )


def _validate_create_package(package: Dict[str, Any]) -> None:
    """
    Validate package for create operation.
    
    Args:
        package: Package dictionary
        
    Raises:
        HTTPException: If validation fails
    """
    # Validate scope_status == "locked"
    scope_status = package.get("scope_status")
    if scope_status != "locked":
        raise HTTPException(
            status_code=400,
            detail=f"Package scope_status must be 'locked', got '{scope_status}'"
        )
    
    # Validate origin.type is NOT "jira" (reject jira-origin packages)
    origin = package.get("metadata", {}).get("origin") if package.get("metadata") else None
    if origin and origin.get("type") == "jira":
        raise HTTPException(
            status_code=400,
            detail="Jira-origin packages cannot be used for create flow. Use rewrite endpoint instead."
        )


def _check_create_idempotency(
    jira_client: JiraClient,
    package_id: str,
    checksum: str
) -> Optional[str]:
    """
    Check if this package has already been created (idempotency check).
    
    Searches for existing issue with label "reqpkg_{package_id}".
    
    Args:
        jira_client: Jira client instance
        package_id: Package identifier
        checksum: Checksum to verify in comment
        
    Returns:
        Existing issue key if found, None otherwise
    """
    try:
        label = f"reqpkg_{package_id}"
        jql = f'labels = "{label}"'
        issues = jira_client.search_issues(jql)
        
        if not issues:
            return None
        
        # Check if any of the found issues has the matching hash in comments
        hash_pattern = f"[ATA-BA-WB v{__version__} | Hash: {checksum}]"
        
        for issue in issues:
            issue_key = issue.get("issue_key")
            if issue_key:
                comments = jira_client.list_comments(issue_key)
                for comment in comments:
                    if hash_pattern in comment.get("body", ""):
                        return issue_key
        
        # If label exists but no matching hash, return None (not idempotent)
        return None
    except JiraClientError:
        # If search fails, proceed (fail-safe)
        return None


def _compute_create_checksum(
    project_key: str,
    issue_type: str,
    summary: str,
    proposed_description: str,
    proposed_acceptance_criteria: str,
    package_id: str
) -> str:
    """
    Compute SHA-256 checksum for create operation.
    
    Args:
        project_key: Jira project key
        issue_type: Issue type
        summary: Issue summary
        proposed_description: Proposed description
        proposed_acceptance_criteria: Proposed acceptance criteria
        package_id: Package identifier
        
    Returns:
        SHA-256 checksum prefixed with "sha256:"
    """
    hash_input = f"{project_key}|{issue_type}|{summary}|{proposed_description}|{proposed_acceptance_criteria}|{package_id}"
    hash_bytes = hashlib.sha256(hash_input.encode('utf-8')).digest()
    hash_hex = hash_bytes.hex()
    return f"sha256:{hash_hex}"


@router.post("/api/v1/jira/create/dry-run", response_model=CreateDryRunResponse)
async def create_dry_run(create_request: CreateDryRunRequest) -> CreateDryRunResponse:
    """
    Perform dry-run of Jira ticket creation.
    
    This endpoint:
    - Validates the input package (must be locked, must NOT be jira-origin)
    - Maps BA output to Jira preview
    - Generates comment preview
    - Computes checksum
    
    No Jira mutations are performed.
    
    Args:
        create_request: Create dry-run request
        
    Returns:
        CreateDryRunResponse with proposed issue details and preview
    """
    package = create_request.package
    project_key = create_request.project_key
    issue_type = create_request.issue_type
    
    # Validate package
    try:
        _validate_create_package(package)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Package validation failed: {str(e)}"
        )
    
    # Validate required fields
    if not project_key:
        raise HTTPException(
            status_code=400,
            detail="project_key is required"
        )
    
    package_id = package.get("package_id", "Unknown")
    requirements = package.get("requirements", [])
    requirements = sorted(requirements, key=lambda r: r.get("id", ""))
    
    # Infer issue_type from package if not provided
    if not issue_type:
        if requirements and len(requirements) > 0:
            first_req = requirements[0]
            issue_type = first_req.get("ticket_type")
        if not issue_type:
            issue_type = "Story"  # Default fallback
    
    # Determine summary
    if create_request.summary:
        summary = create_request.summary
    elif requirements:
        first_req_summary = requirements[0].get("summary", "")
        summary = f"BA Package {package_id}: {first_req_summary}"
    else:
        summary = f"BA Package {package_id}"
    
    # Get gap and risk analysis
    gap_analysis = package.get("gap_analysis")
    risk_analysis = package.get("risk_analysis")
    
    # Use original_input for "preserved original" section (no Jira source)
    original_input = package.get("original_input", "")
    
    # Map BA output to Jira preview
    proposed_acceptance_criteria = _extract_acceptance_criteria_from_requirements(requirements)
    proposed_description = _extract_description_from_requirements(
        requirements=requirements,
        package_id=package_id,
        jira_summary=summary,  # Use proposed summary
        current_jira_description=original_input,  # Use original_input instead of Jira description
        gap_analysis=gap_analysis,
        risk_analysis=risk_analysis
    )
    
    # Get approval info
    approved_by = create_request.approved_by
    approved_at = create_request.approved_at or datetime.now().isoformat()
    
    # Compute checksum
    checksum = _compute_create_checksum(
        project_key=project_key,
        issue_type=issue_type,
        summary=summary,
        proposed_description=proposed_description,
        proposed_acceptance_criteria=proposed_acceptance_criteria,
        package_id=package_id
    )
    
    # Generate comment preview
    comment_preview = _generate_comment_preview(
        package_id=package_id,
        approved_by=approved_by,
        approved_at=approved_at,
        checksum=checksum
    )
    
    return CreateDryRunResponse(
        proposed_issue={
            "project_key": project_key,
            "issue_type": issue_type,
            "summary": summary
        },
        proposed_changes={
            "description": proposed_description,
            "acceptance_criteria": proposed_acceptance_criteria
        },
        comment_preview=comment_preview,
        checksum=checksum
    )


@router.post("/api/v1/jira/create/execute", response_model=CreateExecuteResponse)
async def create_execute(execute_request: CreateExecuteRequest, request: Request) -> CreateExecuteResponse:
    """
    Execute Jira ticket creation.
    
    This endpoint:
    - Validates preconditions
    - Checks idempotency (searches for existing issue with label)
    - Creates Jira issue
    - Sets allow-listed fields (description, acceptance criteria, labels)
    - Adds audit comment
    - Logs audit trail
    - Records usage event for billing/analytics
    
    Args:
        execute_request: Create execute request
        request: FastAPI Request object (for internal service key validation)
        
    Returns:
        CreateExecuteResponse with created issue key and details
    """
    # ============================================================================
    # TRUST BOUNDARY: This agent is a trusted internal executor.
    # All policy enforcement (subscription, plan tiers, trials) happens in Flask app.
    # This agent ONLY validates the internal service key.
    # ============================================================================
    import sys
    import os
    # Import internal auth middleware
    current_file = os.path.abspath(__file__)
    middleware_path = os.path.join(os.path.dirname(os.path.dirname(current_file)), "middleware")
    if middleware_path not in sys.path:
        sys.path.insert(0, middleware_path)
    from middleware.internal_auth import verify_internal_service_key, extract_tenant_context_for_logging
    import logging
    logger = logging.getLogger(__name__)
    
    # Verify internal service key (required - this is the ONLY auth enforcement)
    await verify_internal_service_key(request)
    
    # ============================================================================
    # TENANT_ID EXTRACTION (SECURITY)
    # ============================================================================
    # SECURITY NOTE: tenant_id comes from X-Tenant-ID header, which is set by the
    # Flask app (policy authority) after JWT validation. The Flask app extracts
    # tenant_id from the JWT token's 'tenant_id' claim (not from client headers).
    # 
    # Trust boundary:
    # - Client → Flask app: JWT validated, tenant_id extracted from JWT claim
    # - Flask app → Jira agent: Internal service key validated, tenant_id passed in header
    # 
    # The Jira agent trusts tenant_id from Flask app because:
    # 1. Only Flask app can call Jira agent (X-Internal-Service-Key required)
    # 2. Flask app extracts tenant_id from verified JWT (not client-controlled)
    # 3. This is an internal service-to-service call, not client-facing
    # ============================================================================
    tenant_id, user_id = extract_tenant_context_for_logging(request)
    if tenant_id:
        logger.info(f"Processing create_execute request (tenant={tenant_id}, user={user_id})")
    else:
        # tenant_id should always be present if Flask app called us correctly
        logger.warning("X-Tenant-ID header missing - this should not happen in normal operation")
    
    # ============================================================================
    # NOTE: Entitlement checks (subscription, plan tiers, trials) are REMOVED.
    # Flask app enforces all policy before calling this agent.
    # ============================================================================
    
    # ============================================================================
    # RUN LIMIT ENFORCEMENT (FAIL-CLOSED)
    # Enforce run limits per period based on plan tier BEFORE Jira create operations
    # 
    # FAIL-CLOSED POLICY: If usage metering fails (exception, DB error, etc.),
    # return HTTP 503 and DO NOT proceed with Jira writes. This prevents:
    # - Unmetered runs when metering is unavailable
    # - Billing discrepancies
    # - Resource exhaustion
    # ============================================================================
    usage_data = None
    if not tenant_id:
        # tenant_id is required for run limit enforcement
        # Return 503 (service unavailable) since we cannot meter usage without tenant_id
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=503,
            content={
                "ok": False,
                "error": "USAGE_METER_UNAVAILABLE",
                "message": "Usage metering unavailable. Please try again shortly."
            },
            headers=_get_cors_headers(request)
        )
    
    # tenant_id is present - proceed with run limit enforcement
    # FAIL-CLOSED: All exceptions in usage metering result in 503 (do not proceed)
    try:
        import sys
        import os
        # Calculate absolute path to testing agent backend
        current_file = os.path.abspath(__file__)
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
        backend_path = os.path.join(project_root, "ai-testing-agent", "backend")
        
        if not os.path.exists(backend_path):
            raise RuntimeError(f"Backend path not found: {backend_path}")
        
        # Verify DATABASE_URL is PostgreSQL
        db_url = os.getenv("DATABASE_URL")
        if not db_url:
            raise RuntimeError("DATABASE_URL not set - cannot perform usage metering")
        
        if not (db_url.startswith("postgresql://") or db_url.startswith("postgres://")):
            raise RuntimeError(f"DATABASE_URL is not PostgreSQL: {db_url[:50]}... - cannot perform usage metering")
        
        # Save current directory and change to backend for reliable imports
        original_cwd = os.getcwd()
        try:
            if backend_path not in sys.path:
                sys.path.insert(0, backend_path)
            os.chdir(backend_path)
            
            from db import get_db
            from services.entitlements_centralized import get_tenant_billing
            from services.run_limits import check_and_increment_run_usage
            
            db = next(get_db())
            try:
                # Get billing data to extract plan_tier and period info
                billing = get_tenant_billing(db, str(tenant_id))
                plan_tier = billing.get("plan_tier")
                current_period_start = billing.get("current_period_start")
                current_period_end = billing.get("current_period_end")
                
                # Check and atomically increment run usage
                # Pass user_id for owner bypass check
                run_allowed, run_error, usage_data = check_and_increment_run_usage(
                    db=db,
                    tenant_id=str(tenant_id),
                    plan_tier=plan_tier,
                    current_period_start=current_period_start,
                    current_period_end=current_period_end,
                    user_id=user_id
                )
                
                if not run_allowed:
                    # Determine error type and client-friendly message
                    error_code = run_error or "RUN_LIMIT_REACHED"
                    
                    # Map internal error codes to client-friendly messages
                    if error_code == "RUN_LIMIT_REACHED":
                        client_message = "You've reached your monthly run limit for your current plan. Upgrade your plan or wait until the next billing period to continue."
                        http_status = 402  # Payment Required
                    elif error_code == "USAGE_ROW_MISSING":
                        client_message = "We ran into a temporary system issue while checking usage limits. Please try again in a moment. If the issue persists, contact support."
                        http_status = 500  # Internal Server Error
                    elif error_code == "RUN_LIMIT_CHECK_ERROR":
                        client_message = "We ran into a temporary system issue while checking usage limits. Please try again in a moment. If the issue persists, contact support."
                        http_status = 500  # Internal Server Error
                    else:
                        # Unknown error - use generic message
                        client_message = "We ran into a temporary system issue while checking usage limits. Please try again in a moment. If the issue persists, contact support."
                        http_status = 500
                    
                    # Log internal error code for debugging (not exposed to client)
                    logger.warning(f"Run limit check failed: error_code={error_code} tenant_id={tenant_id} usage_data={usage_data}")
                    
                    from fastapi.responses import JSONResponse
                    error_response = {
                        "ok": False,
                        "error": error_code,  # Internal error code (for debugging/logs)
                        "message": client_message  # Client-friendly message
                    }
                    if usage_data:
                        error_response.update({
                            "runs_used": usage_data.get("runs_used"),
                            "runs_limit": usage_data.get("runs_limit"),
                            "period_start": usage_data.get("period_start"),
                            "period_end": usage_data.get("period_end")
                        })
                    
                    return JSONResponse(
                        status_code=http_status,
                        content=error_response,
                        headers=_get_cors_headers(request)
                    )
            finally:
                db.close()
        finally:
            os.chdir(original_cwd)
    except Exception as run_limit_error:
        # FAIL-CLOSED: If usage metering fails, do NOT proceed with Jira writes
        # This prevents unmetered runs and billing discrepancies
        logger.error(f"Run limit check failed for tenant {tenant_id}: {str(run_limit_error)}", exc_info=True)
        
        # Return 503 (service unavailable) with error details
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=503,
            content={
                "ok": False,
                "error": "USAGE_METER_UNAVAILABLE",
                "message": "Usage metering unavailable. Please try again shortly."
            },
            headers=_get_cors_headers(request)
        )
    
    # Capture start time for usage tracking
    start_time_ms = int(time.time() * 1000)
    
    # Generate run_id for this request
    run_id = str(uuid.uuid4())
    
    # Calculate input_char_count from request payload
    # Serialize execute_request to JSON to get character count
    try:
        input_char_count = len(json.dumps(execute_request.dict(), default=str))
    except Exception:
        input_char_count = 0
    
    package = execute_request.package
    project_key = execute_request.project_key
    issue_type = execute_request.issue_type
    expected_checksum = execute_request.checksum
    approved_by = execute_request.approved_by
    approved_at = execute_request.approved_at
    
    # Validate package
    try:
        _validate_create_package(package)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Package validation failed: {str(e)}"
        )
    
    # Validate required fields
    package_id = package.get("package_id")
    if not package_id:
        raise HTTPException(
            status_code=400,
            detail="package_id is required in package"
        )
    
    if not project_key:
        raise HTTPException(
            status_code=400,
            detail="project_key is required"
        )
    
    # Load configuration
    try:
        config = JiraWriteBackConfig.from_env()
    except ValueError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Configuration error: {str(e)}"
        )
    
    # Initialize clients
    jira_client = JiraClient(
        base_url=config.JIRA_BASE_URL,
        username=config.JIRA_USERNAME,
        api_token=config.JIRA_API_TOKEN
    )
    audit_logger = AuditLogger()
    
    # Extract BA output from package
    requirements = package.get("requirements", [])
    requirements = sorted(requirements, key=lambda r: r.get("id", ""))
    
    # Infer issue_type from package if not provided
    if not issue_type:
        if requirements and len(requirements) > 0:
            first_req = requirements[0]
            issue_type = first_req.get("ticket_type")
        if not issue_type:
            issue_type = "Story"  # Default fallback
    
    # Determine summary
    if execute_request.summary:
        summary = execute_request.summary
    elif requirements:
        first_req_summary = requirements[0].get("summary", "")
        summary = f"BA Package {package_id}: {first_req_summary}"
    else:
        summary = f"BA Package {package_id}"
    
    # Get gap and risk analysis
    gap_analysis = package.get("gap_analysis")
    risk_analysis = package.get("risk_analysis")
    
    # Use original_input for "preserved original" section
    original_input = package.get("original_input", "")
    
    # Map BA output to Jira preview (same logic as dry-run)
    proposed_acceptance_criteria = _extract_acceptance_criteria_from_requirements(requirements)
    proposed_description = _extract_description_from_requirements(
        requirements=requirements,
        package_id=package_id,
        jira_summary=summary,
        current_jira_description=original_input,
        gap_analysis=gap_analysis,
        risk_analysis=risk_analysis
    )
    
    # Recompute checksum to verify it matches
    computed_checksum = _compute_create_checksum(
        project_key=project_key,
        issue_type=issue_type,
        summary=summary,
        proposed_description=proposed_description,
        proposed_acceptance_criteria=proposed_acceptance_criteria,
        package_id=package_id
    )
    
    if computed_checksum != expected_checksum:
        raise HTTPException(
            status_code=400,
            detail=f"Checksum mismatch. Expected {expected_checksum}, computed {computed_checksum}"
        )
    
    # Check idempotency
    existing_issue_key = _check_create_idempotency(jira_client, package_id, expected_checksum)
    if existing_issue_key:
        # Already created - skip and log
        audit_logger.log_event({
            "package_id": package_id,
            "jira_issue_key": existing_issue_key,
            "fields_modified": [],
            "approved_by": approved_by,
            "executed_at": datetime.now().isoformat(),
            "checksum": expected_checksum,
            "result": "skipped"
        })
        
        # Record usage event (skipped = success, 0 tickets created)
        end_time_ms = int(time.time() * 1000)
        duration_ms = end_time_ms - start_time_ms
        _record_usage_event(
            tenant_id=tenant_id,
            user_id=user_id,
            agent="jira-writeback-agent",
            source="ui_execute",
            jira_ticket_count=0,  # Skipped, no new tickets
            input_char_count=input_char_count,
            success=True,
            error_code=None,
            run_id=run_id,
            duration_ms=duration_ms
        )
        
        return CreateExecuteResponse(
            created_issue_key=existing_issue_key,
            result="skipped",
            fields_set=[],
            comment_id=None,
            checksum=expected_checksum,
            usage=usage_data
        )
    
    # Create the issue
    fields_set = []
    comment_id = None
    
    try:
        # Convert description to ADF format
        description_adf = _text_to_adf(proposed_description)
        
        # Prepare labels
        labels = [f"reqpkg_{package_id}"]
        
        # Create issue
        create_response = jira_client.create_issue(
            project_key=project_key,
            issue_type=issue_type,
            summary=summary,
            description_adf=description_adf,
            acceptance_criteria=proposed_acceptance_criteria if proposed_acceptance_criteria else None,
            acceptance_criteria_field_id=config.JIRA_ACCEPTANCE_CRITERIA_FIELD_ID,
            labels=labels
        )
        
        created_issue_key = create_response.get("key")
        if not created_issue_key:
            raise JiraClientError("Created issue response missing key")
        
        fields_set.append("description")
        if proposed_acceptance_criteria and config.JIRA_ACCEPTANCE_CRITERIA_FIELD_ID:
            fields_set.append("acceptance_criteria")
        fields_set.append("labels")
        
        # Add audit comment
        comment_text = _generate_comment_preview(
            package_id=package_id,
            approved_by=approved_by,
            approved_at=approved_at,
            checksum=expected_checksum
        )
        
        comment_response = jira_client.add_comment(created_issue_key, comment_text)
        comment_id = comment_response.get("id")
        
        # Log audit event
        audit_logger.log_event({
            "package_id": package_id,
            "jira_issue_key": created_issue_key,
            "fields_modified": fields_set,
            "approved_by": approved_by,
            "executed_at": datetime.now().isoformat(),
            "checksum": expected_checksum,
            "result": "success"
        })
        
        # Record usage event (success - 1 ticket created)
        end_time_ms = int(time.time() * 1000)
        duration_ms = end_time_ms - start_time_ms
        _record_usage_event(
            tenant_id=tenant_id,
            user_id=user_id,
            agent="jira-writeback-agent",
            source="ui_execute",
            jira_ticket_count=1,  # 1 ticket created
            input_char_count=input_char_count,
            success=True,
            error_code=None,
            run_id=run_id,
            duration_ms=duration_ms
        )
        
        # ============================================================================
        # NOTE: Trial consumption REMOVED - Flask app handles trial consumption
        # after successful agent execution. This agent is execution-only.
        # ============================================================================
        
        return CreateExecuteResponse(
            created_issue_key=created_issue_key,
            result="success",
            fields_set=fields_set,
            comment_id=comment_id,
            checksum=expected_checksum,
            usage=usage_data
        )
        
    except HTTPException:
        # Re-raise HTTP exceptions (validation errors, etc.)
        # Record usage event for HTTP errors
        end_time_ms = int(time.time() * 1000)
        duration_ms = end_time_ms - start_time_ms
        if tenant_id:
            _record_usage_event(
                tenant_id=tenant_id,
                user_id=user_id,
                agent="jira-writeback-agent",
                source="ui_execute",
                jira_ticket_count=0,
                input_char_count=input_char_count,
                success=False,
                error_code="VALIDATION",
                run_id=run_id,
                duration_ms=duration_ms
            )
        raise
    except JiraClientError as e:
        # Record usage event for Jira errors
        end_time_ms = int(time.time() * 1000)
        duration_ms = end_time_ms - start_time_ms
        error_code = "JIRA_5XX"  # Default for JiraClientError
        error_str = str(e).lower()
        if "401" in error_str or "403" in error_str or "unauthorized" in error_str or "forbidden" in error_str:
            error_code = "JIRA_AUTH"
        elif "400" in error_str or "404" in error_str or "422" in error_str:
            error_code = "JIRA_4XX"
        
        if tenant_id:
            _record_usage_event(
                tenant_id=tenant_id,
                user_id=user_id,
                agent="jira-writeback-agent",
                source="ui_execute",
                jira_ticket_count=0,
                input_char_count=input_char_count,
                success=False,
                error_code=error_code,
                run_id=run_id,
                duration_ms=duration_ms
            )
        
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create Jira issue: {str(e)}"
        )
    except Exception as e:
        # Record usage event for unexpected errors
        end_time_ms = int(time.time() * 1000)
        duration_ms = end_time_ms - start_time_ms
        if tenant_id:
            _record_usage_event(
                tenant_id=tenant_id,
                user_id=user_id,
                agent="jira-writeback-agent",
                source="ui_execute",
                jira_ticket_count=0,
                input_char_count=input_char_count,
                success=False,
                error_code="UNKNOWN",
                run_id=run_id,
                duration_ms=duration_ms
            )
        
        raise HTTPException(
            status_code=500,
            detail=f"Unexpected error during Jira issue creation: {str(e)}"
        )


# ============================================================================
# Metadata Endpoints
# ============================================================================

@router.get("/api/v1/jira/meta/projects")
async def get_projects() -> List[Dict[str, str]]:
    """
    Get list of Jira projects visible to the credentials.
    
    Returns:
        List of project dictionaries with 'key' and 'name'
    """
    try:
        config = JiraWriteBackConfig.from_env()
    except ValueError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Configuration error: {str(e)}"
        )
    
    jira_client = JiraClient(
        base_url=config.JIRA_BASE_URL,
        username=config.JIRA_USERNAME,
        api_token=config.JIRA_API_TOKEN
    )
    
    try:
        projects = jira_client.get_projects()
        return projects
    except JiraClientError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get projects: {str(e)}"
        )


@router.get("/api/v1/jira/meta/issue-types")
async def get_issue_types(project_key: str) -> List[Dict[str, Any]]:
    """
    Get issue types valid for a project.
    
    Args:
        project_key: Jira project key (query parameter)
        
    Returns:
        List of issue type dictionaries with 'id' and 'name'
    """
    if not project_key:
        raise HTTPException(
            status_code=400,
            detail="project_key query parameter is required"
        )
    
    try:
        config = JiraWriteBackConfig.from_env()
    except ValueError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Configuration error: {str(e)}"
        )
    
    jira_client = JiraClient(
        base_url=config.JIRA_BASE_URL,
        username=config.JIRA_USERNAME,
        api_token=config.JIRA_API_TOKEN
    )
    
    try:
        issue_types = jira_client.get_issue_types(project_key)
        return issue_types
    except JiraClientError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get issue types for project {project_key}: {str(e)}"
        )
