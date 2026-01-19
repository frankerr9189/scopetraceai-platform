"""
POST /analyze endpoint for requirement analysis.
"""
from datetime import datetime
import re
import time
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional, List, Union, Tuple
from app.models.package import RequirementPackage, Attachment
from app.agent.analyst import BusinessRequirementAnalyst, AnalysisError
from app.api.presentation import generate_readable_summary
from app.config import settings
from app.services.jira_client import JiraClient, JiraClientError, extract_ticket_id_from_text
from app.services.attachment_parser import extract_text_from_attachment, AttachmentParserError

# Input guardrail constants
MAX_REQUIREMENTS_PER_PACKAGE = 100
MAX_FREEFORM_CHARS = 50_000
MAX_DOC_UPLOAD_MB = 15
MAX_TICKETS_PER_RUN = 10
MAX_CHARS_PER_TICKET = 10_000


class AnalyzeRequest(BaseModel):
    """Request model for requirement analysis (JSON body)."""
    
    input_text: str = Field(
        ...,
        description="Human-written requirements to analyze (e.g., Jira ticket, plain text)"
    )
    source: str = Field(
        default="",
        description="Optional source identifier (e.g., 'jira', 'email')"
    )
    context: str = Field(
        default="",
        description="Optional context for the analysis"
    )


async def _extract_form_data(request: Request) -> Tuple[str, str, str, List[UploadFile]]:
    """Extract form data from multipart/form-data request."""
    form = await request.form()
    
    # Extract text fields
    input_text_field = form.get("input_text")
    if not input_text_field:
        raise HTTPException(status_code=400, detail="input_text is required")
    input_text = input_text_field if isinstance(input_text_field, str) else str(input_text_field)
    
    source_field = form.get("source", "")
    source = source_field if isinstance(source_field, str) else str(source_field) if source_field else ""
    
    context_field = form.get("context", "")
    context = context_field if isinstance(context_field, str) else str(context_field) if context_field else ""
    
    # Extract file attachments
    attachments = []
    attachment_files = form.getlist("attachments")
    for file_item in attachment_files:
        if isinstance(file_item, UploadFile):
            attachments.append(file_item)
    
    return input_text, source, context, attachments


def generate_meta(package: RequirementPackage, source: Optional[str] = None) -> Dict[str, Any]:
    """
    Generate meta information from RequirementPackage.
    
    Args:
        package: Requirement package
        source: Optional source identifier from request
        
    Returns:
        Dictionary containing meta information
    """
    # Get confidence from metadata or default
    confidence = package.metadata.get("confidence", "medium") if package.metadata else "medium"
    
    # Determine if human review is required
    requires_human_review = (
        any(req.inferred_logic for req in package.requirements) or
        any(req.ambiguities for req in package.requirements) or
        bool(package.gap_analysis.gaps) or
        bool(package.gap_analysis.missing_information) or
        package.risk_analysis.risk_level in ["high", "critical"] or
        bool(package.risk_analysis.audit_concerns) or
        (package.metadata and package.metadata.get("requires_human_review", False))
    )
    
    # Get source from metadata or request
    source_value = source or (package.metadata.get("source") if package.metadata else None) or "unknown"
    
    return {
        "package_id": package.package_id,
        "agent_name": "AI Sr Business Requirement Analyst",
        "agent_version": settings.api_version,
        "confidence": confidence,
        "requires_human_review": requires_human_review,
        "source": source_value,
        "generated_at": datetime.now().isoformat()
    }


def generate_summary(package: RequirementPackage) -> Dict[str, Any]:
    """
    Generate summary statistics from RequirementPackage.
    
    Args:
        package: Requirement package
        
    Returns:
        Dictionary containing summary statistics
    """
    total_requirements = len(package.requirements)
    parent_requirements = len([req for req in package.requirements if req.parent_id is None])
    child_requirements = len([req for req in package.requirements if req.parent_id is not None])
    inferred_requirements = len([req for req in package.requirements if req.inferred_logic])
    
    # Count high-risk items
    high_risk_items = 0
    if package.risk_analysis.risk_level in ["high", "critical"]:
        high_risk_items += 1
    high_risk_items += len([req for req in package.requirements 
                           if any("high" in risk.lower() or "critical" in risk.lower() 
                                 for risk in req.risks)])
    
    # Count gaps
    gap_count = len(package.gap_analysis.gaps) + len(package.gap_analysis.missing_information)
    for req in package.requirements:
        gap_count += len(req.gaps)
    
    return {
        "total_requirements": total_requirements,
        "parent_requirements": parent_requirements,
        "child_requirements": child_requirements,
        "inferred_requirements": inferred_requirements,
        "high_risk_items": high_risk_items,
        "gap_count": gap_count,
        "status": "IN_REVIEW"
    }


class AnalyzeResponse(BaseModel):
    """Response model containing meta, summary, authoritative package, and readable summary."""
    
    meta: Dict[str, Any] = Field(
        ...,
        description="Metadata about the analysis (package ID, agent info, timestamps)"
    )
    summary: Dict[str, Any] = Field(
        ...,
        description="Summary statistics derived from the requirement package"
    )
    package: RequirementPackage = Field(
        ...,
        description="Authoritative requirement package (audit-grade JSON)"
    )
    readable_summary: Dict[str, Any] = Field(
        ...,
        description="Human-readable presentation layer (derived, non-authoritative)"
    )


router = APIRouter()


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_requirements(
    request: Request
) -> AnalyzeResponse:
    """
    Analyze and normalize human-written business requirements.
    
    Supports both JSON and multipart/form-data requests.
    - JSON: For requests without attachments
    - multipart/form-data: For requests with file attachments
    
    Takes human-written requirements (e.g., Jira tickets or plain text) and
    normalizes them into clear, audit-ready business requirements with defined scope.
    
    The analyst will:
    - Preserve original business intent
    - Decompose vague/compound requests into atomic business requirements
    - Flag all inferred logic
    - Identify gaps, risks, and ambiguities
    - Return structured, versioned JSON suitable for audit evidence
    
    Args:
        request: FastAPI Request object
        json_request: Optional JSON request body (when Content-Type is application/json)
        
    Returns:
        AnalyzeResponse containing:
        - meta: Metadata about the analysis
        - summary: Summary statistics
        - package: Authoritative RequirementPackage (unchanged)
        - readable_summary: Human-readable presentation layer (derived)
        
    Raises:
        HTTPException: If analysis fails or validation errors occur
    """
    # Capture start time for usage tracking
    start_time_ms = int(time.time() * 1000)
    
    # ============================================================================
    # TRUST BOUNDARY: This agent is a trusted internal executor.
    # All policy enforcement (subscription, plan tiers, trials) happens in Flask app.
    # This agent ONLY validates the internal service key.
    # ============================================================================
    # Import internal auth middleware
    try:
        from app.middleware.internal_auth import verify_internal_service_key, extract_tenant_context_for_logging
    except ImportError:
        # Fallback if middleware not found
        import logging
        logger = logging.getLogger(__name__)
        logger.error("Internal auth middleware not found - agent will reject requests")
        raise HTTPException(
            status_code=500,
            detail="Internal service authentication not configured"
        )
    import logging
    logger = logging.getLogger(__name__)
    
    # Verify internal service key (required - this is the ONLY auth enforcement)
    await verify_internal_service_key(request)
    
    # Extract tenant/user context for logging only (optional, not for enforcement)
    tenant_id, user_id = extract_tenant_context_for_logging(request)
    if tenant_id:
        logger.info(f"Processing request (tenant={tenant_id}, user={user_id})")
    
    # ============================================================================
    # NOTE: Entitlement checks (subscription, plan tiers, trials) are REMOVED.
    # Flask app enforces all policy before calling this agent.
    # ============================================================================
    
    # Determine if request is JSON or FormData
    content_type = request.headers.get("content-type", "").lower()
    
    # Log input source for debugging (tenant_id is guaranteed to be present at this point)
    logger.info(f"Processing analyze request: tenant_id={tenant_id}, content_type={content_type}")
    
    if "application/json" in content_type:
        # JSON request (no attachments)
        try:
            json_body = await request.json()
            json_request = AnalyzeRequest(**json_body)
            input_text = json_request.input_text
            source = json_request.source or ""
            context = json_request.context or ""
            attachments = []
            logger.info(f"JSON request parsed: source={source}, input_text_length={len(input_text)}, tenant_id={tenant_id}")
        except Exception as e:
            raise HTTPException(
                status_code=400, 
                detail=f"Failed to parse JSON request: {str(e)}"
            )
    else:
        # FormData request (may have attachments)
        try:
            input_text, source, context, attachments = await _extract_form_data(request)
            logger.info(f"FormData request parsed: source={source}, input_text_length={len(input_text)}, attachments={len(attachments)}, tenant_id={tenant_id}")
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=400, 
                detail=f"Failed to parse form data: {str(e)}"
            )
    
    # PHASE 1 ATTACHMENT SUPPORT: Validation
    # If free-form text is empty and attachments exist, return validation error
    if not input_text.strip() and attachments:
        raise HTTPException(
            status_code=400,
            detail="Describe scope in text. Attachments are supporting materials only."
        )
    
    # Guardrail: Check free-form input length
    if len(input_text) > MAX_FREEFORM_CHARS:
        raise HTTPException(
            status_code=400,
            detail=f"Free-form input exceeds {MAX_FREEFORM_CHARS:,} characters. Reduce text or upload a document."
        )
    
    # PHASE 1 ATTACHMENT SUPPORT: Parse attachments
    package_attachments = []
    attachment_context_parts = []
    
    for attachment_file in attachments:
        try:
            # Read file content
            file_content = await attachment_file.read()
            filename = attachment_file.filename or "unknown"
            mime_type = attachment_file.content_type or "application/octet-stream"
            
            # Guardrail: Check file size (convert bytes to MB)
            file_size_mb = len(file_content) / (1024 * 1024)
            if file_size_mb > MAX_DOC_UPLOAD_MB:
                raise HTTPException(
                    status_code=413,
                    detail=f"Upload too large ({file_size_mb:.1f}MB). Max supported is {MAX_DOC_UPLOAD_MB}MB."
                )
            
            # Ensure file_content is bytes
            if not isinstance(file_content, bytes):
                file_content = bytes(file_content)
            
            # Extract text from attachment
            extracted_text = extract_text_from_attachment(
                file_content=file_content,
                filename=filename,
                mime_type=mime_type
            )
            
            # Ensure extracted_text is a string (not bytes)
            if isinstance(extracted_text, bytes):
                # Try to decode as UTF-8, fallback to latin-1 with error handling
                try:
                    extracted_text = extracted_text.decode('utf-8', errors='replace')
                except Exception:
                    extracted_text = extracted_text.decode('latin-1', errors='replace')
            elif not isinstance(extracted_text, str):
                extracted_text = str(extracted_text)
            
            # Sanitize extracted_text to ensure it's valid UTF-8
            # Remove or replace any invalid UTF-8 sequences
            try:
                extracted_text.encode('utf-8')
            except UnicodeEncodeError:
                # If encoding fails, replace invalid characters
                extracted_text = extracted_text.encode('utf-8', errors='replace').decode('utf-8', errors='replace')
            
            # Create attachment model (only store extracted text, not raw bytes)
            attachment = Attachment(
                filename=filename,
                mime_type=mime_type,
                extracted_text=extracted_text
            )
            package_attachments.append(attachment)
            
            # Add to context for agent (read-only contextual input)
            # Limit context length to avoid token limits
            context_text = extracted_text[:2000] + "..." if len(extracted_text) > 2000 else extracted_text
            attachment_context_parts.append(
                f"[Supporting Material: {filename}]\n{context_text}"
            )
        except AttachmentParserError as e:
            # Log error but don't fail the entire request
            # Attachments are optional supporting materials
            raise HTTPException(
                status_code=400,
                detail=f"Failed to parse attachment {attachment_file.filename}: {str(e)}"
            )
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Unexpected error processing attachment {attachment_file.filename}: {str(e)}"
            )
    
    # Combine attachment context with existing context
    if attachment_context_parts:
        attachment_context = "\n\n---\n\n".join(attachment_context_parts)
        if context:
            context_text = f"{context}\n\n---\n\n{attachment_context}"
        else:
            context_text = attachment_context
    else:
        context_text = context if context else None
    
    analyst = BusinessRequirementAnalyst()
    
    # Determine primary input text based on source
    # When source == "jira", Jira ticket description is authoritative and overrides manual input_text
    # This ensures analysis is always generated from the current Jira ticket state, not stale manual text
    primary_input_text = input_text
    jira_context = None
    input_limits_metadata = {
        "max_tickets_per_run": MAX_TICKETS_PER_RUN,
        "max_chars_per_ticket": MAX_CHARS_PER_TICKET,
        "tickets_received": 0,
        "tickets_processed": 0,
        "tickets_rejected": 0,
        "tickets_truncated": 0,
        "truncation_strategy": "head"
    }
    
    if source and source.lower() == "jira":
        try:
            # Extract ticket ID from input text
            ticket_id = extract_ticket_id_from_text(input_text)
            if ticket_id:
                # Get Jira credentials from database using tenant_id
                jira_creds = None
                if tenant_id:
                    try:
                        import sys
                        import os
                        # Calculate absolute path to testing agent backend
                        current_file = os.path.abspath(__file__)
                        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(current_file))))
                        backend_path = os.path.join(project_root, "ai-testing-agent", "backend")
                        
                        if os.path.exists(backend_path):
                            # Save current directory and change to backend for reliable imports
                            original_cwd = os.getcwd()
                            try:
                                if backend_path not in sys.path:
                                    sys.path.insert(0, backend_path)
                                os.chdir(backend_path)
                                
                                # Clear cached modules to force re-import from new location
                                modules_to_clear = [k for k in sys.modules.keys() if k.startswith(('db', 'models', 'services.integrations', 'utils.encryption'))]
                                for mod in modules_to_clear:
                                    del sys.modules[mod]
                                
                                from db import get_db
                                from services.integrations import get_jira_integration
                                
                                db = next(get_db())
                                try:
                                    jira_creds = get_jira_integration(db, str(tenant_id))
                                finally:
                                    db.close()
                            finally:
                                os.chdir(original_cwd)
                    except Exception as e:
                        import logging
                        logger = logging.getLogger(__name__)
                        logger.warning(f"Failed to get Jira credentials from database: {str(e)}", exc_info=True)
                        # Fall through to try environment variables as fallback
                
                # Initialize JiraClient with credentials from DB or env vars
                if jira_creds:
                    jira_client = JiraClient(
                        jira_base_url=jira_creds["base_url"],
                        jira_email=jira_creds["email"],
                        jira_api_token=jira_creds["api_token"]
                    )
                else:
                    # Fallback to environment variables (for backward compatibility)
                    jira_client = JiraClient()
                
                jira_context_data = jira_client.build_jira_context(ticket_id)
                
                # Count total tickets (parent + sub-tickets)
                parent_ticket = jira_context_data["jira_context"]["parent_ticket"]
                sub_tickets = jira_context_data["jira_context"].get("sub_tickets", [])
                total_tickets = 1 + len(sub_tickets)  # Parent + sub-tickets
                input_limits_metadata["tickets_received"] = total_tickets
                
                # Guardrail: Check ticket count
                if total_tickets > MAX_TICKETS_PER_RUN:
                    input_limits_metadata["tickets_rejected"] = total_tickets
                    raise HTTPException(
                        status_code=400,
                        detail=f"Run exceeds maximum allowed tickets ({MAX_TICKETS_PER_RUN}). Please reduce scope."
                    )
                
                # Jira mode: Use ONLY parent ticket description as authoritative input
                # payload.input_text is ignored - this prevents analysis from stale manual text
                ticket_summary = parent_ticket.get('summary', '') or ''
                ticket_description = parent_ticket.get('description', '') or ''
                
                # Normalize and truncate ticket content deterministically
                # Combine summary and description, normalize whitespace
                combined_text = f"{ticket_summary}\n\n{ticket_description}"
                # Normalize: trim leading/trailing whitespace, collapse repeated whitespace
                normalized_text = re.sub(r'\s+', ' ', combined_text.strip())
                
                # Truncate if exceeds limit
                tickets_truncated = 0
                if len(normalized_text) > MAX_CHARS_PER_TICKET:
                    normalized_text = normalized_text[:MAX_CHARS_PER_TICKET]
                    tickets_truncated = 1
                    input_limits_metadata["tickets_truncated"] = tickets_truncated
                
                primary_input_text = normalized_text
                input_limits_metadata["tickets_processed"] = 1  # Only parent ticket is processed
                
                # Note: We no longer include acceptance criteria as they are not part of scope definition
                
                # Build context string for LLM
                context_parts = []
                if sub_tickets:
                    sub_count = len(sub_tickets)
                    context_parts.append(f"Note: {sub_count} sub-ticket(s) detected — used as contextual signal only")
                if jira_context_data["jira_context"].get("attachments"):
                    context_parts.append("Note: Attachments detected but not analyzed")
                
                if context_parts:
                    context_text = "\n".join(context_parts)
                
                # Store full context for readable_summary enhancement
                jira_context = jira_context_data
            else:
                # If ticket ID cannot be extracted, raise error (don't fall back to manual input)
                raise HTTPException(
                    status_code=400,
                    detail="Jira mode requires a valid ticket ID in input_text (e.g., ATA-36)"
                )
        except HTTPException:
            # Re-raise HTTP exceptions (including our 400 for ticket count)
            raise
        except JiraClientError as e:
            # Jira fetch failed - raise error instead of falling back to manual input
            # This enforces that Jira mode requires successful Jira fetch
            raise HTTPException(
                status_code=500,
                detail=f"Failed to fetch Jira ticket: {str(e)}"
            )
        except Exception as e:
            # Unexpected error during Jira fetch
            raise HTTPException(
                status_code=500,
                detail=f"Unexpected error fetching Jira ticket: {str(e)}"
            )
    
    # Determine source type and counts for usage tracking
    usage_source = "text"
    jira_ticket_count = 0
    input_char_count = len(input_text)
    
    if source and source.lower() == "jira":
        usage_source = "jira"
        # Count will be set when we process Jira tickets
    
    try:
        # Extract attachment context for agent (read-only contextual input)
        attachment_context_for_agent = None
        if attachment_context_parts:
            attachment_context_for_agent = "\n\n---\n\n".join(attachment_context_parts)
        
        # Pass primary_input_text to agent (Jira ticket description in Jira mode, manual input otherwise)
        package = await analyst.analyze(
            input_text=primary_input_text,
            source=source if source else None,
            context=context_text,
            attachment_context=attachment_context_for_agent
        )
        
        # PHASE 1 ATTACHMENT SUPPORT: Store attachments in package
        package.attachments = package_attachments
        
        # Guardrail: Check requirements count
        requirements_count = len(package.requirements)
        if requirements_count > MAX_REQUIREMENTS_PER_PACKAGE:
            raise HTTPException(
                status_code=400,
                detail=f"Package has {requirements_count} requirements. Max supported is {MAX_REQUIREMENTS_PER_PACKAGE}. Split into smaller runs."
            )
        
        # Store jira_context in package metadata for readable_summary
        if jira_context and package.metadata:
            package.metadata["jira_context"] = jira_context["jira_context"]
            # Get ticket count from jira_context
            if "jira_context" in jira_context:
                parent_ticket = jira_context["jira_context"].get("parent_ticket")
                sub_tickets = jira_context["jira_context"].get("sub_tickets", [])
                jira_ticket_count = 1 + len(sub_tickets) if parent_ticket else 0
        
        # Store input_limits in package metadata (audit trail)
        if package.metadata is None:
            package.metadata = {}
        package.metadata["input_limits"] = input_limits_metadata
        
        # Generate meta and summary (derived from package, presentation-only)
        meta = generate_meta(package, source=source if source else None)
        summary = generate_summary(package)
        
        # Generate human-readable summary (presentation-only, does not modify package)
        readable_summary = generate_readable_summary(package)
        
        # Calculate duration
        end_time_ms = int(time.time() * 1000)
        duration_ms = end_time_ms - start_time_ms
        
        # Create Run record in database for Run History
        if tenant_id:
            try:
                import sys
                import os
                import logging
                logger = logging.getLogger(__name__)
                
                # Calculate absolute path to testing agent backend
                current_file = os.path.abspath(__file__)
                project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(current_file))))
                backend_path = os.path.join(project_root, "ai-testing-agent", "backend")
                
                if os.path.exists(backend_path):
                    # Verify DATABASE_URL is PostgreSQL
                    db_url = os.getenv("DATABASE_URL")
                    if db_url and (db_url.startswith("postgresql://") or db_url.startswith("postgres://")):
                        # Save current directory and change to backend for reliable imports
                        original_cwd = os.getcwd()
                        try:
                            if backend_path not in sys.path:
                                sys.path.insert(0, backend_path)
                            os.chdir(backend_path)
                            
                            from db import get_db
                            from services.persistence import save_run
                            
                            db = next(get_db())
                            try:
                                # Generate run_id (use package_id as run_id for BA runs)
                                run_id = package.package_id
                                
                                # Generate run summary text (for run history display)
                                requirements_count = len(package.requirements)
                                if jira_ticket_count > 0:
                                    run_summary_text = f"Generated requirements package from {jira_ticket_count} Jira ticket{'s' if jira_ticket_count > 1 else ''} ({requirements_count} requirements)"
                                else:
                                    run_summary_text = f"Generated requirements package ({requirements_count} requirements)"
                                
                                # Count output items (requirements)
                                output_item_count = requirements_count
                                
                                # Get created_by from request header if available
                                created_by_header = request.headers.get("X-Actor", None)
                                
                                # Save run
                                save_run(
                                    db=db,
                                    run_id=run_id,
                                    source_type=usage_source,  # "jira" or "text"
                                    status="generated",
                                    ticket_count=jira_ticket_count,
                                    created_by=created_by_header,
                                    environment=os.getenv('ENVIRONMENT', 'development').lower(),
                                    tenant_id=str(tenant_id),
                                    agent="ba-agent",
                                    run_kind="requirements",
                                    artifact_type="requirement_package",
                                    artifact_id=package.package_id,
                                    summary=run_summary_text,
                                    input_ticket_count=jira_ticket_count,
                                    output_item_count=output_item_count
                                )
                                logger.info(f"Run record created for BA agent: run_id={run_id}, tenant_id={tenant_id}")
                            finally:
                                db.close()
                        finally:
                            os.chdir(original_cwd)
            except Exception as run_error:
                # Log but don't fail the request if run creation fails
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"Failed to create run record: {str(run_error)}", exc_info=True)
        
        # Record usage event (success)
        if tenant_id:
            try:
                # Import usage service (from testing agent backend)
                # Environment already loaded at startup in main.py
                import sys
                import os
                import logging
                logger = logging.getLogger(__name__)
                
                logger.info(f"Attempting to record usage event for tenant_id={tenant_id}, agent=requirements_ba, source={usage_source}")
                
                # Calculate absolute path to testing agent backend
                current_file = os.path.abspath(__file__)
                # Go up: app/api/analyze.py -> app/api -> app -> ai-sr-business-req-analyst -> appscopetraceai -> ai-testing-agent/backend
                project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(current_file))))
                backend_path = os.path.join(project_root, "ai-testing-agent", "backend")
                
                if not os.path.exists(backend_path):
                    logger.warning(f"Testing agent backend not found at {backend_path}, skipping usage tracking")
                else:
                    # Verify DATABASE_URL is set and is PostgreSQL (env already loaded at startup)
                    db_url = os.getenv("DATABASE_URL")
                    if not db_url:
                        logger.warning("DATABASE_URL not set, cannot record usage event")
                    elif not (db_url.startswith("postgresql://") or db_url.startswith("postgres://")):
                        logger.warning(f"DATABASE_URL is not PostgreSQL: {db_url[:50]}..., skipping usage tracking")
                    else:
                        logger.debug(f"Connecting to PostgreSQL database for usage tracking")
                        if backend_path not in sys.path:
                            sys.path.insert(0, backend_path)
                        
                        from db import get_db
                        from services.usage import record_usage_event
                        
                        db = next(get_db())
                        try:
                            record_usage_event(
                                db=db,
                                tenant_id=str(tenant_id),
                                user_id=str(user_id) if user_id else None,
                                agent="requirements_ba",
                                source=usage_source,
                                jira_ticket_count=jira_ticket_count,
                                input_char_count=input_char_count,
                                success=True,
                                duration_ms=duration_ms
                            )
                            logger.info(f"Successfully recorded usage event for tenant {tenant_id}, agent=requirements_ba, source={usage_source}, jira_tickets={jira_ticket_count}, duration_ms={duration_ms}")
                        finally:
                            db.close()
            except Exception as usage_error:
                # Log but don't fail the request if usage tracking fails
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Failed to record usage event: {str(usage_error)}", exc_info=True)
        
        # ============================================================================
        # NOTE: Trial consumption REMOVED - Flask app handles trial consumption
        # after successful agent execution. This agent is execution-only.
        # ============================================================================
        
        return AnalyzeResponse(
            meta=meta,
            summary=summary,
            package=package,
            readable_summary=readable_summary
        )
    except AnalysisError as e:
        # Record usage event (failure)
        error_code = "analysis_error"
        end_time_ms = int(time.time() * 1000)
        duration_ms = end_time_ms - start_time_ms
        
        if tenant_id:
            try:
                import sys
                import os
                import logging
                logger = logging.getLogger(__name__)
                
                # Calculate absolute path to testing agent backend
                current_file = os.path.abspath(__file__)
                project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(current_file))))
                backend_path = os.path.join(project_root, "ai-testing-agent", "backend")
                
                if not os.path.exists(backend_path):
                    logger.warning(f"Testing agent backend not found at {backend_path}, skipping usage tracking")
                else:
                    # Verify DATABASE_URL is set and is PostgreSQL (env already loaded at startup)
                    db_url = os.getenv("DATABASE_URL")
                    if db_url and (db_url.startswith("postgresql://") or db_url.startswith("postgres://")):
                        if backend_path not in sys.path:
                            sys.path.insert(0, backend_path)
                        
                        from db import get_db
                        from services.usage import record_usage_event
                        
                        db = next(get_db())
                        try:
                            record_usage_event(
                                db=db,
                                tenant_id=str(tenant_id),
                                user_id=str(user_id) if user_id else None,
                                agent="requirements_ba",
                                source=usage_source,
                                jira_ticket_count=jira_ticket_count,
                                input_char_count=input_char_count,
                                success=False,
                                error_code=error_code,
                                duration_ms=duration_ms
                            )
                        finally:
                            db.close()
            except Exception as usage_err:
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"Failed to record usage event (analysis error): {str(usage_err)}", exc_info=True)
        
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )
    except HTTPException:
        # Re-raise HTTP exceptions (validation errors, etc.)
        raise
    except Exception as e:
        # Record usage event (failure)
        error_code = "unexpected_error"
        end_time_ms = int(time.time() * 1000)
        duration_ms = end_time_ms - start_time_ms
        
        if tenant_id:
            try:
                import sys
                import os
                import logging
                logger = logging.getLogger(__name__)
                
                # Calculate absolute path to testing agent backend
                current_file = os.path.abspath(__file__)
                project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(current_file))))
                backend_path = os.path.join(project_root, "ai-testing-agent", "backend")
                
                if not os.path.exists(backend_path):
                    logger.warning(f"Testing agent backend not found at {backend_path}, skipping usage tracking")
                else:
                    # Verify DATABASE_URL is set and is PostgreSQL (env already loaded at startup)
                    db_url = os.getenv("DATABASE_URL")
                    if db_url and (db_url.startswith("postgresql://") or db_url.startswith("postgres://")):
                        if backend_path not in sys.path:
                            sys.path.insert(0, backend_path)
                        
                        from db import get_db
                        from services.usage import record_usage_event
                        
                        db = next(get_db())
                        try:
                            record_usage_event(
                                db=db,
                                tenant_id=str(tenant_id),
                                user_id=str(user_id) if user_id else None,
                                agent="requirements_ba",
                                source=usage_source,
                                jira_ticket_count=jira_ticket_count,
                                input_char_count=input_char_count,
                                success=False,
                                error_code=error_code,
                                duration_ms=duration_ms
                            )
                        finally:
                            db.close()
            except Exception as usage_err:
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"Failed to record usage event (unexpected error): {str(usage_err)}", exc_info=True)
        
        raise HTTPException(
            status_code=500,
            detail=f"Unexpected error: {str(e)}"
        )

