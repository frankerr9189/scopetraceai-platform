"""
Persistence helpers for storing artifacts and run metadata.
"""
import os
import json
import hashlib
import uuid
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, Union, Union
from sqlalchemy.orm import Session
from dotenv import load_dotenv

# Load environment variables
try:
    load_dotenv()
except (PermissionError, OSError):
    pass

# Get artifacts directory from environment
ARTIFACTS_DIR = os.getenv("ARTIFACTS_DIR", "./data/artifacts")

# Ensure artifacts directory exists
if not os.path.exists(ARTIFACTS_DIR):
    os.makedirs(ARTIFACTS_DIR, exist_ok=True)


def ensure_run_dir(run_id: str) -> str:
    """
    Ensure run-specific directory exists under ARTIFACTS_DIR.
    
    Args:
        run_id: Run identifier (UUID string)
    
    Returns:
        str: Path to run directory
    """
    run_dir = os.path.join(ARTIFACTS_DIR, run_id)
    if not os.path.exists(run_dir):
        os.makedirs(run_dir, exist_ok=True)
    return run_dir


def compute_sha256_bytes(data: bytes) -> str:
    """
    Compute SHA-256 hash of bytes data.
    
    Args:
        data: Bytes to hash
    
    Returns:
        str: Hexadecimal SHA-256 hash
    """
    return hashlib.sha256(data).hexdigest()


def write_json_artifact(run_id: str, artifact_type: str, obj: Dict[str, Any]) -> Tuple[str, str]:
    """
    Write JSON artifact to disk and return path and SHA-256 hash.
    
    Writes pretty JSON with indent=2 and sorted keys for determinism.
    
    Args:
        run_id: Run identifier
        artifact_type: Type of artifact (e.g., "package", "rtm", "test_plan")
        obj: Python dict to serialize as JSON
    
    Returns:
        Tuple[str, str]: (file_path, sha256_hash)
    """
    # Ensure run directory exists
    run_dir = ensure_run_dir(run_id)
    
    # Generate filename
    filename = f"{artifact_type}.json"
    file_path = os.path.join(run_dir, filename)
    
    # Serialize to JSON with deterministic formatting
    json_bytes = json.dumps(
        obj,
        indent=2,
        sort_keys=True,
        ensure_ascii=False
    ).encode('utf-8')
    
    # Write to file
    with open(file_path, 'wb') as f:
        f.write(json_bytes)
    
    # Compute SHA-256
    sha256 = compute_sha256_bytes(json_bytes)
    
    return file_path, sha256


def save_run(
    db: Session,
    run_id: str,
    source_type: str,
    status: str,
    ticket_count: Optional[int] = None,
    scope_id: Optional[str] = None,
    scope_type: Optional[str] = None,
    logic_version: Optional[str] = None,
    model_name: Optional[str] = None,
    created_by: Optional[str] = None,
    environment: Optional[str] = None,
    tenant_id: Optional[Union[str, "uuid.UUID"]] = None,
    agent: Optional[str] = None,
    run_kind: Optional[str] = None,
    artifact_type: Optional[str] = None,
    artifact_id: Optional[str] = None,
    summary: Optional[str] = None,
    input_ticket_count: Optional[int] = None,
    output_item_count: Optional[int] = None
):
    """
    Save or update a run record in the database.
    
    Args:
        db: Database session
        run_id: Run identifier (UUID string)
        source_type: Source type ("jira" | "freeform" | "document")
        status: Status ("success" | "error")
        ticket_count: Optional ticket count
        scope_id: Optional scope ID
        scope_type: Optional scope type
        logic_version: Optional logic version
        model_name: Optional model name
        created_by: Optional actor/user who created the run
        environment: Optional environment
        tenant_id: Tenant ID (UUID string) - required for new runs
        agent: Agent identifier ('testing-agent' | 'ba-agent')
        run_kind: Run kind ('test_plan' | 'requirements')
        artifact_type: Artifact type ('test_plan' | 'requirement_package')
        artifact_id: Artifact identifier (package_id or run_id)
        summary: Short display text for run list
        input_ticket_count: Number of input tickets/items
        output_item_count: Number of requirements/tests generated
    
    Returns:
        Run: Created or updated Run object
    """
    from models import Run
    import uuid as uuid_module
    
    if not tenant_id:
        raise ValueError("tenant_id is required for save_run")
    
    # Convert tenant_id to UUID if it's a string
    if isinstance(tenant_id, str):
        tenant_id = uuid_module.UUID(tenant_id)
    
    # Check if run exists (tenant-scoped)
    run = db.query(Run).filter(
        Run.run_id == run_id,
        Run.tenant_id == tenant_id
    ).first()
    
    if run:
        # Update existing run
        run.source_type = source_type
        run.status = status
        run.ticket_count = ticket_count
        run.scope_id = scope_id
        run.scope_type = scope_type
        run.logic_version = logic_version
        run.model_name = model_name
        run.created_by = created_by
        run.environment = environment
        # Update new fields if provided
        if agent is not None:
            run.agent = agent
        if run_kind is not None:
            run.run_kind = run_kind
        if artifact_type is not None:
            run.artifact_type = artifact_type
        if artifact_id is not None:
            run.artifact_id = artifact_id
        if summary is not None:
            run.summary = summary
        if input_ticket_count is not None:
            run.input_ticket_count = input_ticket_count
        if output_item_count is not None:
            run.output_item_count = output_item_count
    else:
        # Create new run (review_status defaults to "generated" in model)
        run = Run(
            run_id=run_id,
            tenant_id=tenant_id,
            source_type=source_type,
            status=status,
            ticket_count=ticket_count,
            scope_id=scope_id,
            scope_type=scope_type,
            logic_version=logic_version,
            model_name=model_name,
            created_by=created_by,
            environment=environment,
            review_status="generated",  # Phase 2A: All new runs start as "generated"
            agent=agent or "testing-agent",  # Default to testing-agent for backward compatibility
            run_kind=run_kind or "test_plan",  # Default to test_plan for backward compatibility
            artifact_type=artifact_type,
            artifact_id=artifact_id,
            summary=summary,
            input_ticket_count=input_ticket_count or 0,
            output_item_count=output_item_count or 0
        )
        db.add(run)
    
    db.commit()
    db.refresh(run)
    return run


def save_artifact(
    db: Session,
    run_id: str,
    artifact_type: str,
    path: str,
    sha256: str,
    tenant_id: Optional[Union[str, "uuid.UUID"]] = None
):
    """
    Save artifact metadata to database.
    
    Args:
        db: Database session
        run_id: Run identifier
        artifact_type: Type of artifact
        path: Path to artifact file
        sha256: SHA-256 hash of artifact
        tenant_id: Tenant ID (UUID string) - required for new artifacts
    
    Returns:
        Artifact: Created Artifact object
    """
    from models import Artifact, Run
    import uuid as uuid_module
    
    if not tenant_id:
        raise ValueError("tenant_id is required for save_artifact")
    
    # Convert tenant_id to UUID if it's a string
    if isinstance(tenant_id, str):
        tenant_id = uuid_module.UUID(tenant_id)
    
    # Verify run exists and belongs to tenant (for safety)
    run = db.query(Run).filter(
        Run.run_id == run_id,
        Run.tenant_id == tenant_id
    ).first()
    if not run:
        raise ValueError(f"Run {run_id} not found for tenant {tenant_id}")
    
    # Check if artifact already exists for this run and type (tenant-scoped)
    artifact = db.query(Artifact).filter(
        Artifact.run_id == run_id,
        Artifact.artifact_type == artifact_type,
        Artifact.tenant_id == tenant_id
    ).first()
    
    if artifact:
        # Update existing artifact
        artifact.path = path
        artifact.sha256 = sha256
    else:
        # Create new artifact
        artifact = Artifact(
            tenant_id=tenant_id,
            run_id=run_id,
            artifact_type=artifact_type,
            path=path,
            sha256=sha256
        )
        db.add(artifact)
    
    db.commit()
    db.refresh(artifact)
    return artifact


def get_artifact_path(db: Session, run_id: str, artifact_type: str, tenant_id: Optional[Union[str, uuid.UUID]] = None) -> Optional[str]:
    """
    Get artifact path for a given run and artifact type.
    
    Args:
        db: Database session
        run_id: Run identifier
        artifact_type: Type of artifact
        tenant_id: Tenant ID (UUID string) - required for tenant isolation
    
    Returns:
        Optional[str]: Path to artifact file, or None if not found
    """
    from models import Artifact
    import uuid as uuid_module
    
    if not tenant_id:
        raise ValueError("tenant_id is required for get_artifact_path")
    
    # Convert tenant_id to UUID if it's a string
    if isinstance(tenant_id, str):
        tenant_id = uuid_module.UUID(tenant_id)
    
    artifact = db.query(Artifact).filter(
        Artifact.run_id == run_id,
        Artifact.artifact_type == artifact_type,
        Artifact.tenant_id == tenant_id
    ).first()
    
    if artifact:
        return artifact.path
    return None
