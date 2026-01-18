"""
Scope status transition endpoints for requirement packages.
"""
from datetime import datetime
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Literal, Optional
from app.models.package import RequirementPackage, ScopeStatusTransition


router = APIRouter()


class ScopeStatusTransitionRequest(BaseModel):
    """Request model for scope status transitions."""
    
    changed_by: Optional[str] = Field(None, description="User identifier who is changing the status")


class ScopeStatusTransitionResponse(BaseModel):
    """Response model for scope status transitions."""
    
    package: RequirementPackage = Field(..., description="Updated package with new scope status")
    previous_status: Literal["draft", "reviewed", "locked"] = Field(..., description="Previous scope status")
    new_status: Literal["draft", "reviewed", "locked"] = Field(..., description="New scope status")


def _validate_status_transition(
    current_status: Literal["draft", "reviewed", "locked"],
    new_status: Literal["draft", "reviewed", "locked"]
) -> bool:
    """
    Validate that scope status transition is allowed.
    
    Allowed transitions:
    - draft → reviewed
    - reviewed → locked
    - No backward transitions allowed
    """
    valid_transitions = {
        "draft": ["reviewed"],
        "reviewed": ["locked"],
        "locked": []  # Locked cannot transition
    }
    
    return new_status in valid_transitions.get(current_status, [])


def _transition_scope_status(
    package: RequirementPackage,
    new_status: Literal["draft", "reviewed", "locked"],
    changed_by: Optional[str] = None
) -> RequirementPackage:
    """
    Transition package scope status with audit trail.
    
    Args:
        package: Current requirement package
        new_status: Target scope status
        changed_by: User identifier who is making the change
        
    Returns:
        Updated package with new scope status and transition audit
        
    Raises:
        ValueError: If transition is invalid
    """
    current_status = package.scope_status
    
    # Validate transition
    if not _validate_status_transition(current_status, new_status):
        raise ValueError(
            f"Invalid scope status transition: {current_status} → {new_status}. "
            f"Allowed transitions: draft → reviewed → locked"
        )
    
    # Create transition audit record
    transition = ScopeStatusTransition(
        previous_status=current_status,
        new_status=new_status,
        changed_by=changed_by,
        changed_at=datetime.now()
    )
    
    # Update package
    updated_transitions = list(package.scope_status_transitions) + [transition]
    
    # Create updated package (preserving all other fields)
    updated_package = RequirementPackage(
        package_id=package.package_id,
        version=package.version,
        requirements=package.requirements,
        gap_analysis=package.gap_analysis,
        risk_analysis=package.risk_analysis,
        original_input=package.original_input,
        attachments=package.attachments,
        scope_status=new_status,
        scope_status_transitions=updated_transitions,
        metadata=package.metadata,
        created_at=package.created_at,
        created_by=package.created_by
    )
    
    return updated_package


class PackageTransitionRequest(BaseModel):
    """Request model that includes package for status transition."""
    
    package: RequirementPackage = Field(..., description="Current requirement package")


@router.post("/packages/{package_id}/review", response_model=ScopeStatusTransitionResponse)
async def mark_package_reviewed(
    package_id: str,
    request: PackageTransitionRequest,
    transition_request: ScopeStatusTransitionRequest
) -> ScopeStatusTransitionResponse:
    """
    Transition package scope status from draft to reviewed.
    
    This marks the package as ready for locking but does not lock it.
    
    Args:
        package_id: Package identifier (must match package in request)
        request: Request containing the package
        transition_request: Transition request with user identifier
        
    Returns:
        Updated package with scope_status = "reviewed"
        
    Raises:
        HTTPException: If package ID mismatch, invalid transition, or validation fails
    """
    package = request.package
    
    # Validate package ID matches
    if package.package_id != package_id:
        raise HTTPException(
            status_code=400,
            detail=f"Package ID mismatch: expected {package_id}, got {package.package_id}"
        )
    
    # Transition to reviewed
    try:
        updated_package = _transition_scope_status(
            package,
            "reviewed",
            changed_by=transition_request.changed_by
        )
    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )
    
    return ScopeStatusTransitionResponse(
        package=updated_package,
        previous_status=package.scope_status,
        new_status="reviewed"
    )


@router.post("/packages/{package_id}/lock", response_model=ScopeStatusTransitionResponse)
async def lock_package_scope(
    package_id: str,
    request: PackageTransitionRequest,
    transition_request: ScopeStatusTransitionRequest
) -> ScopeStatusTransitionResponse:
    """
    Lock package scope (transition from reviewed to locked).
    
    Once locked:
    - Manual edits to requirements are blocked
    - AI regeneration is blocked
    - Automatic decomposition is blocked
    - Attachment re-processing is blocked
    
    This action is irreversible without unlocking (which requires a separate endpoint if implemented).
    
    Args:
        package_id: Package identifier (must match package in request)
        request: Request containing the package
        transition_request: Transition request with user identifier
        
    Returns:
        Updated package with scope_status = "locked"
        
    Raises:
        HTTPException: If package ID mismatch, invalid transition, or validation fails
    """
    package = request.package
    
    # Validate package ID matches
    if package.package_id != package_id:
        raise HTTPException(
            status_code=400,
            detail=f"Package ID mismatch: expected {package_id}, got {package.package_id}"
        )
    
    # Transition to locked
    try:
        updated_package = _transition_scope_status(
            package,
            "locked",
            changed_by=transition_request.changed_by
        )
    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )
    
    return ScopeStatusTransitionResponse(
        package=updated_package,
        previous_status=package.scope_status,
        new_status="locked"
    )

