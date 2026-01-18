"""
POST /overrides endpoint for manual requirement editing.
"""
from datetime import datetime
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import re
from app.models.requirement import Requirement, BusinessRequirement, RequirementManualOverride, BusinessRequirementManualOverride, ManualOverrideAudit, ScopeBoundaries
from app.models.package import RequirementPackage
from app.services.quality_scoring import calculate_quality_scores


router = APIRouter()


def _detect_scope_misalignment(
    original_summary: str,
    original_description: str,
    original_brs: List[BusinessRequirement],
    edited_summary: Optional[str],
    edited_description: Optional[str],
    edited_brs: Optional[Dict[str, str]],
    original_scope: ScopeBoundaries
) -> bool:
    """
    Detect if manual edits to text fields may have altered scope meaning without explicit scope boundary changes.
    
    This is an advisory-only check. It does NOT modify scope boundaries or block saves.
    
    Returns True if:
    - Text fields were edited (summary, description, or BRs)
    - Scope boundaries were NOT explicitly edited
    - The edited text introduces new concepts, capabilities, or domain areas not mentioned in original scope
    - The edited text removes or significantly narrows concepts that were in original scope
    
    Args:
        original_summary: Original requirement summary
        original_description: Original requirement description
        original_brs: Original business requirements
        edited_summary: Edited summary (None if not edited)
        edited_description: Edited description (None if not edited)
        edited_brs: Map of BR ID to edited statement (None if not edited)
        original_scope: Original scope boundaries (unchanged)
        
    Returns:
        True if scope misalignment advisory should be shown, False otherwise
    """
    # Only check if text fields were edited but scope was NOT explicitly edited
    text_edited = (
        (edited_summary is not None and edited_summary != original_summary) or
        (edited_description is not None and edited_description != original_description) or
        (edited_brs is not None and len(edited_brs) > 0)
    )
    
    if not text_edited:
        return False
    
    # Collect all text content (original and edited)
    original_text = f"{original_summary} {original_description}".lower()
    for br in original_brs:
        original_text += f" {br.statement}".lower()
    
    edited_text = original_text
    if edited_summary is not None:
        edited_text = edited_text.replace(original_summary.lower(), edited_summary.lower())
    if edited_description is not None:
        edited_text = edited_text.replace(original_description.lower(), edited_description.lower())
    if edited_brs:
        for br in original_brs:
            if br.id in edited_brs:
                edited_text = edited_text.replace(br.statement.lower(), edited_brs[br.id].lower())
    
    # Extract key terms from scope
    scope_terms = set()
    for item in original_scope.in_scope:
        # Extract meaningful words (skip common stop words)
        words = re.findall(r'\b[a-z]{4,}\b', item.lower())
        scope_terms.update(words)
    
    # Extract key terms from edited text
    edited_terms = set()
    words = re.findall(r'\b[a-z]{4,}\b', edited_text.lower())
    edited_terms.update(words)
    
    # Extract key terms from original text
    original_terms = set()
    words = re.findall(r'\b[a-z]{4,}\b', original_text.lower())
    original_terms.update(words)
    
    # Check for significant divergence
    # If edited text introduces many new terms not in scope, or removes terms that were in scope
    new_terms = edited_terms - original_terms - scope_terms
    removed_terms = original_terms - edited_terms
    
    # Heuristic: If >3 new significant terms introduced or >2 scope-relevant terms removed
    # This is advisory-only, so we use a conservative threshold
    significant_new_terms = len([t for t in new_terms if len(t) > 5])  # Longer words are more significant
    significant_removed_terms = len([t for t in removed_terms if t in scope_terms])
    
    return significant_new_terms >= 3 or significant_removed_terms >= 2


class BusinessRequirementOverrideRequest(BaseModel):
    """Request model for overriding a business requirement statement."""
    
    statement: str = Field(..., description="New statement text")
    edited_by: Optional[str] = Field(None, description="User identifier who made the edit")


class RequirementOverrideRequest(BaseModel):
    """Request model for overriding requirement fields."""
    
    summary: Optional[str] = Field(None, description="New summary text")
    description: Optional[str] = Field(None, description="New description text")
    scope_boundaries: Optional[Dict[str, List[str]]] = Field(
        None,
        description="New scope boundaries: {'in_scope': [...], 'out_of_scope': [...]}"
    )
    open_questions: Optional[List[str]] = Field(None, description="New open questions list")
    business_requirement_overrides: Optional[Dict[str, BusinessRequirementOverrideRequest]] = Field(
        None,
        description="Map of BR ID to override request (e.g., {'BR-001': {...}})"
    )
    edited_by: Optional[str] = Field(None, description="User identifier who made the edit")


class OverrideResponse(BaseModel):
    """Response model for override operations."""
    
    requirement: Requirement = Field(..., description="Updated requirement with overrides applied")
    quality_scores: Dict[str, float] = Field(..., description="Recalculated quality scores")
    quality_notes: Optional[List[str]] = Field(None, description="Quality notes if any score < 0.75")


def _apply_requirement_override(
    requirement: Requirement,
    override_request: RequirementOverrideRequest,
    all_requirements: List[Requirement]
) -> Requirement:
    """
    Apply manual override to a requirement and recalculate scores.
    
    Args:
        requirement: Original requirement (immutable)
        override_request: Override request with new values
        all_requirements: All requirements in package (for score calculation)
        
    Returns:
        Requirement with overrides applied and scores recalculated
    """
    # Track which fields changed
    fields_changed = []
    if override_request.summary is not None and override_request.summary != requirement.summary:
        fields_changed.append("summary")
    if override_request.description is not None and override_request.description != requirement.description:
        fields_changed.append("description")
    if override_request.scope_boundaries is not None:
        fields_changed.append("scope_boundaries")
    if override_request.open_questions is not None:
        fields_changed.append("open_questions")
    
    # Apply BR overrides
    updated_business_requirements = []
    br_fields_changed = False
    for br in requirement.business_requirements:
        if override_request.business_requirement_overrides and br.id in override_request.business_requirement_overrides:
            br_override_req = override_request.business_requirement_overrides[br.id]
            if br_override_req.statement != br.statement:
                br_fields_changed = True
                updated_business_requirements.append(
                    BusinessRequirement(
                        id=br.id,
                        statement=br.statement,  # Preserve original
                        inferred=br.inferred,
                        manual_override=BusinessRequirementManualOverride(
                            statement=br_override_req.statement,
                            audit=ManualOverrideAudit(
                                edited_by=br_override_req.edited_by,
                                edited_at=datetime.now(),
                                fields_changed=["statement"]
                            )
                        )
                    )
                )
            else:
                updated_business_requirements.append(br)
        else:
            updated_business_requirements.append(br)
    
    if br_fields_changed:
        fields_changed.append("business_requirements")
    
    # SCOPE OWNERSHIP GUARDRAIL: Detect scope misalignment (advisory only)
    # Only check if text fields were edited but scope boundaries were NOT explicitly edited
    scope_explicitly_edited = override_request.scope_boundaries is not None
    text_fields_edited = (
        override_request.summary is not None or
        override_request.description is not None or
        (override_request.business_requirement_overrides is not None and len(override_request.business_requirement_overrides) > 0)
    )
    
    scope_misalignment_advisory = False
    if text_fields_edited and not scope_explicitly_edited:
        # Extract edited BR statements
        edited_br_statements = None
        if override_request.business_requirement_overrides:
            edited_br_statements = {
                br_id: req.statement
                for br_id, req in override_request.business_requirement_overrides.items()
            }
        
        scope_misalignment_advisory = _detect_scope_misalignment(
            original_summary=requirement.summary,
            original_description=requirement.description,
            original_brs=requirement.business_requirements,
            edited_summary=override_request.summary,
            edited_description=override_request.description,
            edited_brs=edited_br_statements,
            original_scope=requirement.scope_boundaries
        )
    
    # Create override structure
    manual_override = RequirementManualOverride(
        summary=override_request.summary,
        description=override_request.description,
        scope_boundaries=override_request.scope_boundaries,
        open_questions=override_request.open_questions,
        scope_misalignment_advisory=scope_misalignment_advisory,
        audit=ManualOverrideAudit(
            edited_by=override_request.edited_by,
            edited_at=datetime.now(),
            fields_changed=fields_changed
        ) if fields_changed else None
    )
    
    # Create updated requirement (preserving all original fields)
    updated_requirement = Requirement(
        id=requirement.id,
        parent_id=requirement.parent_id,
        ticket_type=requirement.ticket_type,
        summary=requirement.summary,  # Original preserved
        description=requirement.description,  # Original preserved
        business_requirements=updated_business_requirements,
        scope_boundaries=requirement.scope_boundaries,  # Original preserved
        constraints_policies=requirement.constraints_policies,
        open_questions=requirement.open_questions,  # Original preserved
        metadata=requirement.metadata,
        status=requirement.status,
        priority=requirement.priority,
        gaps=requirement.gaps,
        risks=requirement.risks,
        ambiguities=requirement.ambiguities,
        inferred_logic=requirement.inferred_logic,
        original_intent=requirement.original_intent,
        created_at=requirement.created_at,
        updated_at=datetime.now(),
        manual_override=manual_override
    )
    
    # Recalculate quality scores using display values (overrides applied)
    quality_result = calculate_quality_scores(updated_requirement, all_requirements)
    updated_requirement.quality_scores = quality_result["quality_scores"]
    updated_requirement.quality_notes = quality_result.get("quality_notes")
    
    return updated_requirement


class OverrideRequestWithPackage(BaseModel):
    """Request model that includes override request and package."""
    
    override_request: RequirementOverrideRequest = Field(..., description="Override request")
    package: RequirementPackage = Field(..., description="Current requirement package")


@router.post("/requirements/{requirement_id}/overrides", response_model=OverrideResponse)
async def apply_requirement_override(
    requirement_id: str,
    request: OverrideRequestWithPackage
) -> OverrideResponse:
    """
    Apply manual override to a requirement.
    
    This endpoint:
    - Preserves original LLM-generated content unchanged
    - Stores overrides separately in manual_override structure
    - Recalculates quality scores deterministically (no LLM)
    - Maintains full audit trail
    
    Args:
        requirement_id: ID of requirement to override (e.g., "REQ-001")
        request: Request containing override_request and package
        
    Returns:
        OverrideResponse with updated requirement and recalculated scores
        
    Raises:
        HTTPException: If requirement not found or validation fails
    """
    override_request = request.override_request
    package = request.package
    
    # SCOPE LOCK GUARD: Block manual edits when scope is locked
    if package.scope_status == "locked":
        raise HTTPException(
            status_code=403,
            detail="Scope is locked. Unlock required to modify requirements."
        )
    
    # Find requirement in package
    requirement = None
    for req in package.requirements:
        if req.id == requirement_id:
            requirement = req
            break
    
    if not requirement:
        raise HTTPException(
            status_code=404,
            detail=f"Requirement {requirement_id} not found in package"
        )
    
    # Validate scope boundaries if provided
    if override_request.scope_boundaries:
        if "in_scope" not in override_request.scope_boundaries:
            override_request.scope_boundaries["in_scope"] = []
        if "out_of_scope" not in override_request.scope_boundaries:
            override_request.scope_boundaries["out_of_scope"] = []
    
    # Apply override
    updated_requirement = _apply_requirement_override(
        requirement,
        override_request,
        package.requirements
    )
    
    return OverrideResponse(
        requirement=updated_requirement,
        quality_scores=updated_requirement.quality_scores or {},
        quality_notes=updated_requirement.quality_notes
    )

