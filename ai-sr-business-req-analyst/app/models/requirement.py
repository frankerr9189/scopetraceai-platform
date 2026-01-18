"""
Pydantic models for business requirements.
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from app.models.enums import RequirementStatus, TicketType


class ManualOverrideAudit(BaseModel):
    """Audit trail for manual overrides."""
    
    edited_by: Optional[str] = Field(None, description="User identifier who made the edit")
    edited_at: datetime = Field(default_factory=datetime.now, description="Timestamp when edit was made")
    fields_changed: List[str] = Field(default_factory=list, description="List of field names that were changed")


class BusinessRequirementManualOverride(BaseModel):
    """Manual override for a business requirement statement."""
    
    statement: Optional[str] = Field(None, description="Manually edited statement (if None, use original)")
    audit: Optional[ManualOverrideAudit] = Field(None, description="Audit trail for this override")


class BusinessRequirement(BaseModel):
    """A single business requirement statement."""
    
    id: str = Field(..., description="Business requirement ID (e.g., BR-001, BR-002)")
    statement: str = Field(..., description="Declarative business requirement statement (e.g., 'The system shall...')")
    inferred: bool = Field(default=False, description="Whether this requirement is inferred")
    manual_override: Optional[BusinessRequirementManualOverride] = Field(
        None,
        description="Manual override for this BR (preserves original statement unchanged)"
    )
    
    def get_display_statement(self) -> str:
        """Get the statement to display (override if present, otherwise original)."""
        if self.manual_override and self.manual_override.statement:
            return self.manual_override.statement
        return self.statement
    
    def is_manually_edited(self) -> bool:
        """Check if this BR has been manually edited."""
        return self.manual_override is not None and self.manual_override.statement is not None


class ScopeBoundaries(BaseModel):
    """Scope boundaries for a requirement."""
    
    in_scope: List[str] = Field(..., description="Items explicitly in scope")
    out_of_scope: List[str] = Field(..., description="Items explicitly out of scope")


class RequirementMetadata(BaseModel):
    """Metadata for a requirement."""
    
    source_type: str = Field(..., description="Source type: brd | freeform | jira_existing")
    enhancement_mode: int = Field(..., description="Enhancement mode: 0 | 1 | 2 | 3")
    enhancement_actions: List[str] = Field(default_factory=list, description="List of enhancement actions taken")
    inferred_content: bool = Field(default=False, description="Whether any content was inferred")
    ui_orchestration: bool = Field(default=False, description="Whether this requirement is a UI orchestration ticket (UI controls, presentation, no backend mutation)")


class RequirementManualOverride(BaseModel):
    """Manual override structure for requirement fields (diff-based, preserves original)."""
    
    summary: Optional[str] = Field(None, description="Manually edited summary (if None, use original)")
    description: Optional[str] = Field(None, description="Manually edited description (if None, use original)")
    scope_boundaries: Optional[Dict[str, List[str]]] = Field(
        None,
        description="Manually edited scope boundaries: {'in_scope': [...], 'out_of_scope': [...]} (if None, use original)"
    )
    open_questions: Optional[List[str]] = Field(
        None,
        description="Manually edited open questions (if None, use original)"
    )
    scope_misalignment_advisory: bool = Field(
        default=False,
        description="Advisory flag: True if manual edits to text fields may have altered scope meaning without explicit scope boundary changes. Informational only, does not block saves."
    )
    audit: Optional[ManualOverrideAudit] = Field(None, description="Audit trail for this override")


class Requirement(BaseModel):
    """Structured business requirement model with scope definition."""
    
    id: str = Field(..., description="Stable, hierarchical requirement ID (e.g., REQ-001, REQ-001.1)")
    parent_id: Optional[str] = Field(None, description="Parent requirement ID for child requirements")
    ticket_type: TicketType = Field(..., description="Jira ticket type: 'story' for parent requirements, 'sub-task' for child requirements")
    summary: str = Field(..., description="Requirement summary/title")
    description: str = Field(..., description="Business intent description - what the system must provide, not how it is validated")
    business_requirements: List[BusinessRequirement] = Field(
        default_factory=list,
        description="Business requirements (BR-###) - declarative statements describing what exists"
    )
    scope_boundaries: ScopeBoundaries = Field(
        ...,
        description="Scope boundaries - what is in scope and what is out of scope"
    )
    constraints_policies: List[str] = Field(
        default_factory=list,
        description="Constraints and policies that apply, or ['N/A'] if none"
    )
    open_questions: List[str] = Field(
        default_factory=list,
        description="Open questions or ambiguities, or ['N/A'] if none"
    )
    metadata: RequirementMetadata = Field(..., description="Requirement metadata")
    status: RequirementStatus = Field(
        default=RequirementStatus.IN_REVIEW,
        description="Requirement status (must start in REVIEW)"
    )
    priority: Optional[str] = None
    gaps: List[str] = Field(default_factory=list, description="Identified gaps in the requirement")
    risks: List[str] = Field(default_factory=list, description="Identified risks")
    ambiguities: List[str] = Field(
        default_factory=list,
        description="Ambiguities requiring human confirmation"
    )
    inferred_logic: List[str] = Field(
        default_factory=list,
        description="List of inferred logic that must be explicitly flagged"
    )
    original_intent: str = Field(..., description="Preserved original business intent")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    quality_scores: Optional[Dict[str, float]] = Field(
        default=None,
        description="Quality scores: clarity, completeness, scope_containment (0.0-1.0). No test-oriented scoring."
    )
    quality_notes: Optional[List[str]] = Field(
        default=None,
        description="Quality notes added when any score < 0.75"
    )
    manual_override: Optional[RequirementManualOverride] = Field(
        None,
        description="Manual override for this requirement (preserves original fields unchanged)"
    )
    
    def get_display_summary(self) -> str:
        """Get the summary to display (override if present, otherwise original)."""
        if self.manual_override and self.manual_override.summary:
            return self.manual_override.summary
        return self.summary
    
    def get_display_description(self) -> str:
        """Get the description to display (override if present, otherwise original)."""
        if self.manual_override and self.manual_override.description:
            return self.manual_override.description
        return self.description
    
    def get_display_scope_boundaries(self) -> ScopeBoundaries:
        """Get the scope boundaries to display (override if present, otherwise original)."""
        if self.manual_override and self.manual_override.scope_boundaries:
            return ScopeBoundaries(**self.manual_override.scope_boundaries)
        return self.scope_boundaries
    
    def get_display_open_questions(self) -> List[str]:
        """Get the open questions to display (override if present, otherwise original)."""
        if self.manual_override and self.manual_override.open_questions is not None:
            return self.manual_override.open_questions
        return self.open_questions
    
    def is_manually_edited(self) -> bool:
        """Check if this requirement has been manually edited."""
        return self.manual_override is not None and (
            self.manual_override.summary is not None or
            self.manual_override.description is not None or
            self.manual_override.scope_boundaries is not None or
            self.manual_override.open_questions is not None
        )
    
    class Config:
        json_schema_extra = {
            "example": {
                "id": "REQ-001",
                "summary": "User Authentication",
                "description": "The system must provide user authentication capability",
                "business_requirements": [
                    {
                        "id": "BR-001",
                        "statement": "The system shall authenticate users with valid credentials.",
                        "inferred": False
                    }
                ],
                "scope_boundaries": {
                    "in_scope": ["User credential authentication", "Session management"],
                    "out_of_scope": ["Password reset flow", "User registration"]
                },
                "constraints_policies": ["N/A"],
                "open_questions": ["N/A"],
                "metadata": {
                    "source_type": "freeform",
                    "enhancement_mode": 1,
                    "enhancement_actions": ["Clarified language"],
                    "inferred_content": False
                },
                "status": "in_review",
                "ticket_type": "story",
                "original_intent": "Users need to log in"
            }
        }


class RequirementAnalysis(BaseModel):
    """Model for requirement analysis results."""
    
    requirement_id: str
    analysis: str
    gaps: List[str] = Field(default_factory=list)
    risks: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    confidence_score: Optional[float] = None
