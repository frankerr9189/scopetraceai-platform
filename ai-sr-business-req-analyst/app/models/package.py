"""
Versioned output model for requirement packages.
"""
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Literal
from datetime import datetime
from app.models.requirement import Requirement


class GapAnalysis(BaseModel):
    """Gap analysis for the requirement package."""
    
    gaps: List[str] = Field(default_factory=list, description="Identified gaps")
    missing_information: List[str] = Field(
        default_factory=list,
        description="Missing information requiring human confirmation"
    )


class RiskAnalysis(BaseModel):
    """Risk analysis for the requirement package."""
    
    risks: List[str] = Field(default_factory=list, description="Identified risks")
    risk_level: str = Field(default="medium", description="Overall risk level")
    audit_concerns: List[str] = Field(
        default_factory=list,
        description="Concerns for ISO 27001 and SOC 2 audit evidence"
    )


class Attachment(BaseModel):
    """Attachment model for supporting materials at package level."""
    
    filename: str = Field(..., description="Original filename")
    mime_type: str = Field(..., description="MIME type of the file")
    extracted_text: Optional[str] = Field(
        default=None,
        description="Extracted readable text from the attachment (if parsed)"
    )
    # Note: raw content is stored as base64 or file reference in production
    # For Phase 1, we store extracted text only


class ScopeStatusTransition(BaseModel):
    """Audit trail for scope status transitions."""
    
    previous_status: Literal["draft", "reviewed", "locked"] = Field(..., description="Previous scope status")
    new_status: Literal["draft", "reviewed", "locked"] = Field(..., description="New scope status")
    changed_by: Optional[str] = Field(None, description="User identifier who changed the status")
    changed_at: datetime = Field(default_factory=datetime.now, description="Timestamp when status was changed")


class RequirementPackage(BaseModel):
    """
    Deterministic, versioned package of requirements.
    Suitable for ISO 27001 and SOC 2 audit evidence.
    """
    
    package_id: str = Field(..., description="Unique package identifier")
    version: str = Field(..., description="Package version")
    requirements: List[Requirement] = Field(
        default_factory=list,
        description="List of structured requirements with hierarchical IDs"
    )
    gap_analysis: GapAnalysis = Field(
        default_factory=lambda: GapAnalysis(),
        description="Gap analysis for the package"
    )
    risk_analysis: RiskAnalysis = Field(
        default_factory=lambda: RiskAnalysis(),
        description="Risk analysis for the package"
    )
    original_input: str = Field(..., description="Original human-written requirements input")
    attachments: List[Attachment] = Field(
        default_factory=list,
        description="Supporting materials (attachments) at package level only. NOT associated with individual requirements."
    )
    scope_status: Literal["draft", "reviewed", "locked"] = Field(
        default="draft",
        description="Scope lock status: draft (editable), reviewed (ready to lock), locked (immutable)"
    )
    scope_status_transitions: List[ScopeStatusTransition] = Field(
        default_factory=list,
        description="Audit trail of scope status transitions"
    )
    metadata: Optional[Dict[str, Any]] = None
    agent_metadata: Optional[Dict[str, Any]] = Field(
        default_factory=lambda: {
            "agent": "ba-requirements-agent",
            "agent_version": "1.0.0",
            "logic_version": "ba-v1",
            "determinism": "rule-based + constrained LLM",
            "change_policy": "non-retroactive"
        },
        description="Agent versioning and determinism metadata"
    )
    created_at: datetime = Field(default_factory=datetime.now)
    created_by: Optional[str] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "package_id": "PKG-001",
                "version": "1.0.0",
                "requirements": [],
                "gap_analysis": {"gaps": [], "missing_information": []},
                "risk_analysis": {"risks": [], "risk_level": "medium", "audit_concerns": []},
                "original_input": "User needs to log in"
            }
        }


class PackageVersion(BaseModel):
    """Version information for a requirement package."""
    
    version: str
    package_id: str
    changelog: Optional[str] = None
    created_at: datetime
    is_latest: bool = False

