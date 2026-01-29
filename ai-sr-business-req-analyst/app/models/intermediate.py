"""
Intermediate LLM output contract for the AI Sr Business Requirement Analyst.

This contract represents the raw analysis output produced by the LLM before any
normalization, numbering, versioning, or invariant enforcement occurs.

The LLM output is advisory only and does NOT:
- Assign requirement IDs
- Assign statuses
- Apply versioning
- Enforce invariants
- Apply Jira semantics
- Produce final RequirementPackage objects
"""
from pydantic import BaseModel, Field, field_validator
from typing import List, Optional, Union, Any
from app.models.enums import RiskLevel, ConfidenceLevel


class BusinessRequirementIntermediate(BaseModel):
    """A business requirement statement (intermediate).
    
    Each BR must represent exactly ONE obligation (atomic).
    Do NOT combine multiple obligations into a single BR.
    If in_scope has N distinct obligations, create N separate BRs.
    
    HARD REQUIREMENT: If the INPUT TEXT explicitly references multiple system obligations,
    those obligations MUST be represented as separate BRs, regardless of enhancement_mode.
    Examples: "publish X and associate it with Z" → 2 BRs, "store data and link it" → 2 BRs.
    """
    
    statement: str = Field(..., description="Declarative business requirement statement (e.g., 'The system shall...'). Must describe what exists, not how it is validated. Must represent exactly ONE obligation (atomic). Do NOT use 'and', 'or', or commas to join multiple obligations. If input text explicitly references multiple obligations, create separate BRs for each.")
    inferred: bool = Field(
        default=False,
        description="Whether this requirement is inferred"
    )


class ScopeBoundariesIntermediate(BaseModel):
    """Scope boundaries for a requirement (intermediate).
    
    Each distinct obligation in in_scope should have a corresponding atomic BR.
    If in_scope has N distinct items, ensure N separate BRs exist.
    """
    
    in_scope: List[str] = Field(..., description="Items explicitly in scope. Each distinct obligation should have a corresponding atomic BR.")
    out_of_scope: List[str] = Field(..., description="Items explicitly out of scope")


class RequirementMetadataIntermediate(BaseModel):
    """Metadata for a requirement (intermediate)."""
    
    source_type: str = Field(..., description="Source type: brd | freeform | jira_existing")
    enhancement_mode: int = Field(..., description="Enhancement mode: 0 | 1 | 2 | 3")
    enhancement_actions: List[str] = Field(default_factory=list, description="List of enhancement actions taken")
    inferred_content: bool = Field(default=False, description="Whether any content was inferred")


class ProposedRequirement(BaseModel):
    """A proposed requirement from LLM analysis (intermediate, advisory only)."""
    
    summary: str = Field(..., description="Requirement summary/title")
    description: str = Field(..., description="Business intent description - what the system must provide, not how it is validated")
    business_requirements: List[BusinessRequirementIntermediate] = Field(
        default_factory=list,
        description="Business requirements (BR-###) - declarative statements describing what exists"
    )
    scope_boundaries: ScopeBoundariesIntermediate = Field(
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
    metadata: RequirementMetadataIntermediate = Field(..., description="Requirement metadata")
    gaps: List[str] = Field(
        default_factory=list,
        description="Gaps or missing information for this requirement"
    )
    risks: List[str] = Field(
        default_factory=list,
        description="Risks associated with this requirement"
    )

    @field_validator("risks", mode="before")
    @classmethod
    def coerce_risks_to_strings(cls, v: Any) -> List[str]:
        """Accept LLM returning risk dicts (type/description/severity) and coerce to list of strings."""
        if not isinstance(v, list):
            return v
        out: List[str] = []
        for item in v:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, dict):
                desc = item.get("description") or item.get("type") or str(item)
                severity = item.get("severity", "")
                if severity:
                    out.append(f"{desc} (severity: {severity})")
                else:
                    out.append(desc)
            else:
                out.append(str(item))
        return out


class ProposedCapability(BaseModel):
    """A proposed capability grouping requirements (intermediate, advisory only)."""
    
    capability_title: str = Field(..., description="Capability title")
    description: str = Field(..., description="Capability description")
    inferred: bool = Field(
        default=False,
        description="Whether this capability was inferred rather than explicitly stated"
    )
    proposed_requirements: List[ProposedRequirement] = Field(
        default_factory=list,
        description="Requirements proposed under this capability"
    )


class AnalysisSummary(BaseModel):
    """Summary of the analysis (intermediate)."""
    
    original_intent: str = Field(
        ...,
        description="Verbatim original input text (preserved exactly)"
    )
    interpretation_notes: List[str] = Field(
        default_factory=list,
        description="Observations and interpretation notes from the analyst"
    )
    requires_human_decision: bool = Field(
        default=False,
        description="Whether this analysis requires human decision/confirmation"
    )


class GlobalRisk(BaseModel):
    """Cross-cutting risk not tied to a single requirement (intermediate)."""
    
    type: str = Field(..., description="Type/category of risk")
    description: str = Field(..., description="Risk description")
    severity: RiskLevel = Field(..., description="Risk severity level")


class LLMAnalysisOutput(BaseModel):
    """
    Intermediate LLM output contract.
    
    This represents the raw analysis output from the LLM before normalization.
    It is advisory only and does not include IDs, statuses, or final structures.
    """
    
    analysis_summary: AnalysisSummary = Field(
        ...,
        description="Summary of the analysis including original intent"
    )
    proposed_capabilities: List[ProposedCapability] = Field(
        default_factory=list,
        description="Proposed capabilities grouping requirements"
    )
    global_gaps: List[str] = Field(
        default_factory=list,
        description="Cross-cutting missing information not tied to a single requirement"
    )
    global_risks: List[GlobalRisk] = Field(
        default_factory=list,
        description="Cross-cutting risks affecting the overall analysis"
    )
    confidence: ConfidenceLevel = Field(
        ...,
        description="Confidence level reflecting ambiguity, inference level, and attachment dependency"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "analysis_summary": {
                    "original_intent": "Users need to log in",
                    "interpretation_notes": [
                        "Authentication mechanism not specified",
                        "Assuming standard username/password flow"
                    ],
                    "requires_human_decision": True
                },
                "proposed_capabilities": [
                    {
                        "capability_title": "User Authentication",
                        "description": "Users can authenticate to access the system",
                        "inferred": False,
                        "proposed_requirements": [
                            {
                                "summary": "User Login",
                                "description": "The system must provide user authentication capability",
                                "business_requirements": [
                                    {
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
                                "gaps": ["Password reset flow not specified"],
                                "risks": ["No mention of password complexity requirements"]
                            }
                        ]
                    }
                ],
                "global_gaps": [
                    "No mention of session timeout",
                    "No mention of multi-factor authentication"
                ],
                "global_risks": [
                    {
                        "type": "Compliance",
                        "description": "No mention of audit logging requirements",
                        "severity": "high"
                    }
                ],
                "confidence": "medium"
            }
        }
