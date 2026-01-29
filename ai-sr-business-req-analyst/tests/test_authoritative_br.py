"""
Regression tests for Authoritative BR Mode (BA agent when source == "jira").

A) One-line Jira description with BR-003..BR-026 => marker_count=24, extracted_count=24,
   output must contain 24 BR statements and preserve original IDs.
B) Jira description with no BR markers => behavior unchanged.
C) Partial BR content (marker_count > 1 but extraction returns fewer) => fallback must occur.
"""
import asyncio
from unittest.mock import patch

from app.services.authoritative_br import extract_authoritative_brs
from app.agent.analyst import BusinessRequirementAnalyst
from app.models.intermediate import (
    LLMAnalysisOutput,
    ProposedCapability,
    ProposedRequirement,
    BusinessRequirementIntermediate,
    ScopeBoundariesIntermediate,
    RequirementMetadataIntermediate,
    AnalysisSummary,
)
from app.models.enums import ConfidenceLevel


# ---------------------------------------------------------------------------
# Unit tests: extract_authoritative_brs()
# ---------------------------------------------------------------------------

def test_authoritative_br_case_a_one_line_24_brs():
    """
    Case A: One-line Jira description containing BR-003..BR-026 => marker_count=24,
    extracted_count=24, output must contain 24 BR statements and preserve original IDs.
    """
    br_parts = [
        f"BR-{n:03d}: The system shall fulfill requirement {n}."
        for n in range(3, 27)
    ]
    block_content = " ".join(br_parts)
    desc = "Business Requirements (Normalized):\n" + block_content + "\n\nIdentified Risks:\n- None"
    extracted_list, marker_count, extracted_count = extract_authoritative_brs(desc)
    assert marker_count == 24, "expected marker_count=24"
    assert extracted_count == 24, "expected extracted_count=24"
    assert len(extracted_list) == 24, "expected 24 extracted BRs"
    assert extracted_list[0][0] == "BR-003"
    assert extracted_list[-1][0] == "BR-026"
    assert "fulfill requirement 3" in extracted_list[0][1]
    assert "fulfill requirement 26" in extracted_list[-1][1]


def test_authoritative_br_case_b_no_markers():
    """
    Case B: Jira description with no BR markers => extraction returns ([], 0, 0),
    behavior unchanged (caller uses existing generation).
    """
    desc = """Scope (In):
- Excel exports
- PDF plan sets

Scope (Out):
- Fabrication optimization

No BR-001 or Business Requirements (Normalized) here.
"""
    extracted_list, marker_count, extracted_count = extract_authoritative_brs(desc)
    assert marker_count == 0
    assert extracted_count == 0
    assert extracted_list == []


def test_authoritative_br_case_b_no_header():
    """Case B variant: text has BR-003 in it but no header block => not in block, marker_count=0 in block."""
    desc = "Some intro. BR-003: The system shall do X. More text."
    # Block is only after "Business Requirements (Normalized):", so block is empty -> marker_count=0
    extracted_list, marker_count, extracted_count = extract_authoritative_brs(desc)
    assert marker_count == 0
    assert extracted_list == []


def test_authoritative_br_case_c_partial_parse_fallback():
    """
    Case C: Partial BR content (marker_count > 1 but extraction returns fewer) => fallback.
    extract_authoritative_brs returns ([], marker_count, extracted_count) so caller does not use authoritative.
    """
    desc = """Business Requirements (Normalized):
BR-001: First requirement.
BR-002:
BR-003: Third requirement.

Identified Risks:
- None
"""
    extracted_list, marker_count, extracted_count = extract_authoritative_brs(desc)
    assert marker_count == 3
    assert extracted_count == 2  # BR-002 has empty statement
    assert extracted_list == [], "partial parse must return empty list so caller falls back"


# ---------------------------------------------------------------------------
# Integration: analyst.analyze with authoritative BRs (Case A end-to-end)
# ---------------------------------------------------------------------------

def _minimal_llm_output_single_br():
    """LLM output that would produce one requirement with one BR (what we want to overwrite)."""
    return LLMAnalysisOutput(
        analysis_summary=AnalysisSummary(
            original_intent="Upload PDF plan sets",
            interpretation_notes=[],
            requires_human_decision=False,
        ),
        proposed_capabilities=[
            ProposedCapability(
                capability_title="PDF upload",
                description="Upload PDF plan sets",
                inferred=False,
                proposed_requirements=[
                    ProposedRequirement(
                        summary="Upload PDF plan sets",
                        description="The platform shall allow users to upload PDF plan sets.",
                        business_requirements=[
                            BusinessRequirementIntermediate(
                                statement="The system shall allow users to upload PDF plan sets.",
                                inferred=False,
                            ),
                        ],
                        scope_boundaries=ScopeBoundariesIntermediate(
                            in_scope=["PDF upload"],
                            out_of_scope=[],
                        ),
                        constraints_policies=["N/A"],
                        open_questions=["N/A"],
                        metadata=RequirementMetadataIntermediate(
                            source_type="jira_existing",
                            enhancement_mode=0,
                            enhancement_actions=[],
                            inferred_content=False,
                        ),
                        gaps=[],
                        risks=[],
                    ),
                ],
            ),
        ],
        global_gaps=[],
        global_risks=[],
        confidence=ConfidenceLevel.HIGH,
    )


def test_analyst_case_a_preserves_24_brs_and_original_ids():
    """
    Case A integration: Input has BR-003..BR-026 in one line; analyst must output 24 BRs
    with original IDs (BR-003..BR-026), not a single BR-001 from LLM.
    """
    br_parts = [f"BR-{n:03d}: The system shall fulfill requirement {n}." for n in range(3, 27)]
    block_content = " ".join(br_parts)
    input_text = "Business Requirements (Normalized):\n" + block_content + "\n\nIdentified Risks:\n- None"

    with patch("app.agent.analyst.llm_analyze", return_value=_minimal_llm_output_single_br()):
        analyst = BusinessRequirementAnalyst()
        package = asyncio.run(analyst.analyze(input_text=input_text, source="jira"))

    assert package.requirements, "package must have at least one requirement"
    brs = package.requirements[0].business_requirements
    assert len(brs) == 24, "output must contain 24 BR statements (authoritative mode)"
    ids = [br.id for br in brs]
    assert ids[0] == "BR-003"
    assert ids[-1] == "BR-026"
    assert "fulfill requirement 3" in brs[0].statement
    assert "fulfill requirement 26" in brs[-1].statement
