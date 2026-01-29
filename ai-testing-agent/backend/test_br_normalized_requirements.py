"""
Tests for Business Requirements (Normalized) extraction and integration.

Verifies:
1. extract_normalized_business_requirements() parses BR block and tolerates whitespace/blank lines
2. ATA-43 style description with BR block => requirements[] from BRs (ATA-43-BR-001..003), no inferred
3. Description without BR block => current inferred requirement behavior unchanged
"""

import pytest
from unittest.mock import patch, MagicMock

from app import extract_normalized_business_requirements, generate_test_plan_with_llm, classify_ticket_item


# ---------------------------------------------------------------------------
# Unit tests: extract_normalized_business_requirements()
# ---------------------------------------------------------------------------

def test_extract_br_empty_or_none():
    assert extract_normalized_business_requirements("") == []
    assert extract_normalized_business_requirements(None) == []
    assert extract_normalized_business_requirements("  \n  ") == []


def test_extract_br_no_header():
    desc = "Some text\nBR-001: The system shall do X\nMore text"
    assert extract_normalized_business_requirements(desc) == []


def test_extract_br_ata43_style_three_brs():
    desc = """Business Requirements (Normalized):
BR-001: The system shall provide admin visibility into important system changes.
BR-002: The solution shall log permission updates made by administrators.
BR-003: The platform shall support audit trails for scope changes.
"""
    result = extract_normalized_business_requirements(desc)
    assert len(result) == 3
    assert result[0] == ("BR-001", "The system shall provide admin visibility into important system changes.")
    assert result[1] == ("BR-002", "The solution shall log permission updates made by administrators.")
    assert result[2] == ("BR-003", "The platform shall support audit trails for scope changes.")


def test_extract_br_stops_at_section_headers():
    desc = """Business Requirements (Normalized):
BR-001: The system shall do X.

Identified Gaps:
- Some gap
"""
    result = extract_normalized_business_requirements(desc)
    assert len(result) == 1
    assert result[0][0] == "BR-001"
    assert "Identified Gaps" not in result[0][1]


def test_extract_br_stops_at_identified_risks():
    desc = """Business Requirements (Normalized):
BR-001: First requirement

Identified Risks:
- Some risk
"""
    result = extract_normalized_business_requirements(desc)
    assert len(result) == 1
    assert result[0][0] == "BR-001"


def test_extract_br_stops_at_scope_in():
    desc = """Business Requirements (Normalized):
BR-001: First requirement

Scope (In):
- In scope item
"""
    result = extract_normalized_business_requirements(desc)
    assert len(result) == 1


def test_extract_br_tolerates_whitespace_and_blank_lines():
    desc = """
Business Requirements (Normalized):

  BR-001  :  The system shall do X.

  BR-002: The solution shall do Y.

"""
    result = extract_normalized_business_requirements(desc)
    assert len(result) == 2
    assert result[0][0] == "BR-001"
    assert result[0][1].strip() == "The system shall do X."
    assert result[1][0] == "BR-002"
    assert result[1][1].strip() == "The solution shall do Y."


def test_extract_br_case_insensitive_header():
    desc = """business requirements (normalized):
BR-001: The system shall do X.
"""
    result = extract_normalized_business_requirements(desc)
    assert len(result) == 1
    assert result[0] == ("BR-001", "The system shall do X.")


def test_extract_br_ignores_non_matching_lines():
    desc = """Business Requirements (Normalized):
- Bullet that is not a BR
BR-001: The system shall do X.
Some other line
BR-002: The solution shall do Y.
"""
    result = extract_normalized_business_requirements(desc)
    assert len(result) == 2
    assert result[0][0] == "BR-001"
    assert result[1][0] == "BR-002"


# ---------------------------------------------------------------------------
# Integration: generate_test_plan_with_llm with BR block
# ---------------------------------------------------------------------------

def test_ata43_style_br_block_produces_br_requirements_not_inferred():
    """
    ATA-43 style description with BR block => requirements[] contains ATA-43-BR-001..003,
    source=explicit, no single inferred 'Improve admin visibility...' requirement.
    """
    ticket = {
        "ticket_id": "ATA-43",
        "summary": "Improve admin visibility into important system changes",
        "description": """Business Requirements (Normalized):
BR-001: The system shall provide admin visibility into important system changes.
BR-002: The solution shall log permission updates made by administrators.
BR-003: The platform shall support audit trails for scope changes.

Identified Gaps:
- None

Identified Risks:
- Low
""",
        "acceptance_criteria": "",
    }
    mock_llm_response = {
        "requirements": [],  # Empty so Path A would not run; without BR we'd get Path C inferred
        "description": "LLM description",
        "metadata": {"source": "jira", "source_id": "ATA-43"},
        "test_plan": {"api_tests": [], "ui_tests": [], "negative_tests": [], "edge_cases": [], "data_validation_tests": []},
        "summary": "Improve admin visibility into important system changes",
    }
    with patch("app.openai_client") as mock_openai:
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = str(mock_llm_response).replace("'", '"')
        mock_openai.chat.completions.create.return_value = mock_response
        with patch("app.json.loads", return_value=mock_llm_response):
            compiled_ticket = {
                "ticket_id": ticket["ticket_id"],
                "summary": ticket["summary"],
                "description": ticket["description"],
                "acceptance_criteria": ticket["acceptance_criteria"],
            }
            result = generate_test_plan_with_llm(compiled_ticket)
    reqs = result.get("requirements", [])
    assert len(reqs) == 3, "Should have 3 BR requirements, not a single inferred one"
    ids = [r.get("id") for r in reqs]
    assert "ATA-43-BR-001" in ids
    assert "ATA-43-BR-002" in ids
    assert "ATA-43-BR-003" in ids
    # Regression lock: NO inferred ATA-43-REQ-001 when BRs exist
    assert "ATA-43-REQ-001" not in ids, "BRs must win; inferred REQ-001 must not appear when BR block exists"
    for r in reqs:
        assert r.get("source") == "explicit"
    inferred = [r for r in reqs if r.get("source") == "inferred"]
    assert len(inferred) == 0
    # Dev breadcrumb: br_extraction metadata
    meta = result.get("metadata", {})
    br_ext = meta.get("br_extraction", {})
    assert br_ext.get("found_header") is True and br_ext.get("br_count") == 3
    assert br_ext.get("br_ids") == ["BR-001", "BR-002", "BR-003"]


def test_no_br_block_preserves_inferred_behavior():
    """
    Description without BR block => current behavior: single inferred requirement when
    LLM returns empty requirements and no numbered items.
    """
    ticket = {
        "ticket_id": "ATA-99",
        "summary": "Improve admin visibility",
        "description": "Plain description with no Business Requirements (Normalized) section.",
        "acceptance_criteria": "",
    }
    mock_llm_response = {
        "requirements": [],
        "description": "LLM description",
        "metadata": {"source": "jira", "source_id": "ATA-99"},
        "test_plan": {"api_tests": [], "ui_tests": [], "negative_tests": [], "edge_cases": [], "data_validation_tests": []},
        "summary": "Improve admin visibility",
    }
    with patch("app.openai_client") as mock_openai:
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = str(mock_llm_response).replace("'", '"')
        mock_openai.chat.completions.create.return_value = mock_response
        with patch("app.json.loads", return_value=mock_llm_response):
            compiled_ticket = {
                "ticket_id": ticket["ticket_id"],
                "summary": ticket["summary"],
                "description": ticket["description"],
                "acceptance_criteria": ticket["acceptance_criteria"],
            }
            result = generate_test_plan_with_llm(compiled_ticket)
    reqs = result.get("requirements", [])
    assert len(reqs) >= 1, "Should have at least one requirement (inferred)"
    # When no BR block, we get Path C: single inferred requirement
    inferred = [r for r in reqs if r.get("source") == "inferred"]
    assert len(inferred) >= 1


# ---------------------------------------------------------------------------
# classify_ticket_item: BR lines not informational_only
# ---------------------------------------------------------------------------

def test_classify_ticket_item_br_line_is_system_behavior():
    assert classify_ticket_item("BR-001: The system shall do X.") == "system_behavior"
    assert classify_ticket_item("  BR-002 : The solution shall do Y.") == "system_behavior"
    assert classify_ticket_item("br-003: lowercase header") == "system_behavior"


# ---------------------------------------------------------------------------
# Deterministic BR ingestion: marker count vs extracted count (regression A, B, C)
# ---------------------------------------------------------------------------

def test_br_deterministic_case_a_24_brs_one_line_format():
    """
    Case A: Jira description with BR-003..BR-026 in one-line format -> marker_count=24,
    extracted_count=24, output uses those BR statements.
    """
    from app import _count_br_markers_in_text, _extract_br_block_after_header

    # Build one-line style: BR-003: X. BR-004: Y. ... BR-026: Z.
    br_parts = [
        f"BR-{n:03d}: The system shall fulfill requirement {n}."
        for n in range(3, 27)
    ]
    block_content = " ".join(br_parts)
    desc = "Business Requirements (Normalized):\n" + block_content + "\n\nIdentified Risks:\n- None"
    result = extract_normalized_business_requirements(desc)
    assert len(result) == 24, "expected 24 extracted BRs (BR-003..BR-026)"
    assert result[0][0] == "BR-003"
    assert result[-1][0] == "BR-026"
    assert "fulfill requirement 3" in result[0][1]
    assert "fulfill requirement 26" in result[-1][1]
    # Sanity: marker count in block matches
    block = _extract_br_block_after_header(desc, "Business Requirements (Normalized):")
    assert _count_br_markers_in_text(block) == 24


def test_br_deterministic_case_b_no_br_markers_unchanged_behavior():
    """
    Case B: Jira description without any BR markers -> generation behaves exactly as before
    (extract returns [], caller uses prose/scope-based path).
    """
    desc = """Scope (In):
- Excel exports
- PDF plan sets

Scope (Out):
- Fabrication optimization

Some free-form text. No BR-001 or Business Requirements (Normalized) here.
"""
    result = extract_normalized_business_requirements(desc)
    assert result == [], "no BR block/markers => empty list, caller uses prose path"


def test_br_deterministic_case_b_no_header_no_markers():
    """Case B variant: header present but no BR markers in block => empty."""
    desc = """Business Requirements (Normalized):

(No BR-xxx lines in this block.)

Identified Risks:
- None
"""
    result = extract_normalized_business_requirements(desc)
    assert result == []


def test_br_deterministic_case_c_partial_parse_falls_back():
    """
    Case C: Simulate partial parse (e.g. one BR has empty statement so we extract fewer
    than marker_count) -> should fall back, not accept partial parse when marker_count > extracted_count.
    """
    # Block has 3 markers but BR-002 has no statement (empty between : and next BR-)
    desc = """Business Requirements (Normalized):
BR-001: First requirement.
BR-002:
BR-003: Third requirement.

Identified Risks:
- None
"""
    result = extract_normalized_business_requirements(desc)
    assert result == [], (
        "partial parse (3 markers, 2 with non-empty statement) must return [] and fall back to prose"
    )
