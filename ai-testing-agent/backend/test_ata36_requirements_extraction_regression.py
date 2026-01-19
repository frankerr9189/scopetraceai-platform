"""
Test for ATA-36 requirements extraction regression fix.

This test verifies that:
1. Path B/C uses compiled_ticket["description"] as the first preference for normalized text
2. Path A zero-output falls back to Path B/C normalized extraction
3. Single inferred requirement is created when no normalized text exists
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from app import generate_test_plan_with_llm


def test_path_bc_uses_compiled_ticket_description_for_normalized_text():
    """
    Test that Path B/C uses compiled_ticket["description"] as the first preference
    for normalized text extraction (ATA-36 regression fix).
    
    Scenario:
    - compiled_ticket["description"] contains ATA-36 normalized block with:
        "Normalized Requirements:" (1) item
        "Scope (In):" bullets (several)
    - llm_response contains requirements: [] (empty)
    - Expect: requirements[] populated (>= 1), ids deterministic, source == "normalized"
    """
    ticket = {
        "ticket_id": "ATA-36",
        "summary": "Original ticket summary",
        "description": """Normalized Requirements:
1) Automatic generation of Requirement Traceability Matrix (RTM)

Scope (In):
- Inclusion of Requirement description in RTM
- Inclusion of Test Plan details in RTM
- Inclusion of Test Case details in RTM

Scope (Out):
- Manual RTM creation""",
        "acceptance_criteria": "Some acceptance criteria without numbering"
    }
    
    # Mock LLM response with empty requirements array
    mock_llm_response = {
        "requirements": [],  # Empty array - should trigger Path B/C
        "description": "LLM description (should be ignored if compiled_ticket has normalized text)",
        "metadata": {"source": "jira", "source_id": "ATA-36"},
        "test_plan": {"api_tests": [], "ui_tests": []},
        "summary": "LLM summary (should be ignored if compiled_ticket has normalized text)"
    }
    
    with patch('app.openai_client') as mock_openai:
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = str(mock_llm_response).replace("'", '"')
        mock_openai.chat.completions.create.return_value = mock_response
        
        with patch('app.json.loads', return_value=mock_llm_response):
            compiled_ticket = {
                "ticket_id": ticket["ticket_id"],
                "summary": ticket["summary"],
                "description": ticket["description"],  # This contains the normalized text
                "acceptance_criteria": ticket["acceptance_criteria"]
            }
            result = generate_test_plan_with_llm(compiled_ticket)
            
            # Should have requirements populated from normalized text (Path B)
            assert "requirements" in result
            assert len(result["requirements"]) >= 1, "Should have at least 1 requirement from normalized text"
            
            # Check that requirements came from normalized text
            normalized_reqs = [req for req in result["requirements"] if req.get("source") == "normalized"]
            assert len(normalized_reqs) >= 1, "Should have at least one requirement with source='normalized'"
            
            # Check deterministic IDs
            for i, req in enumerate(normalized_reqs, 1):
                assert req.get("id") == f"ATA-36-REQ-{i:03d}", f"Requirement {i} should have deterministic ID ATA-36-REQ-{i:03d}"
                assert req.get("inferred") == False, "Normalized requirements should not be inferred"
            
            # Verify content
            req_descriptions = [req.get("description", "") for req in normalized_reqs]
            assert any("Automatic generation" in desc for desc in req_descriptions), "Should contain numbered requirement"
            assert any("Inclusion of Requirement description" in desc for desc in req_descriptions), "Should contain scope-in bullet"


def test_path_a_zero_output_falls_back_to_normalized_extraction():
    """
    Test that Path A zero-output falls back to Path B/C normalized extraction.
    
    Scenario:
    - llm_response returns requirements list but post-processing results in 0
      (e.g., empty descriptions or filtered)
    - compiled_ticket["description"] contains normalized block
    - Expect: requirements[] populated from normalized block
    """
    ticket = {
        "ticket_id": "ATA-37",
        "summary": "Test ticket",
        "description": """Normalized Requirements:
1) First requirement from normalized text
2) Second requirement from normalized text

Scope (In):
- Scope item 1
- Scope item 2""",
        "acceptance_criteria": "Some acceptance criteria"
    }
    
    # Mock LLM response with requirements that will be filtered out (empty descriptions)
    mock_llm_response = {
        "requirements": [
            {"id": "REQ-001", "source": "jira", "description": ""},  # Empty description - will be filtered
            {"id": "REQ-002", "source": "inferred", "description": ""}  # Empty description - will be filtered
        ],
        "metadata": {"source": "jira", "source_id": "ATA-37"},
        "test_plan": {"api_tests": [], "ui_tests": []},
        "summary": "Test summary"
    }
    
    with patch('app.openai_client') as mock_openai:
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = str(mock_llm_response).replace("'", '"')
        mock_openai.chat.completions.create.return_value = mock_response
        
        with patch('app.json.loads', return_value=mock_llm_response):
            compiled_ticket = {
                "ticket_id": ticket["ticket_id"],
                "summary": ticket["summary"],
                "description": ticket["description"],  # Contains normalized text
                "acceptance_criteria": ticket["acceptance_criteria"]
            }
            result = generate_test_plan_with_llm(compiled_ticket)
            
            # Path A should produce 0 requirements (empty descriptions filtered)
            # Should fall back to Path B/C and extract from normalized text
            assert "requirements" in result
            assert len(result["requirements"]) >= 1, "Should have requirements from normalized text fallback"
            
            # Check that requirements came from normalized text (Path B/C fallback)
            normalized_reqs = [req for req in result["requirements"] if req.get("source") == "normalized"]
            assert len(normalized_reqs) >= 1, "Should have at least one requirement with source='normalized'"
            
            # Verify content from normalized text
            req_descriptions = [req.get("description", "") for req in normalized_reqs]
            assert any("First requirement" in desc for desc in req_descriptions) or \
                   any("Second requirement" in desc for desc in req_descriptions) or \
                   any("Scope item" in desc for desc in req_descriptions), \
                   "Should contain content from normalized text"


def test_no_normalized_text_creates_single_inferred_requirement():
    """
    Test that when no normalized text exists, Path C creates a single inferred requirement.
    
    Scenario:
    - compiled_ticket has summary/description but no normalized sections and no numbered items
    - llm_response requirements: []
    - Expect: exactly one inferred requirement in requirements[]
    """
    ticket = {
        "ticket_id": "ATA-38",
        "summary": "Test ticket summary",
        "description": "Test description without normalized sections or numbered items",
        "acceptance_criteria": "Some acceptance criteria without numbering"
    }
    
    # Mock LLM response with empty requirements array
    mock_llm_response = {
        "requirements": [],  # Empty array - should trigger Path B/C, then Path C
        "metadata": {"source": "jira", "source_id": "ATA-38"},
        "test_plan": {"api_tests": [], "ui_tests": []},
        "summary": "Test summary"
    }
    
    with patch('app.openai_client') as mock_openai:
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = str(mock_llm_response).replace("'", '"')
        mock_openai.chat.completions.create.return_value = mock_response
        
        with patch('app.json.loads', return_value=mock_llm_response):
            compiled_ticket = {
                "ticket_id": ticket["ticket_id"],
                "summary": ticket["summary"],
                "description": ticket["description"],
                "acceptance_criteria": ticket["acceptance_criteria"]
            }
            result = generate_test_plan_with_llm(compiled_ticket)
            
            # Should have exactly one inferred requirement (Path C)
            assert "requirements" in result
            assert len(result["requirements"]) == 1, "Should have exactly 1 inferred requirement"
            
            first_req = result["requirements"][0]
            assert first_req.get("source") == "inferred", "First requirement should have source='inferred'"
            assert first_req.get("id") == "ATA-38-REQ-001", "Inferred requirement should have ID ATA-38-REQ-001"
            assert first_req.get("description"), "Inferred requirement should have a description"
            
            # Description should come from summary or description
            assert "Test ticket summary" in first_req.get("description", "") or \
                   "Test description" in first_req.get("description", ""), \
                   "Description should come from ticket summary or description"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
