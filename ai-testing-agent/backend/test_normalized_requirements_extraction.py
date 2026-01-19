"""
Test for normalized requirements text extraction (Path B/C restoration).

This test verifies that when LLM returns requirements: [] and normalized requirements text
exists in the LLM response, requirements are extracted from:
1. "Normalized Requirements:" section (numbered items)
2. "Scope (In):" section (bullet items)
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from app import generate_test_plan_with_llm


def test_normalized_requirements_numbered_items():
    """
    Test that when LLM returns requirements: [] AND normalized text has numbered items,
    requirements are populated from "Normalized Requirements:" section (Path B).
    """
    # Mock ticket without numbered acceptance criteria (to force Path B/C)
    ticket = {
        "ticket_id": "ATA-36",
        "summary": "Test ticket",
        "description": "Test description",
        "acceptance_criteria": "Some acceptance criteria without numbering"
    }
    
    # Mock LLM response with empty requirements but normalized text with numbered items
    mock_llm_response = {
        "requirements": [],  # Empty array - should trigger Path B/C
        "description": """Normalized Requirements:
1) First requirement from normalized text
2) Second requirement from normalized text
3) Third requirement from normalized text

Scope (In):
- Some scope item

Scope (Out):
- Out of scope item""",
        "metadata": {"source": "jira", "source_id": "ATA-36"},
        "test_plan": {"api_tests": [], "ui_tests": []},
        "summary": """Normalized Requirements:
1) First requirement from normalized text
2) Second requirement from normalized text
3) Third requirement from normalized text

Scope (In):
- Some scope item

Scope (Out):
- Out of scope item"""
    }
    
    with patch('app.openai_client') as mock_openai:
        # Mock the LLM call to return empty requirements but normalized text
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = str(mock_llm_response).replace("'", '"')
        mock_openai.chat.completions.create.return_value = mock_response
        
        # Mock json.loads to return our mock response
        with patch('app.json.loads', return_value=mock_llm_response):
            # Create compiled ticket
            compiled_ticket = {
                "ticket_id": ticket["ticket_id"],
                "summary": ticket["summary"],
                "description": ticket["description"],
                "acceptance_criteria": ticket["acceptance_criteria"]
            }
            result = generate_test_plan_with_llm(compiled_ticket)
            
            # Should have requirements populated from normalized text (Path B)
            assert "requirements" in result
            assert len(result["requirements"]) >= 3, f"Should have at least 3 requirements from normalized text, got {len(result['requirements'])}"
            
            # All requirements should have source="normalized"
            for req in result["requirements"]:
                assert req.get("source") == "normalized", f"Requirement should have source='normalized', got {req.get('source')}"
                assert "id" in req, "Requirement should have an ID"
                assert req["id"].startswith("ATA-36-REQ-"), f"Requirement ID should start with ATA-36-REQ-, got {req['id']}"
                assert req.get("inferred") == False, "Requirement should have inferred=False"


def test_normalized_requirements_scope_in_bullets():
    """
    Test that when LLM returns requirements: [] AND normalized text has Scope (In) bullets,
    requirements are populated from "Scope (In):" section (Path B).
    """
    # Mock ticket without numbered acceptance criteria
    ticket = {
        "ticket_id": "TEST-004",
        "summary": "Test ticket",
        "description": "Test description",
        "acceptance_criteria": "Some acceptance criteria"
    }
    
    # Mock LLM response with empty requirements but Scope (In) bullets
    mock_llm_response = {
        "requirements": [],  # Empty array - should trigger Path B/C
        "description": """Normalized Requirements:
(No numbered requirements)

Scope (In):
- First scope item
- Second scope item
- Third scope item

Scope (Out):
- Out of scope item""",
        "metadata": {"source": "jira", "source_id": "TEST-004"},
        "test_plan": {"api_tests": [], "ui_tests": []},
        "summary": "Test summary"
    }
    
    with patch('app.openai_client') as mock_openai:
        # Mock the LLM call
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = str(mock_llm_response).replace("'", '"')
        mock_openai.chat.completions.create.return_value = mock_response
        
        # Mock json.loads to return our mock response
        with patch('app.json.loads', return_value=mock_llm_response):
            # Create compiled ticket
            compiled_ticket = {
                "ticket_id": ticket["ticket_id"],
                "summary": ticket["summary"],
                "description": ticket["description"],
                "acceptance_criteria": ticket["acceptance_criteria"]
            }
            result = generate_test_plan_with_llm(compiled_ticket)
            
            # Should have requirements populated from Scope (In) bullets (Path B)
            assert "requirements" in result
            assert len(result["requirements"]) >= 3, f"Should have at least 3 requirements from Scope (In), got {len(result['requirements'])}"
            
            # All requirements should have source="normalized"
            for req in result["requirements"]:
                assert req.get("source") == "normalized", f"Requirement should have source='normalized', got {req.get('source')}"
                assert "id" in req, "Requirement should have an ID"
                assert req.get("inferred") == False, "Requirement should have inferred=False"


def test_normalized_requirements_no_normalized_text():
    """
    Test that when LLM returns requirements: [] AND no normalized text exists,
    Path C creates single inferred requirement (unchanged behavior).
    """
    # Mock ticket without numbered acceptance criteria
    ticket = {
        "ticket_id": "TEST-005",
        "summary": "Test ticket summary",
        "description": "Test description without normalized text",
        "acceptance_criteria": "Some acceptance criteria"
    }
    
    # Mock LLM response with empty requirements and no normalized text
    mock_llm_response = {
        "requirements": [],  # Empty array - should trigger Path B/C
        "metadata": {"source": "jira", "source_id": "TEST-005"},
        "test_plan": {"api_tests": [], "ui_tests": []},
        "summary": "Test summary"
    }
    
    with patch('app.openai_client') as mock_openai:
        # Mock the LLM call
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = str(mock_llm_response).replace("'", '"')
        mock_openai.chat.completions.create.return_value = mock_response
        
        # Mock json.loads to return our mock response
        with patch('app.json.loads', return_value=mock_llm_response):
            # Create compiled ticket
            compiled_ticket = {
                "ticket_id": ticket["ticket_id"],
                "summary": ticket["summary"],
                "description": ticket["description"],
                "acceptance_criteria": ticket["acceptance_criteria"]
            }
            result = generate_test_plan_with_llm(compiled_ticket)
            
            # Should have at least one inferred requirement (Path C)
            assert "requirements" in result
            assert len(result["requirements"]) >= 1, "Should have at least one inferred requirement"
            
            # First requirement should be inferred
            first_req = result["requirements"][0]
            assert first_req.get("source") == "inferred", f"First requirement should have source='inferred', got {first_req.get('source')}"
            assert first_req.get("id") == "REQ-001", "Inferred requirement should have ID REQ-001"


def test_non_empty_llm_requirements_unchanged():
    """
    Test that when LLM returns non-empty requirements, behavior is unchanged (Path A).
    """
    # Mock ticket
    ticket = {
        "ticket_id": "TEST-006",
        "summary": "Test ticket",
        "description": "Test description",
        "acceptance_criteria": "Some criteria"
    }
    
    # Mock LLM response with non-empty requirements array
    mock_llm_response = {
        "requirements": [
            {"id": "REQ-001", "source": "jira", "description": "First requirement"},
            {"id": "REQ-002", "source": "inferred", "description": "Second requirement"}
        ],
        "metadata": {"source": "jira", "source_id": "TEST-006"},
        "test_plan": {"api_tests": [], "ui_tests": []},
        "summary": "Test summary"
    }
    
    with patch('app.openai_client') as mock_openai:
        # Mock the LLM call
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = str(mock_llm_response).replace("'", '"')
        mock_openai.chat.completions.create.return_value = mock_response
        
        # Mock json.loads to return our mock response
        with patch('app.json.loads', return_value=mock_llm_response):
            # Create compiled ticket
            compiled_ticket = {
                "ticket_id": ticket["ticket_id"],
                "summary": ticket["summary"],
                "description": ticket["description"],
                "acceptance_criteria": ticket["acceptance_criteria"]
            }
            result = generate_test_plan_with_llm(compiled_ticket)
            
            # Should use LLM requirements (Path A)
            assert "requirements" in result
            assert len(result["requirements"]) >= 2, "Should have at least 2 requirements from LLM"
            
            # Requirements should match LLM response (may be split/processed)
            assert result["requirements"][0]["id"] in ["REQ-001", "TEST-006-REQ-001"], f"First requirement ID should be REQ-001 or ticket-scoped, got {result['requirements'][0]['id']}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
