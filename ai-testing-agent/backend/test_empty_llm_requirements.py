"""
Test for empty LLM requirements array fallback behavior.

This test verifies that when the LLM returns an empty requirements array,
the code correctly falls back to Path B/C (numbered/bulleted extraction or single inferred requirement).
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from app import generate_test_plan_with_llm


def test_empty_llm_requirements_with_numbered_items():
    """
    Test that when LLM returns requirements: [] AND bulleted/numbered items exist,
    requirements are populated from those items (Path B).
    """
    # Mock ticket with numbered acceptance criteria
    ticket = {
        "ticket_id": "TEST-001",
        "summary": "Test ticket",
        "description": "Test description",
        "acceptance_criteria": "1. First requirement\n2. Second requirement\n3. Third requirement"
    }
    
    # Mock LLM response with empty requirements array
    mock_llm_response = {
        "requirements": [],  # Empty array - should trigger Path B
        "metadata": {"source": "jira", "source_id": "TEST-001"},
        "test_plan": {"api_tests": [], "ui_tests": []},
        "summary": "Test summary"
    }
    
    with patch('app.openai_client') as mock_openai:
        # Mock the LLM call to return empty requirements
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
            
            # Should have requirements populated from numbered items (Path B)
            assert "requirements" in result
            assert len(result["requirements"]) > 0, "Requirements should be populated from numbered items"
            
            # All requirements should have source="jira" (from numbered items)
            for req in result["requirements"]:
                assert req.get("source") == "jira", f"Requirement should have source='jira', got {req.get('source')}"
                assert "id" in req, "Requirement should have an ID"
                assert req["id"].startswith("REQ-"), "Requirement ID should start with REQ-"


def test_empty_llm_requirements_without_numbered_items():
    """
    Test that when LLM returns requirements: [] AND no numbered items exist,
    a single inferred requirement is created (Path C).
    """
    # Mock ticket without numbered acceptance criteria
    ticket = {
        "ticket_id": "TEST-002",
        "summary": "Test ticket summary",
        "description": "Test description without numbered items",
        "acceptance_criteria": "Some acceptance criteria without numbering"
    }
    
    # Mock LLM response with empty requirements array
    mock_llm_response = {
        "requirements": [],  # Empty array - should trigger Path C
        "metadata": {"source": "jira", "source_id": "TEST-002"},
        "test_plan": {"api_tests": [], "ui_tests": []},
        "summary": "Test summary"
    }
    
    with patch('app.openai_client') as mock_openai:
        # Mock the LLM call to return empty requirements
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
            
            # Description should come from summary or description
            assert first_req.get("description"), "Inferred requirement should have a description"


def test_non_empty_llm_requirements_unchanged():
    """
    Test that when LLM returns non-empty requirements, behavior is unchanged (Path A).
    """
    # Mock ticket
    ticket = {
        "ticket_id": "TEST-003",
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
        "metadata": {"source": "jira", "source_id": "TEST-003"},
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
            assert len(result["requirements"]) == 2, "Should have 2 requirements from LLM"
            
            # Requirements should match LLM response
            assert result["requirements"][0]["id"] == "REQ-001"
            assert result["requirements"][0]["source"] == "jira"
            assert result["requirements"][1]["id"] == "REQ-002"
            assert result["requirements"][1]["source"] == "inferred"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
