"""
Regression test for Path B: numbered items extraction when LLM returns empty requirements.

This test verifies that when:
- LLM returns {"requirements": []} (empty list)
- compiled_ticket contains numbered items in description/acceptance_criteria
- Path B should create one requirement per numbered item

This restores the 1/14 behavior where numbered items always produce requirements.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from app import generate_test_plan_with_llm


def test_path_b_creates_requirements_from_numbered_items():
    """
    Test that Path B creates requirements from numbered items when LLM returns empty requirements.
    
    Scenario:
    - LLM returns {"requirements": []}
    - compiled_ticket contains numbered items in description: "1. First item\n2. Second item\n3. Third item"
    - Expect: test_plan["requirements"] contains 3 requirements with IDs REQ-001, REQ-002, REQ-003
    """
    ticket = {
        "ticket_id": "TEST-001",
        "summary": "Test ticket",
        "description": "1. First requirement from numbered list\n2. Second requirement from numbered list\n3. Third requirement from numbered list",
        "acceptance_criteria": "Some acceptance criteria"
    }
    
    # Mock LLM response with empty requirements array
    mock_llm_response = {
        "requirements": [],  # Empty array - should trigger Path B
        "metadata": {"source": "jira", "source_id": "TEST-001"},
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
                "description": ticket["description"],  # Contains numbered items
                "acceptance_criteria": ticket["acceptance_criteria"]
            }
            result = generate_test_plan_with_llm(compiled_ticket)
            
            # Should have requirements populated from numbered items (Path B)
            assert "requirements" in result
            assert len(result["requirements"]) >= 3, f"Should have at least 3 requirements from numbered items, got {len(result['requirements'])}"
            
            # Check that requirements have correct IDs
            req_ids = [req.get("id") for req in result["requirements"] if isinstance(req, dict)]
            assert "REQ-001" in req_ids, f"Should have REQ-001, got {req_ids}"
            assert "REQ-002" in req_ids, f"Should have REQ-002, got {req_ids}"
            assert "REQ-003" in req_ids, f"Should have REQ-003, got {req_ids}"
            
            # Check that requirements have source="jira"
            for req in result["requirements"]:
                if isinstance(req, dict) and req.get("id") in ["REQ-001", "REQ-002", "REQ-003"]:
                    assert req.get("source") == "jira", f"Requirement {req.get('id')} should have source='jira', got {req.get('source')}"
                    assert "description" in req, f"Requirement {req.get('id')} should have description"
                    assert len(req.get("description", "")) > 0, f"Requirement {req.get('id')} should have non-empty description"


def test_path_b_creates_requirements_from_acceptance_criteria_items():
    """
    Test that Path B creates requirements from acceptance_criteria numbered items when description has none.
    
    Scenario:
    - LLM returns {"requirements": []}
    - compiled_ticket description has no numbered items
    - compiled_ticket acceptance_criteria has numbered items: "1. First\n2. Second"
    - Expect: test_plan["requirements"] contains requirements from acceptance_criteria
    """
    ticket = {
        "ticket_id": "TEST-002",
        "summary": "Test ticket",
        "description": "Some description without numbered items",
        "acceptance_criteria": "1. First acceptance criteria item\n2. Second acceptance criteria item"
    }
    
    # Mock LLM response with empty requirements array
    mock_llm_response = {
        "requirements": [],  # Empty array - should trigger Path B
        "metadata": {"source": "jira", "source_id": "TEST-002"},
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
                "acceptance_criteria": ticket["acceptance_criteria"]  # Contains numbered items
            }
            result = generate_test_plan_with_llm(compiled_ticket)
            
            # Should have requirements populated from acceptance_criteria numbered items (Path B)
            assert "requirements" in result
            assert len(result["requirements"]) >= 2, f"Should have at least 2 requirements from acceptance_criteria numbered items, got {len(result['requirements'])}"
            
            # Check that requirements have correct structure
            for req in result["requirements"]:
                if isinstance(req, dict):
                    assert "id" in req, "Requirement should have an ID"
                    assert req.get("id").startswith("REQ-"), f"Requirement ID should start with REQ-, got {req.get('id')}"
                    assert req.get("source") == "jira", f"Requirement should have source='jira', got {req.get('source')}"
                    assert "description" in req, "Requirement should have description"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
