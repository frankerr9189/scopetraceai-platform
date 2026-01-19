"""
Test for normalized requirements extraction from ticket_details description (test_plan summary).

This test verifies that when normalized text exists only in test_plan summary
(which ends up in ticket_details[].description), requirements are extracted correctly.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from app import generate_test_plan_with_llm


def test_normalized_requirements_from_ticket_details():
    """
    Test that when LLM returns requirements: [] AND normalized text exists only in test_plan summary,
    requirements are populated from "Normalized Requirements:" section (Path B).
    This simulates the ATA-36 case where normalized text is in ticket_details[].description.
    """
    # Mock ticket without numbered acceptance criteria (to force Path B/C)
    ticket = {
        "ticket_id": "ATA-36",
        "summary": "Test ticket",
        "description": "Test description",
        "acceptance_criteria": "Some acceptance criteria without numbering"
    }
    
    # Mock LLM response with empty requirements
    # Normalized text is ONLY in summary (which becomes test_plan summary -> ticket_details description)
    mock_llm_response = {
        "requirements": [],  # Empty array - should trigger Path B/C
        "metadata": {"source": "jira", "source_id": "ATA-36"},
        "test_plan": {"api_tests": [], "ui_tests": []},
        "summary": """Normalized Requirements:
1) Automatic generation of Requirement Traceability Matrix (RTM)
   This capability shall automatically generate a Requirement Traceability Matrix (RTM) for each test plan.
2) RTM shall map requirements to test cases
   The RTM shall provide traceability between requirements and the test cases that validate them.
3) RTM shall include coverage status
   The RTM shall indicate whether each requirement is covered by at least one test case.

Scope (In):
- RTM generation functionality
- Requirement-to-test mapping
- Coverage status tracking

Scope (Out):
- Manual RTM creation
- External RTM tools"""
    }
    
    with patch('app.openai_client') as mock_openai:
        # Mock the LLM call to return empty requirements but normalized text in summary
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
            
            # Should have requirements populated from normalized text in test_plan summary (Path B)
            assert "requirements" in result
            assert len(result["requirements"]) >= 3, f"Should have at least 3 requirements from normalized text, got {len(result['requirements'])}"
            
            # All requirements should have source="normalized"
            for req in result["requirements"]:
                assert req.get("source") == "normalized", f"Requirement should have source='normalized', got {req.get('source')}"
                assert "id" in req, "Requirement should have an ID"
                assert req["id"].startswith("ATA-36-REQ-"), f"Requirement ID should start with ATA-36-REQ-, got {req['id']}"
                assert req.get("inferred") == False, "Requirement should have inferred=False"
            
            # Verify test_plan summary contains the normalized text (this ends up in ticket_details[].description)
            assert "summary" in result
            assert "Normalized Requirements:" in result["summary"], "test_plan summary should contain normalized requirements text"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
