"""
Unit tests for input guardrails.
"""
import pytest
from app import app, MAX_TICKETS_PER_RUN, MAX_REQUIREMENTS_PER_PACKAGE, MAX_FREEFORM_CHARS, MAX_DOC_UPLOAD_MB


@pytest.fixture
def client():
    """Create Flask test client."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_max_tickets_per_run_guardrail(client):
    """Test that ticket count limit is enforced."""
    # Create request with too many tickets
    tickets = [{"ticket_id": f"TICKET-{i}"} for i in range(MAX_TICKETS_PER_RUN + 1)]
    
    response = client.post(
        "/generate-test-plan",
        json={"tickets": tickets},
        content_type="application/json"
    )
    
    assert response.status_code == 400
    data = response.get_json()
    assert "detail" in data
    assert f"Too many Jira tickets ({MAX_TICKETS_PER_RUN + 1})" in data["detail"]
    assert f"Max supported per run is {MAX_TICKETS_PER_RUN}" in data["detail"]


def test_max_tickets_per_run_within_limit(client, monkeypatch):
    """Test that valid ticket count passes guardrail."""
    # Mock the test plan generation to avoid actual processing
    def mock_generate(*args, **kwargs):
        return {"test_plan": {}, "audit_metadata": {}}
    
    tickets = [{"ticket_id": f"TICKET-{i}"} for i in range(MAX_TICKETS_PER_RUN)]
    
    # This should not raise a guardrail error (but may fail for other reasons like missing Jira)
    response = client.post(
        "/generate-test-plan",
        json={"tickets": tickets},
        content_type="application/json"
    )
    
    # Should not be a 400 guardrail error
    # (May be other errors like 500 if Jira is not configured, but not the guardrail)
    assert response.status_code != 400 or "Too many Jira tickets" not in response.get_data(as_text=True)


def test_empty_tickets_list_guardrail(client):
    """Test that empty tickets list is rejected."""
    response = client.post(
        "/generate-test-plan",
        json={"tickets": []},
        content_type="application/json"
    )
    
    assert response.status_code == 400
    data = response.get_json()
    assert "detail" in data
    assert "tickets must be a non-empty list" in data["detail"]


def test_missing_tickets_guardrail(client):
    """Test that missing tickets field is rejected."""
    response = client.post(
        "/generate-test-plan",
        json={},
        content_type="application/json"
    )
    
    assert response.status_code == 400
    data = response.get_json()
    assert "detail" in data
    assert "tickets must be a non-empty list" in data["detail"]
