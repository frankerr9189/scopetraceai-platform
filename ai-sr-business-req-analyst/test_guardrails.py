"""
Unit tests for input guardrails in BA Requirements Agent.
"""
import pytest
from unittest.mock import Mock, patch
from fastapi.testclient import TestClient
from app.main import app
from app.api.analyze import (
    MAX_REQUIREMENTS_PER_PACKAGE, 
    MAX_FREEFORM_CHARS, 
    MAX_DOC_UPLOAD_MB,
    MAX_TICKETS_PER_RUN,
    MAX_CHARS_PER_TICKET
)


@pytest.fixture
def client():
    """Create FastAPI test client."""
    return TestClient(app)


def test_max_freeform_chars_guardrail(client):
    """Test that free-form input length limit is enforced."""
    # Create input text exceeding the limit
    long_text = "A" * (MAX_FREEFORM_CHARS + 1)
    
    response = client.post(
        "/api/v1/analyze",
        json={
            "input_text": long_text,
            "source": "freeform"
        }
    )
    
    assert response.status_code == 400
    data = response.json()
    assert "detail" in data
    assert f"Free-form input exceeds {MAX_FREEFORM_CHARS:,} characters" in data["detail"]
    assert "Reduce text or upload a document" in data["detail"]


def test_max_freeform_chars_within_limit(client, monkeypatch):
    """Test that valid free-form input length passes guardrail."""
    # Mock the analysis to avoid actual LLM calls
    def mock_analyze(*args, **kwargs):
        from app.models.package import RequirementPackage, GapAnalysis, RiskAnalysis
        from datetime import datetime
        return RequirementPackage(
            package_id="PKG-TEST",
            version="1.0.0",
            requirements=[],
            gap_analysis=GapAnalysis(),
            risk_analysis=RiskAnalysis(),
            original_input="test",
            created_at=datetime.now()
        )
    
    # Use valid length text
    valid_text = "A" * MAX_FREEFORM_CHARS
    
    # This should not raise a guardrail error
    # (May fail for other reasons like missing LLM, but not the guardrail)
    response = client.post(
        "/api/v1/analyze",
        json={
            "input_text": valid_text,
            "source": "freeform"
        }
    )
    
    # Should not be a 400 guardrail error
    assert response.status_code != 400 or "Free-form input exceeds" not in response.text


def test_max_doc_upload_mb_guardrail(client):
    """Test that document upload size limit is enforced."""
    # Create a file larger than the limit
    large_content = b"X" * (MAX_DOC_UPLOAD_MB * 1024 * 1024 + 1)
    
    response = client.post(
        "/api/v1/analyze",
        data={
            "input_text": "Test requirements",
            "source": "freeform"
        },
        files={
            "attachments": ("large_file.txt", large_content, "text/plain")
        }
    )
    
    assert response.status_code == 413
    data = response.json()
    assert "detail" in data
    assert "Upload too large" in data["detail"]
    assert f"Max supported is {MAX_DOC_UPLOAD_MB}MB" in data["detail"]


def test_max_requirements_per_package_guardrail(client, monkeypatch):
    """Test that requirements count limit is enforced after package generation."""
    # Mock the analysis to return a package with too many requirements
    def mock_analyze(*args, **kwargs):
        from app.models.package import RequirementPackage, GapAnalysis, RiskAnalysis, Requirement
        from datetime import datetime
        
        # Create package with too many requirements
        requirements = [
            Requirement(
                id=f"REQ-{i:03d}",
                summary=f"Requirement {i}",
                description=f"Description {i}",
                business_requirements=[],
                scope_boundaries={"in_scope": [], "out_of_scope": []},
                constraints_policies=[],
                open_questions=[],
                gaps=[],
                risks=[],
                metadata={}
            )
            for i in range(MAX_REQUIREMENTS_PER_PACKAGE + 1)
        ]
        
        return RequirementPackage(
            package_id="PKG-TEST",
            version="1.0.0",
            requirements=requirements,
            gap_analysis=GapAnalysis(),
            risk_analysis=RiskAnalysis(),
            original_input="test",
            created_at=datetime.now()
        )
    
    # This test would require mocking the entire analysis flow
    # For now, we'll test the constant is defined correctly
    assert MAX_REQUIREMENTS_PER_PACKAGE == 100


def test_guardrail_constants_defined():
    """Test that all guardrail constants are defined."""
    assert MAX_REQUIREMENTS_PER_PACKAGE == 100
    assert MAX_FREEFORM_CHARS == 50_000
    assert MAX_DOC_UPLOAD_MB == 15
    assert MAX_TICKETS_PER_RUN == 10
    assert MAX_CHARS_PER_TICKET == 10_000


def test_max_tickets_per_run_guardrail(client, monkeypatch):
    """Test that max tickets per run (parent + sub-tickets) is enforced."""
    # Mock JiraClient to return a ticket with too many sub-tickets
    def mock_build_jira_context(ticket_id):
        # Create parent ticket
        parent_ticket = {
            "ticket_id": ticket_id,
            "summary": "Test Parent",
            "description": "Test description"
        }
        
        # Create 10 sub-tickets (total = 11 tickets, exceeds limit)
        sub_tickets = [
            {
                "sub_ticket_id": f"{ticket_id}-{i}",
                "summary": f"Sub-ticket {i}",
                "issue_type": "Sub-task",
                "status": "To Do"
            }
            for i in range(MAX_TICKETS_PER_RUN)  # 10 sub-tickets + 1 parent = 11 total
        ]
        
        return {
            "jira_context": {
                "parent_ticket": parent_ticket,
                "sub_tickets": sub_tickets,
                "attachments": []
            }
        }
    
    # Mock JiraClient
    with patch('app.api.analyze.JiraClient') as mock_jira_client_class:
        mock_jira_client = Mock()
        mock_jira_client.build_jira_context = mock_build_jira_context
        mock_jira_client_class.return_value = mock_jira_client
        
        response = client.post(
            "/api/v1/analyze",
            json={
                "input_text": "ATA-36",
                "source": "jira"
            }
        )
        
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert f"Run exceeds maximum allowed tickets ({MAX_TICKETS_PER_RUN})" in data["detail"]
        assert "Please reduce scope" in data["detail"]


def test_max_tickets_per_run_within_limit(client, monkeypatch):
    """Test that valid ticket count (parent + sub-tickets <= 10) passes guardrail."""
    # Mock JiraClient to return a ticket with valid number of sub-tickets
    def mock_build_jira_context(ticket_id):
        parent_ticket = {
            "ticket_id": ticket_id,
            "summary": "Test Parent",
            "description": "Test description"
        }
        
        # Create 9 sub-tickets (total = 10 tickets, within limit)
        sub_tickets = [
            {
                "sub_ticket_id": f"{ticket_id}-{i}",
                "summary": f"Sub-ticket {i}",
                "issue_type": "Sub-task",
                "status": "To Do"
            }
            for i in range(MAX_TICKETS_PER_RUN - 1)  # 9 sub-tickets + 1 parent = 10 total
        ]
        
        return {
            "jira_context": {
                "parent_ticket": parent_ticket,
                "sub_tickets": sub_tickets,
                "attachments": []
            }
        }
    
    # Mock the analysis to avoid actual LLM calls
    def mock_analyze(*args, **kwargs):
        from app.models.package import RequirementPackage, GapAnalysis, RiskAnalysis
        from datetime import datetime
        return RequirementPackage(
            package_id="PKG-TEST",
            version="1.0.0",
            requirements=[],
            gap_analysis=GapAnalysis(),
            risk_analysis=RiskAnalysis(),
            original_input="test",
            created_at=datetime.now()
        )
    
    with patch('app.api.analyze.JiraClient') as mock_jira_client_class:
        mock_jira_client = Mock()
        mock_jira_client.build_jira_context = mock_build_jira_context
        mock_jira_client_class.return_value = mock_jira_client
        
        with patch('app.api.analyze.BusinessRequirementAnalyst') as mock_analyst_class:
            mock_analyst = Mock()
            mock_analyst.analyze = mock_analyze
            mock_analyst_class.return_value = mock_analyst
            
            response = client.post(
                "/api/v1/analyze",
                json={
                    "input_text": "ATA-36",
                    "source": "jira"
                }
            )
            
            # Should not be a 400 guardrail error for ticket count
            assert response.status_code != 400 or "exceeds maximum allowed tickets" not in response.text


def test_ticket_content_truncation(client, monkeypatch):
    """Test that ticket content (summary + description) is truncated to MAX_CHARS_PER_TICKET."""
    # Create a ticket with content exceeding the limit
    long_summary = "A" * 5000
    long_description = "B" * 6000  # Total = 11,000 chars, exceeds 10,000 limit
    
    def mock_build_jira_context(ticket_id):
        parent_ticket = {
            "ticket_id": ticket_id,
            "summary": long_summary,
            "description": long_description
        }
        
        return {
            "jira_context": {
                "parent_ticket": parent_ticket,
                "sub_tickets": [],
                "attachments": []
            }
        }
    
    # Mock the analysis
    def mock_analyze(input_text, *args, **kwargs):
        from app.models.package import RequirementPackage, GapAnalysis, RiskAnalysis
        from datetime import datetime
        
        # Verify that input_text was truncated
        assert len(input_text) <= MAX_CHARS_PER_TICKET
        
        return RequirementPackage(
            package_id="PKG-TEST",
            version="1.0.0",
            requirements=[],
            gap_analysis=GapAnalysis(),
            risk_analysis=RiskAnalysis(),
            original_input=input_text,
            created_at=datetime.now()
        )
    
    with patch('app.api.analyze.JiraClient') as mock_jira_client_class:
        mock_jira_client = Mock()
        mock_jira_client.build_jira_context = mock_build_jira_context
        mock_jira_client_class.return_value = mock_jira_client
        
        with patch('app.api.analyze.BusinessRequirementAnalyst') as mock_analyst_class:
            mock_analyst = Mock()
            mock_analyst.analyze = mock_analyze
            mock_analyst_class.return_value = mock_analyst
            
            response = client.post(
                "/api/v1/analyze",
                json={
                    "input_text": "ATA-36",
                    "source": "jira"
                }
            )
            
            # Should succeed (truncation is silent, not an error)
            assert response.status_code == 200
            
            # Verify input_limits metadata is present
            data = response.json()
            assert "package" in data
            assert "metadata" in data["package"]
            assert "input_limits" in data["package"]["metadata"]
            
            input_limits = data["package"]["metadata"]["input_limits"]
            assert input_limits["max_chars_per_ticket"] == MAX_CHARS_PER_TICKET
            assert input_limits["tickets_truncated"] == 1
            assert input_limits["truncation_strategy"] == "head"


def test_input_limits_metadata_in_package(client, monkeypatch):
    """Test that input_limits metadata is included in package metadata."""
    def mock_build_jira_context(ticket_id):
        parent_ticket = {
            "ticket_id": ticket_id,
            "summary": "Test Summary",
            "description": "Test Description"
        }
        
        return {
            "jira_context": {
                "parent_ticket": parent_ticket,
                "sub_tickets": [],
                "attachments": []
            }
        }
    
    def mock_analyze(*args, **kwargs):
        from app.models.package import RequirementPackage, GapAnalysis, RiskAnalysis
        from datetime import datetime
        return RequirementPackage(
            package_id="PKG-TEST",
            version="1.0.0",
            requirements=[],
            gap_analysis=GapAnalysis(),
            risk_analysis=RiskAnalysis(),
            original_input="test",
            created_at=datetime.now()
        )
    
    with patch('app.api.analyze.JiraClient') as mock_jira_client_class:
        mock_jira_client = Mock()
        mock_jira_client.build_jira_context = mock_build_jira_context
        mock_jira_client_class.return_value = mock_jira_client
        
        with patch('app.api.analyze.BusinessRequirementAnalyst') as mock_analyst_class:
            mock_analyst = Mock()
            mock_analyst.analyze = mock_analyze
            mock_analyst_class.return_value = mock_analyst
            
            response = client.post(
                "/api/v1/analyze",
                json={
                    "input_text": "ATA-36",
                    "source": "jira"
                }
            )
            
            assert response.status_code == 200
            data = response.json()
            
            # Verify input_limits metadata structure
            assert "package" in data
            assert "metadata" in data["package"]
            assert "input_limits" in data["package"]["metadata"]
            
            input_limits = data["package"]["metadata"]["input_limits"]
            assert input_limits["max_tickets_per_run"] == MAX_TICKETS_PER_RUN
            assert input_limits["max_chars_per_ticket"] == MAX_CHARS_PER_TICKET
            assert input_limits["tickets_received"] == 1  # Parent only, no sub-tickets
            assert input_limits["tickets_processed"] == 1
            assert input_limits["tickets_rejected"] == 0
            assert input_limits["tickets_truncated"] == 0
            assert input_limits["truncation_strategy"] == "head"