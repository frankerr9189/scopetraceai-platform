"""
Regression test to ensure free_text input source decrements trial counter correctly.

This test verifies that:
1. Free-text requests require authentication (401 if missing)
2. Free-text requests check entitlements (same as jira)
3. Free-text successful runs decrement trial_requirements_runs_remaining
4. Free-text failures do NOT decrement
"""
import pytest
from unittest.mock import Mock, patch, AsyncMock
from fastapi import HTTPException
from fastapi.testclient import TestClient
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Mock the analyst to avoid LLM calls
@pytest.fixture
def mock_analyst():
    """Mock BusinessRequirementAnalyst to avoid actual LLM calls."""
    with patch('app.api.analyze.BusinessRequirementAnalyst') as mock:
        mock_instance = Mock()
        mock_instance.analyze = AsyncMock(return_value=Mock(
            package_id="test-package-123",
            requirements=[Mock(id="REQ-1", statement="Test requirement")],
            metadata={},
            gap_analysis=Mock(gaps=[]),
            risk_analysis=Mock(risk_level="low")
        ))
        mock.return_value = mock_instance
        yield mock_instance


def test_free_text_requires_auth():
    """Test that free-text requests without auth return 401."""
    from app.main import app
    client = TestClient(app)
    
    # Request without Authorization header
    response = client.post(
        "/analyze",
        json={
            "input_text": "The system shall do something.",
            "source": ""
        }
    )
    
    assert response.status_code == 401, "Should return 401 when Authorization header is missing"
    assert "Authorization" in response.json().get("detail", "").lower() or "required" in response.json().get("detail", "").lower()


def test_free_text_checks_entitlements(mock_analyst):
    """Test that free-text requests check entitlements."""
    from app.main import app
    from unittest.mock import patch
    
    # Mock JWT token
    mock_payload = {
        "tenant_id": "test-tenant-id",
        "sub": "test-user-id"
    }
    
    with patch('jwt.decode', return_value=mock_payload):
        with patch('app.api.analyze.check_entitlement') as mock_check:
            mock_check.return_value = (False, "PAYWALLED", "Paywalled", 0)
            
            client = TestClient(app)
            response = client.post(
                "/analyze",
                json={
                    "input_text": "The system shall do something.",
                    "source": ""
                },
                headers={"Authorization": "Bearer fake-token"}
            )
            
            # Should be blocked by entitlement check
            assert response.status_code == 403, "Should return 403 when paywalled"
            mock_check.assert_called_once()


def test_free_text_decrements_on_success(mock_analyst):
    """Test that free-text successful runs decrement trial counter."""
    from app.main import app
    from unittest.mock import patch, MagicMock
    
    # Mock JWT token
    mock_payload = {
        "tenant_id": "test-tenant-id",
        "sub": "test-user-id"
    }
    
    # Mock database and entitlements
    mock_db = MagicMock()
    mock_get_db = MagicMock(return_value=iter([mock_db]))
    
    with patch('jwt.decode', return_value=mock_payload):
        with patch('app.api.analyze.check_entitlement', return_value=(True, None, "Trial", 3)):
            with patch('app.api.analyze.get_db', mock_get_db):
                with patch('app.api.analyze.consume_trial_run') as mock_consume:
                    with patch('app.api.analyze.save_run'):
                        with patch('app.api.analyze.record_usage_event'):
                            client = TestClient(app)
                            response = client.post(
                                "/analyze",
                                json={
                                    "input_text": "The system shall do something.",
                                    "source": ""
                                },
                                headers={"Authorization": "Bearer fake-token"}
                            )
                            
                            # Should succeed
                            assert response.status_code == 200, f"Should return 200 on success, got {response.status_code}"
                            
                            # Should have called consume_trial_run
                            mock_consume.assert_called_once_with(mock_db, "test-tenant-id")


def test_free_text_no_decrement_on_failure(mock_analyst):
    """Test that free-text failures do NOT decrement trial counter."""
    from app.main import app
    from unittest.mock import patch
    
    # Mock JWT token
    mock_payload = {
        "tenant_id": "test-tenant-id",
        "sub": "test-user-id"
    }
    
    # Mock analyst to raise AnalysisError
    mock_analyst.analyze.side_effect = Exception("Analysis failed")
    
    with patch('jwt.decode', return_value=mock_payload):
        with patch('app.api.analyze.check_entitlement', return_value=(True, None, "Trial", 3)):
            with patch('app.api.analyze.consume_trial_run') as mock_consume:
                client = TestClient(app)
                try:
                    response = client.post(
                        "/analyze",
                        json={
                            "input_text": "The system shall do something.",
                            "source": ""
                        },
                        headers={"Authorization": "Bearer fake-token"}
                    )
                except:
                    pass
                
                # Should NOT have called consume_trial_run on failure
                mock_consume.assert_not_called()
