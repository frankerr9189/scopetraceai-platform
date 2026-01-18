"""
Unit tests for Jira create functionality (Phase 4B).
"""
import sys
import os

# Add parent directory to path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from api.rewrite import (
    _extract_acceptance_criteria_from_requirements,
    _extract_description_from_requirements,
    _check_create_idempotency,
    _compute_create_checksum
)
from services.jira_client import JiraClient, JiraClientError
from unittest.mock import Mock


def test_acceptance_criteria_aggregates_all_brs():
        """Test that acceptance criteria aggregates all business_requirements across all requirements."""
        requirements = [
            {
                "id": "REQ-001",
                "summary": "First requirement",
                "business_requirements": [
                    {"statement": "The system shall save the Jira API token."},
                    {"statement": "The system shall save the Jira Username/email."}
                ]
            },
            {
                "id": "REQ-002",
                "summary": "Second requirement",
                "business_requirements": [
                    {"statement": "The system shall save the Jira Base URL."}
                ]
            },
            {
                "id": "REQ-003",
                "summary": "Third requirement",
                "business_requirements": [
                    {"statement": "The system shall validate credentials."},
                    {"statement": "The system shall handle errors gracefully."}
                ]
            }
        ]
        
        result = _extract_acceptance_criteria_from_requirements(requirements)
        
        # Should contain 5 bullets (one per BR statement)
        lines = result.strip().split('\n')
        assert len(lines) == 5, f"Expected 5 bullets, got {len(lines)}"
        
        # Check all statements are present
        assert "* The system shall save the Jira API token." in result
        assert "* The system shall save the Jira Username/email." in result
        assert "* The system shall save the Jira Base URL." in result
        assert "* The system shall validate credentials." in result
        assert "* The system shall handle errors gracefully." in result
        
        # Check ordering (REQ-001 BRs first, then REQ-002, then REQ-003)
        lines_list = [line.strip() for line in lines]
        assert lines_list[0] == "* The system shall save the Jira API token."
        assert lines_list[1] == "* The system shall save the Jira Username/email."
        assert lines_list[2] == "* The system shall save the Jira Base URL."
        assert lines_list[3] == "* The system shall validate credentials."
        assert lines_list[4] == "* The system shall handle errors gracefully."
        
        print("✅ test_acceptance_criteria_aggregates_all_brs: PASSED")


def test_description_contains_all_requirements():
        """Test that description contains all requirement summaries and preserves original input."""
        requirements = [
            {
                "id": "REQ-001",
                "summary": "First requirement",
                "description": "First requirement description",
                "scope_boundaries": {
                    "in_scope": ["Feature A"],
                    "out_of_scope": ["Feature B"]
                }
            },
            {
                "id": "REQ-002",
                "summary": "Second requirement",
                "description": "Second requirement description",
                "scope_boundaries": {
                    "in_scope": ["Feature C"],
                    "out_of_scope": []
                }
            },
            {
                "id": "REQ-003",
                "summary": "Third requirement",
                "description": "Third requirement description",
                "scope_boundaries": {
                    "in_scope": [],
                    "out_of_scope": ["Feature D"]
                }
            }
        ]
        
        original_input = "Original free-form input text"
        package_id = "PKG-123"
        summary = "Test Summary"
        
        result = _extract_description_from_requirements(
            requirements=requirements,
            package_id=package_id,
            jira_summary=summary,
            current_jira_description=original_input
        )
        
        # Check all requirement summaries are present
        assert "1) First requirement" in result
        assert "2) Second requirement" in result
        assert "3) Third requirement" in result
        
        # Check all requirement descriptions are present
        assert "First requirement description" in result
        assert "Second requirement description" in result
        assert "Third requirement description" in result
        
        # Check original input is preserved
        assert "--- Original Jira Description (preserved) ---" in result
        assert original_input in result
        
        # Check scope boundaries are included
        assert "Scope (In):" in result
        assert "- Feature A" in result
        assert "- Feature C" in result
        assert "Scope (Out):" in result
        assert "- Feature B" in result
        assert "- Feature D" in result
        
        print("✅ test_description_contains_all_requirements: PASSED")


def test_description_omits_gaps_when_na():
        """Test that description omits gaps section when gaps are 'N/A'."""
        requirements = [
            {
                "id": "REQ-001",
                "summary": "Test requirement",
                "description": "Test description"
            }
        ]
        
        gap_analysis = {
            "gaps": ["N/A"]
        }
        
        result = _extract_description_from_requirements(
            requirements=requirements,
            package_id="PKG-123",
            jira_summary="Test Summary",
            current_jira_description="Original input",
            gap_analysis=gap_analysis
        )
        
        # Should not contain gaps section
        assert "Identified Gaps:" not in result
        
        print("✅ test_description_omits_gaps_when_na: PASSED")


def test_description_includes_meaningful_gaps():
        """Test that description includes gaps section when gaps are meaningful."""
        requirements = [
            {
                "id": "REQ-001",
                "summary": "Test requirement",
                "description": "Test description"
            }
        ]
        
        gap_analysis = {
            "gaps": ["Missing API documentation", "No error handling"]
        }
        
        result = _extract_description_from_requirements(
            requirements=requirements,
            package_id="PKG-123",
            jira_summary="Test Summary",
            current_jira_description="Original input",
            gap_analysis=gap_analysis
        )
        
        # Should contain gaps section
        assert "Identified Gaps:" in result
        assert "- Missing API documentation" in result
        assert "- No error handling" in result
        
        print("✅ test_description_includes_meaningful_gaps: PASSED")


def test_description_includes_risks_with_level():
        """Test that description includes risks section with risk level."""
        requirements = [
            {
                "id": "REQ-001",
                "summary": "Test requirement",
                "description": "Test description"
            }
        ]
        
        risk_analysis = {
            "risks": ["Security vulnerability", "Performance impact"],
            "risk_level": "High"
        }
        
        result = _extract_description_from_requirements(
            requirements=requirements,
            package_id="PKG-123",
            jira_summary="Test Summary",
            current_jira_description="Original input",
            risk_analysis=risk_analysis
        )
        
        # Should contain risks section
        assert "Identified Risks:" in result
        assert "- Security vulnerability" in result
        assert "- Performance impact" in result
        assert "Risk Level: High" in result
        
        print("✅ test_description_includes_risks_with_level: PASSED")


def test_description_omits_risks_when_na():
        """Test that description omits risks section when risks are 'N/A'."""
        requirements = [
            {
                "id": "REQ-001",
                "summary": "Test requirement",
                "description": "Test description"
            }
        ]
        
        risk_analysis = {
            "risks": ["N/A"]
        }
        
        result = _extract_description_from_requirements(
            requirements=requirements,
            package_id="PKG-123",
            jira_summary="Test Summary",
            current_jira_description="Original input",
            risk_analysis=risk_analysis
        )
        
        # Should not contain risks section
        assert "Identified Risks:" not in result
        
        print("✅ test_description_omits_risks_when_na: PASSED")


def test_idempotency_returns_existing_issue_when_label_and_hash_match():
        """Test that idempotency check returns existing issue key when label and hash match."""
        package_id = "PKG-123"
        checksum = "sha256:abc123"
        
        # Mock JiraClient
        mock_client = Mock(spec=JiraClient)
        mock_client.search_issues.return_value = [
            {"issue_key": "PROJ-456", "summary": "Existing issue"}
        ]
        mock_client.list_comments.return_value = [
            {
                "id": "10000",
                "body": f"Some comment\n[ATA-BA-WB v1.0.0 | Hash: {checksum}]",
                "created": "2024-01-01T00:00:00Z",
                "author": "test@example.com"
            }
        ]
        
        result = _check_create_idempotency(mock_client, package_id, checksum)
        
        assert result == "PROJ-456"
        mock_client.search_issues.assert_called_once_with('labels = "reqpkg_PKG-123"')
        mock_client.list_comments.assert_called_once_with("PROJ-456")
        
        print("✅ test_idempotency_returns_existing_issue_when_label_and_hash_match: PASSED")


def test_idempotency_returns_none_when_no_label_match():
        """Test that idempotency check returns None when no issue with label exists."""
        package_id = "PKG-123"
        checksum = "sha256:abc123"
        
        # Mock JiraClient
        mock_client = Mock(spec=JiraClient)
        mock_client.search_issues.return_value = []
        
        result = _check_create_idempotency(mock_client, package_id, checksum)
        
        assert result is None
        mock_client.search_issues.assert_called_once_with('labels = "reqpkg_PKG-123"')
        mock_client.list_comments.assert_not_called()
        
        print("✅ test_idempotency_returns_none_when_no_label_match: PASSED")


def test_idempotency_returns_none_when_hash_mismatch():
        """Test that idempotency check returns None when label exists but hash doesn't match."""
        package_id = "PKG-123"
        checksum = "sha256:abc123"
        
        # Mock JiraClient
        mock_client = Mock(spec=JiraClient)
        mock_client.search_issues.return_value = [
            {"issue_key": "PROJ-456", "summary": "Existing issue"}
        ]
        mock_client.list_comments.return_value = [
            {
                "id": "10000",
                "body": "[ATA-BA-WB v1.0.0 | Hash: sha256:different]",
                "created": "2024-01-01T00:00:00Z",
                "author": "test@example.com"
            }
        ]
        
        result = _check_create_idempotency(mock_client, package_id, checksum)
        
        # Should return None because hash doesn't match
        assert result is None
        
        print("✅ test_idempotency_returns_none_when_hash_mismatch: PASSED")


def test_idempotency_handles_search_error_gracefully():
        """Test that idempotency check handles search errors gracefully."""
        package_id = "PKG-123"
        checksum = "sha256:abc123"
        
        # Mock JiraClient
        mock_client = Mock(spec=JiraClient)
        mock_client.search_issues.side_effect = JiraClientError("Search failed")
        
        result = _check_create_idempotency(mock_client, package_id, checksum)
        
        # Should return None on error (fail-safe)
        assert result is None
        
        print("✅ test_idempotency_handles_search_error_gracefully: PASSED")


def test_checksum_is_deterministic():
        """Test that checksum is deterministic for same inputs."""
        project_key = "PROJ"
        issue_type = "Story"
        summary = "Test Summary"
        description = "Test Description"
        acceptance_criteria = "* Test AC"
        package_id = "PKG-123"
        
        checksum1 = _compute_create_checksum(
            project_key, issue_type, summary, description, acceptance_criteria, package_id
        )
        checksum2 = _compute_create_checksum(
            project_key, issue_type, summary, description, acceptance_criteria, package_id
        )
        
        assert checksum1 == checksum2
        assert checksum1.startswith("sha256:")
        
        print("✅ test_checksum_is_deterministic: PASSED")


def test_checksum_changes_with_input():
        """Test that checksum changes when any input changes."""
        base_params = {
            "project_key": "PROJ",
            "issue_type": "Story",
            "summary": "Test Summary",
            "proposed_description": "Test Description",
            "proposed_acceptance_criteria": "* Test AC",
            "package_id": "PKG-123"
        }
        
        base_checksum = _compute_create_checksum(**base_params)
        
        # Change project_key
        params2 = base_params.copy()
        params2["project_key"] = "PROJ2"
        checksum2 = _compute_create_checksum(**params2)
        assert base_checksum != checksum2
        
        # Change summary
        params3 = base_params.copy()
        params3["summary"] = "Different Summary"
        checksum3 = _compute_create_checksum(**params3)
        assert base_checksum != checksum3
        
        print("✅ test_checksum_changes_with_input: PASSED")


if __name__ == "__main__":
    print("Running create tests...\n")
    
    test_acceptance_criteria_aggregates_all_brs()
    test_description_contains_all_requirements()
    test_description_omits_gaps_when_na()
    test_description_includes_meaningful_gaps()
    test_description_includes_risks_with_level()
    test_description_omits_risks_when_na()
    test_idempotency_returns_existing_issue_when_label_and_hash_match()
    test_idempotency_returns_none_when_no_label_match()
    test_idempotency_returns_none_when_hash_mismatch()
    test_idempotency_handles_search_error_gracefully()
    test_checksum_is_deterministic()
    test_checksum_changes_with_input()
    
    print("\n✅ All tests passed!")
