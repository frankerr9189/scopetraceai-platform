"""
Unit tests for Jira writeback mapping functions.
"""
import sys
import os

# Add parent directory to path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from api.rewrite import (
    _extract_acceptance_criteria_from_requirements,
    _extract_description_from_requirements
)


def test_acceptance_criteria_aggregates_all_brs():
    """Test that acceptance criteria aggregates all BR statements from all requirements."""
    requirements = [
        {
            'id': 'REQ-001',
            'business_requirements': [
                {'statement': 'The system shall save the Jira API token.'},
                {'statement': 'The system shall encrypt the token.'}
            ]
        },
        {
            'id': 'REQ-002',
            'business_requirements': [
                {'statement': 'The system shall save the Jira Username/email.'}
            ]
        },
        {
            'id': 'REQ-003',
            'business_requirements': [
                {'statement': 'The system shall save the Jira Base URL.'}
            ]
        }
    ]
    
    result = _extract_acceptance_criteria_from_requirements(requirements)
    
    # Should have 4 bullets (4 BR statements total)
    assert result.count('* ') == 4, f"Expected 4 bullets, got {result.count('* ')}"
    
    # Should contain all statements
    assert 'The system shall save the Jira API token.' in result
    assert 'The system shall encrypt the token.' in result
    assert 'The system shall save the Jira Username/email.' in result
    assert 'The system shall save the Jira Base URL.' in result
    
    # Should be in deterministic order (REQ-001 BRs, then REQ-002, then REQ-003)
    lines = result.split('\n')
    assert 'The system shall save the Jira API token.' in lines[0]
    assert 'The system shall encrypt the token.' in lines[1]
    assert 'The system shall save the Jira Username/email.' in lines[2]
    assert 'The system shall save the Jira Base URL.' in lines[3]
    
    print("✅ test_acceptance_criteria_aggregates_all_brs: PASSED")


def test_description_includes_all_requirements():
    """Test that description includes all requirement summaries and descriptions."""
    requirements = [
        {
            'id': 'REQ-001',
            'summary': 'Save Jira API token',
            'description': 'The system shall save the Jira API token securely.',
            'scope_boundaries': {'in_scope': ['Token storage'], 'out_of_scope': ['Token validation']}
        },
        {
            'id': 'REQ-002',
            'summary': 'Save Jira Username',
            'description': 'The system shall save the Jira Username/email for authentication.',
            'scope_boundaries': {'in_scope': ['Username storage'], 'out_of_scope': ['Email validation']}
        },
        {
            'id': 'REQ-003',
            'summary': 'Save Jira Base URL',
            'description': 'The system shall save the Jira Base URL for API calls.',
            'scope_boundaries': {'in_scope': ['URL storage'], 'out_of_scope': []}
        }
    ]
    
    result = _extract_description_from_requirements(
        requirements=requirements,
        package_id='PKG-TEST',
        jira_summary='Configure Jira Settings',
        current_jira_description='Original description',
        gap_analysis=None,
        risk_analysis=None
    )
    
    # Should contain all requirement summaries
    assert 'Save Jira API token' in result
    assert 'Save Jira Username' in result
    assert 'Save Jira Base URL' in result
    
    # Should contain all requirement descriptions
    assert 'The system shall save the Jira API token securely.' in result
    assert 'The system shall save the Jira Username/email for authentication.' in result
    assert 'The system shall save the Jira Base URL for API calls.' in result
    
    # Should contain scope sections
    assert 'Scope (In):' in result
    assert 'Token storage' in result
    assert 'Username storage' in result
    assert 'URL storage' in result
    
    assert 'Scope (Out):' in result
    assert 'Token validation' in result
    assert 'Email validation' in result
    
    # Should preserve original description
    assert '--- Original Jira Description (preserved) ---' in result
    assert 'Original description' in result
    
    print("✅ test_description_includes_all_requirements: PASSED")


def test_description_includes_gaps_when_present():
    """Test that description includes gaps section when gaps exist."""
    requirements = [
        {
            'id': 'REQ-001',
            'summary': 'Test',
            'description': 'Test desc',
            'scope_boundaries': {'in_scope': [], 'out_of_scope': []}
        }
    ]
    
    gap_analysis = {
        'gaps': ['Missing error handling', 'No timeout configuration']
    }
    
    result = _extract_description_from_requirements(
        requirements=requirements,
        package_id='PKG-TEST',
        jira_summary='Test Summary',
        current_jira_description='Original',
        gap_analysis=gap_analysis,
        risk_analysis=None
    )
    
    assert 'Identified Gaps:' in result
    assert 'Missing error handling' in result
    assert 'No timeout configuration' in result
    
    print("✅ test_description_includes_gaps_when_present: PASSED")


def test_description_includes_risks_when_present():
    """Test that description includes risks section when risks exist."""
    requirements = [
        {
            'id': 'REQ-001',
            'summary': 'Test',
            'description': 'Test desc',
            'scope_boundaries': {'in_scope': [], 'out_of_scope': []}
        }
    ]
    
    risk_analysis = {
        'risks': ['Token exposure risk', 'Username validation needed'],
        'risk_level': 'medium'
    }
    
    result = _extract_description_from_requirements(
        requirements=requirements,
        package_id='PKG-TEST',
        jira_summary='Test Summary',
        current_jira_description='Original',
        gap_analysis=None,
        risk_analysis=risk_analysis
    )
    
    assert 'Identified Risks:' in result
    assert 'Token exposure risk' in result
    assert 'Username validation needed' in result
    assert 'Risk Level: medium' in result
    
    print("✅ test_description_includes_risks_when_present: PASSED")


def test_description_omits_gaps_when_empty():
    """Test that description omits gaps section when no meaningful gaps exist."""
    requirements = [
        {
            'id': 'REQ-001',
            'summary': 'Test',
            'description': 'Test desc',
            'scope_boundaries': {'in_scope': [], 'out_of_scope': []}
        }
    ]
    
    gap_analysis = {
        'gaps': []
    }
    
    result = _extract_description_from_requirements(
        requirements=requirements,
        package_id='PKG-TEST',
        jira_summary='Test Summary',
        current_jira_description='Original',
        gap_analysis=gap_analysis,
        risk_analysis=None
    )
    
    assert 'Identified Gaps:' not in result
    
    print("✅ test_description_omits_gaps_when_empty: PASSED")


def test_description_omits_risks_when_empty():
    """Test that description omits risks section when no meaningful risks exist."""
    requirements = [
        {
            'id': 'REQ-001',
            'summary': 'Test',
            'description': 'Test desc',
            'scope_boundaries': {'in_scope': [], 'out_of_scope': []}
        }
    ]
    
    risk_analysis = {
        'risks': [],
        'risk_level': 'low'
    }
    
    result = _extract_description_from_requirements(
        requirements=requirements,
        package_id='PKG-TEST',
        jira_summary='Test Summary',
        current_jira_description='Original',
        gap_analysis=None,
        risk_analysis=risk_analysis
    )
    
    assert 'Identified Risks:' not in result
    
    print("✅ test_description_omits_risks_when_empty: PASSED")


def test_description_filters_na_values():
    """Test that description filters out 'N/A' values from gaps and risks."""
    requirements = []
    
    gap_analysis = {
        'gaps': ['Real gap', 'N/A', 'Another gap']
    }
    
    risk_analysis = {
        'risks': ['Real risk', 'N/A'],
        'risk_level': 'high'
    }
    
    result = _extract_description_from_requirements(
        requirements=requirements,
        package_id='PKG-TEST',
        jira_summary='Test',
        current_jira_description='Original',
        gap_analysis=gap_analysis,
        risk_analysis=risk_analysis
    )
    
    # Should contain real values
    assert 'Real gap' in result
    assert 'Another gap' in result
    assert 'Real risk' in result
    
    # Should not contain N/A in gaps/risks sections
    gaps_section = result.split('Identified Gaps:')[1].split('Identified Risks:')[0] if 'Identified Gaps:' in result else ''
    risks_section = result.split('Identified Risks:')[1].split('--- Original')[0] if 'Identified Risks:' in result else ''
    
    assert 'N/A' not in gaps_section or gaps_section.count('N/A') == 0
    assert 'N/A' not in risks_section or risks_section.count('N/A') == 0
    
    print("✅ test_description_filters_na_values: PASSED")


if __name__ == '__main__':
    print("Running mapping tests...\n")
    
    test_acceptance_criteria_aggregates_all_brs()
    test_description_includes_all_requirements()
    test_description_includes_gaps_when_present()
    test_description_includes_risks_when_present()
    test_description_omits_gaps_when_empty()
    test_description_omits_risks_when_empty()
    test_description_filters_na_values()
    
    print("\n✅ All tests passed!")
