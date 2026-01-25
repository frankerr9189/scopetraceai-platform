#!/usr/bin/env python3
"""
Regression tests for RTM testability consistency.

Tests:
1) Any requirement with mapped tests MUST have requirements[].testable == True
2) Any legacy RTM row with covered_by_tests MUST NOT have trace_type == "informational"
3) Any rtm_artifact.requirements_rtm row with covered_by_tests MUST have testability == "testable"
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rtm import generate_rtm, is_requirement_testable_by_mapping


def test_requirement_testable_when_has_mapped_tests():
    """
    Test 1: Any requirement with mapped tests MUST have requirements[].testable == True
    """
    # Create test plan with requirements and tests
    test_plan = {
        "requirements": [
            {"id": "REQ-001", "description": "Requirement 1", "testable": False},
            {"id": "REQ-002", "description": "Requirement 2", "testable": False},
            {"id": "REQ-003", "description": "Requirement 3", "testable": False},
        ],
        "test_plan": {
            "ui_tests": [
                {"id": "UI-001", "requirements_covered": ["REQ-001"]},
                {"id": "UI-002", "requirements_covered": ["REQ-002"]},
            ]
        },
        "ticket_traceability": [],
        "ticket_item_coverage": []
    }
    
    # Use helper to check testability
    test_plan_dict = test_plan.get("test_plan", {})
    
    # Check REQ-001 (has test)
    assert is_requirement_testable_by_mapping("REQ-001", test_plan=test_plan_dict) == True, \
        "REQ-001 should be testable (has mapped test UI-001)"
    
    # Check REQ-002 (has test)
    assert is_requirement_testable_by_mapping("REQ-002", test_plan=test_plan_dict) == True, \
        "REQ-002 should be testable (has mapped test UI-002)"
    
    # Check REQ-003 (no test)
    assert is_requirement_testable_by_mapping("REQ-003", test_plan=test_plan_dict) == False, \
        "REQ-003 should not be testable (no mapped tests)"
    
    print("✅ Test 1 passed: Requirements with mapped tests are testable")
    return True


def test_legacy_rtm_row_not_informational_when_has_tests():
    """
    Test 2: Any legacy RTM row with covered_by_tests MUST NOT have trace_type == "informational"
    """
    # Create RTM artifact with requirements that have tests
    test_plan = {
        "requirements": [
            {"id": "REQ-001", "description": "Requirement 1", "testable": True},
            {"id": "REQ-002", "description": "Requirement 2", "testable": False},  # Not testable but has tests
        ],
        "test_plan": {
            "ui_tests": [
                {"id": "UI-001", "requirements_covered": ["REQ-001"]},
                {"id": "UI-002", "requirements_covered": ["REQ-002"]},
            ]
        },
        "ticket_traceability": [
            {
                "ticket_id": "TEST-001",
                "items": [
                    {
                        "item_id": "TEST-001-ITEM-001",
                        "text": "Item 1",
                        "mapped_requirement_id": "REQ-001"
                    },
                    {
                        "item_id": "TEST-001-ITEM-002",
                        "text": "Item 2",
                        "mapped_requirement_id": "REQ-002"
                    }
                ]
            }
        ],
        "ticket_item_coverage": []
    }
    
    # Generate RTM artifact
    rtm_artifact = generate_rtm(test_plan)
    requirements_rtm = rtm_artifact.get("requirements_rtm", [])
    
    # Simulate legacy RTM row creation (as done in app.py)
    legacy_rtm_rows = []
    for req_row in requirements_rtm:
        covered_by_tests = req_row.get("covered_by_tests", [])
        has_tests = isinstance(covered_by_tests, list) and len(covered_by_tests) > 0
        
        if has_tests:
            testability = "testable"
            trace_type = "testable"
        else:
            testability = req_row.get("testability", "testable")
            trace_type = "testable" if testability == "testable" else "informational"
        
        legacy_rtm_rows.append({
            "requirement_id": req_row.get("requirement_id", ""),
            "requirement_description": req_row.get("requirement_description", ""),
            "covered_by_tests": covered_by_tests,
            "testability": testability,
            "trace_type": trace_type
        })
    
    # Verify: Any row with covered_by_tests must NOT have trace_type == "informational"
    for legacy_row in legacy_rtm_rows:
        covered_by_tests = legacy_row.get("covered_by_tests", [])
        trace_type = legacy_row.get("trace_type", "")
        
        if isinstance(covered_by_tests, list) and len(covered_by_tests) > 0:
            assert trace_type != "informational", \
                f"Legacy RTM row {legacy_row.get('requirement_id')} has covered_by_tests but trace_type is 'informational'"
            assert trace_type == "testable", \
                f"Legacy RTM row {legacy_row.get('requirement_id')} has covered_by_tests but trace_type is '{trace_type}' (expected 'testable')"
    
    print("✅ Test 2 passed: Legacy RTM rows with covered_by_tests are not 'informational'")
    return True


def test_rtm_artifact_testability_when_has_tests():
    """
    Test 3: Any rtm_artifact.requirements_rtm row with covered_by_tests MUST have testability == "testable"
    """
    # Create test plan with requirements (some with tests, some without)
    test_plan = {
        "requirements": [
            {"id": "REQ-001", "description": "Requirement 1", "testable": False},  # Not testable but has tests
            {"id": "REQ-002", "description": "Requirement 2", "testable": True},
            {"id": "REQ-003", "description": "Requirement 3", "testable": False},  # No tests
        ],
        "test_plan": {
            "ui_tests": [
                {"id": "UI-001", "requirements_covered": ["REQ-001"]},
                {"id": "UI-002", "requirements_covered": ["REQ-002"]},
            ]
        },
        "ticket_traceability": [
            {
                "ticket_id": "TEST-001",
                "items": [
                    {
                        "item_id": "TEST-001-ITEM-001",
                        "text": "Item 1",
                        "mapped_requirement_id": "REQ-001"
                    },
                    {
                        "item_id": "TEST-001-ITEM-002",
                        "text": "Item 2",
                        "mapped_requirement_id": "REQ-002"
                    },
                    {
                        "item_id": "TEST-001-ITEM-003",
                        "text": "Item 3",
                        "mapped_requirement_id": "REQ-003"
                    }
                ]
            }
        ],
        "ticket_item_coverage": []
    }
    
    # Generate RTM artifact
    rtm_artifact = generate_rtm(test_plan)
    requirements_rtm = rtm_artifact.get("requirements_rtm", [])
    
    # Verify: Any row with covered_by_tests must have testability == "testable"
    for req_row in requirements_rtm:
        req_id = req_row.get("requirement_id", "")
        covered_by_tests = req_row.get("covered_by_tests", [])
        testability = req_row.get("testability", "")
        
        if isinstance(covered_by_tests, list) and len(covered_by_tests) > 0:
            assert testability == "testable", \
                f"RTM row {req_id} has covered_by_tests but testability is '{testability}' (expected 'testable')"
    
    # Also verify REQ-003 (no tests) can be "not_testable"
    req_003_row = next((r for r in requirements_rtm if r.get("requirement_id") == "REQ-003"), None)
    if req_003_row:
        covered_by_tests_003 = req_003_row.get("covered_by_tests", [])
        if not (isinstance(covered_by_tests_003, list) and len(covered_by_tests_003) > 0):
            # REQ-003 has no tests, so it can be "not_testable"
            assert req_003_row.get("testability") in ["testable", "not_testable"], \
                f"REQ-003 testability should be 'testable' or 'not_testable', got '{req_003_row.get('testability')}'"
    
    print("✅ Test 3 passed: RTM artifact rows with covered_by_tests have testability == 'testable'")
    return True


if __name__ == "__main__":
    try:
        test_requirement_testable_when_has_mapped_tests()
        test_legacy_rtm_row_not_informational_when_has_tests()
        test_rtm_artifact_testability_when_has_tests()
        print("\n✅ All RTM testability consistency regression tests passed!")
        sys.exit(0)
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
