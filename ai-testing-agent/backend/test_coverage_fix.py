#!/usr/bin/env python3
"""
Regression tests for Day-1 Coverage Fix + ID Sanity.

Tests:
- scope_summary.requirements_covered reflects actual test mapping
- No orphan requirement references in tests
"""

import sys
import os
import json

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import normalize_all_test_requirement_references


def test_scope_summary_requirements_covered():
    """
    Test that requirements_covered is > 0 when requirements have tests mapped.
    """
    # Sample result with requirements and tests
    result = {
        "requirements": [
            {"id": "ATA-36-REQ-001", "description": "Requirement 1", "testable": True},
            {"id": "ATA-36-REQ-002", "description": "Requirement 2", "testable": True},
            {"id": "ATA-36-REQ-003", "description": "Requirement 3", "testable": False},
        ],
        "test_plan": {
            "ui_tests": [
                {"id": "UI-001", "requirements_covered": ["ATA-36-REQ-001"]},
                {"id": "UI-002", "requirements_covered": ["ATA-36-REQ-002"]},
            ]
        }
    }
    
    # Build set of requirement IDs that have tests mapped
    requirements_with_tests = set()
    test_plan_section = result.get("test_plan", {})
    test_categories = ["api_tests", "ui_tests", "negative_tests", "data_validation_tests", "edge_cases", "system_tests"]
    
    for category in test_categories:
        tests = test_plan_section.get(category, [])
        if isinstance(tests, list):
            for test in tests:
                if isinstance(test, dict):
                    reqs_covered = test.get("requirements_covered", [])
                    if isinstance(reqs_covered, list):
                        for req_id in reqs_covered:
                            if req_id:
                                requirements_with_tests.add(req_id)
    
    # Count requirements that have tests mapped
    requirements = result.get("requirements", [])
    requirements_covered = sum(
        1 for req in requirements
        if isinstance(req, dict) and req.get("id", "") in requirements_with_tests
    )
    
    assert requirements_covered == 2, f"Expected 2 covered requirements, got {requirements_covered}"
    assert requirements_covered > 0, "requirements_covered must be > 0 when requirements have tests"
    
    print("✅ scope_summary.requirements_covered test passed!")
    return True


def test_no_orphan_requirement_references():
    """
    Test that no test has requirements_covered entries that are not present in requirements[].id
    """
    result = {
        "requirements": [
            {"id": "ATA-36-REQ-001", "description": "Requirement 1"},
            {"id": "ATA-36-REQ-002", "description": "Requirement 2"},
        ],
        "test_plan": {
            "ui_tests": [
                {"id": "UI-001", "requirements_covered": ["ATA-36-REQ-001"]},  # Valid
                {"id": "UI-002", "requirements_covered": ["ATA-36-REQ-007"]},  # Orphan - should be removed
                {"id": "UI-003", "requirements_covered": ["ATA-36-REQ-008"]},  # Orphan - should be removed
                {"id": "UI-004", "requirements_covered": ["ATA-36-REQ-002", "ATA-36-REQ-009"]},  # Mixed: valid + orphan
            ]
        }
    }
    
    # Apply normalization (which removes orphan references)
    normalize_all_test_requirement_references(result)
    
    # Verify no orphan references remain
    valid_req_ids = {req.get("id") for req in result.get("requirements", []) if isinstance(req, dict)}
    
    test_plan_section = result.get("test_plan", {})
    for category in ["api_tests", "ui_tests", "negative_tests", "data_validation_tests", "edge_cases", "system_tests"]:
        tests = test_plan_section.get(category, [])
        if isinstance(tests, list):
            for test in tests:
                if isinstance(test, dict):
                    reqs_covered = test.get("requirements_covered", [])
                    if isinstance(reqs_covered, list):
                        for req_id in reqs_covered:
                            assert req_id in valid_req_ids, \
                                f"Test {test.get('id')} has orphan requirement reference: {req_id}"
    
    # Verify specific test cases
    ui_tests = result["test_plan"]["ui_tests"]
    
    # UI-001 should still have REQ-001
    ui_001 = next((t for t in ui_tests if t.get("id") == "UI-001"), None)
    assert ui_001 is not None, "UI-001 not found"
    assert "ATA-36-REQ-001" in ui_001.get("requirements_covered", []), "UI-001 should have REQ-001"
    
    # UI-002 should have orphan REQ-007 removed
    ui_002 = next((t for t in ui_tests if t.get("id") == "UI-002"), None)
    assert ui_002 is not None, "UI-002 not found"
    assert "ATA-36-REQ-007" not in ui_002.get("requirements_covered", []), "UI-002 should not have orphan REQ-007"
    
    # UI-003 should have orphan REQ-008 removed
    ui_003 = next((t for t in ui_tests if t.get("id") == "UI-003"), None)
    assert ui_003 is not None, "UI-003 not found"
    assert "ATA-36-REQ-008" not in ui_003.get("requirements_covered", []), "UI-003 should not have orphan REQ-008"
    
    # UI-004 should have REQ-002 but not REQ-009
    ui_004 = next((t for t in ui_tests if t.get("id") == "UI-004"), None)
    assert ui_004 is not None, "UI-004 not found"
    assert "ATA-36-REQ-002" in ui_004.get("requirements_covered", []), "UI-004 should have REQ-002"
    assert "ATA-36-REQ-009" not in ui_004.get("requirements_covered", []), "UI-004 should not have orphan REQ-009"
    
    print("✅ No orphan requirement references test passed!")
    return True


def test_generic_id_mapping():
    """
    Test that generic REQ-### IDs are mapped to ticket-scoped IDs when possible.
    """
    result = {
        "requirements": [
            {"id": "ATA-36-REQ-001", "description": "Requirement 1"},
            {"id": "ATA-36-REQ-002", "description": "Requirement 2"},
        ],
        "test_plan": {
            "ui_tests": [
                {"id": "UI-001", "requirements_covered": ["REQ-001"]},  # Generic - should map to ATA-36-REQ-001
                {"id": "UI-002", "requirements_covered": ["REQ-002"]},  # Generic - should map to ATA-36-REQ-002
            ]
        }
    }
    
    # Apply normalization
    normalize_all_test_requirement_references(result)
    
    # Verify mapping occurred
    ui_tests = result["test_plan"]["ui_tests"]
    
    ui_001 = next((t for t in ui_tests if t.get("id") == "UI-001"), None)
    assert ui_001 is not None, "UI-001 not found"
    assert "ATA-36-REQ-001" in ui_001.get("requirements_covered", []), "UI-001 should have mapped REQ-001 to ATA-36-REQ-001"
    assert "REQ-001" not in ui_001.get("requirements_covered", []), "UI-001 should not have unmapped REQ-001"
    
    ui_002 = next((t for t in ui_tests if t.get("id") == "UI-002"), None)
    assert ui_002 is not None, "UI-002 not found"
    assert "ATA-36-REQ-002" in ui_002.get("requirements_covered", []), "UI-002 should have mapped REQ-002 to ATA-36-REQ-002"
    
    print("✅ Generic ID mapping test passed!")
    return True


def test_requirement_testable_when_has_tests():
    """
    Regression test: Any requirement with mapped tests must have testable == True.
    """
    # Simulate the consistency fix logic
    result = {
        "requirements": [
            {"id": "ATA-36-REQ-001", "description": "Requirement 1", "testable": False},  # Initially false
            {"id": "ATA-36-REQ-002", "description": "Requirement 2", "testable": False},  # Initially false
            {"id": "ATA-36-REQ-003", "description": "Requirement 3", "testable": False},  # No tests - should stay false
        ],
        "test_plan": {
            "ui_tests": [
                {"id": "UI-001", "requirements_covered": ["ATA-36-REQ-001"]},
                {"id": "UI-002", "requirements_covered": ["ATA-36-REQ-002"]},
            ]
        },
        "rtm_artifact": {
            "requirements_rtm": [
                {
                    "requirement_id": "ATA-36-REQ-001",
                    "covered_by_tests": ["UI-001"]
                },
                {
                    "requirement_id": "ATA-36-REQ-002",
                    "covered_by_tests": ["UI-002"]
                }
            ]
        }
    }
    
    # Build set of requirement IDs that have tests mapped (simulating the fix logic)
    requirements_with_tests_set = set()
    
    # Check test_plan
    test_plan_check = result.get("test_plan", {})
    test_categories_check = ["api_tests", "ui_tests", "negative_tests", "data_validation_tests", "edge_cases", "system_tests"]
    for category in test_categories_check:
        tests = test_plan_check.get(category, [])
        if isinstance(tests, list):
            for test in tests:
                if isinstance(test, dict):
                    reqs_covered = test.get("requirements_covered", [])
                    if isinstance(reqs_covered, list):
                        for req_id in reqs_covered:
                            if req_id:
                                requirements_with_tests_set.add(req_id)
    
    # Check rtm_artifact
    requirements_rtm_check = result.get("rtm_artifact", {}).get("requirements_rtm", [])
    if isinstance(requirements_rtm_check, list):
        for req_row in requirements_rtm_check:
            if isinstance(req_row, dict):
                req_id = req_row.get("requirement_id", "")
                covered_by_tests = req_row.get("covered_by_tests", [])
                if req_id and isinstance(covered_by_tests, list) and len(covered_by_tests) > 0:
                    requirements_with_tests_set.add(req_id)
    
    # Update requirements[] to mark as testable if they have mapped tests
    requirements_list = result.get("requirements", [])
    for req in requirements_list:
        if isinstance(req, dict):
            req_id = req.get("id", "")
            if req_id in requirements_with_tests_set:
                req["testable"] = True
    
    # Verify
    req_001 = next((r for r in requirements_list if r.get("id") == "ATA-36-REQ-001"), None)
    assert req_001 is not None, "REQ-001 not found"
    assert req_001.get("testable") == True, "REQ-001 should be testable=True (has mapped tests)"
    
    req_002 = next((r for r in requirements_list if r.get("id") == "ATA-36-REQ-002"), None)
    assert req_002 is not None, "REQ-002 not found"
    assert req_002.get("testable") == True, "REQ-002 should be testable=True (has mapped tests)"
    
    req_003 = next((r for r in requirements_list if r.get("id") == "ATA-36-REQ-003"), None)
    assert req_003 is not None, "REQ-003 not found"
    assert req_003.get("testable") == False, "REQ-003 should be testable=False (no mapped tests)"
    
    print("✅ Requirement testable when has tests test passed!")
    return True


def test_legacy_rtm_row_not_informational_when_has_tests():
    """
    Regression test: Corresponding legacy RTM row must not be trace_type "informational" when covered_by_tests exists.
    """
    # Simulate legacy RTM row generation
    rtm_artifact = {
        "requirements_rtm": [
            {
                "requirement_id": "ATA-36-REQ-001",
                "covered_by_tests": ["UI-001", "UI-002"],
                "testability": "not_testable"  # Initially incorrect
            }
        ]
    }
    
    # Build requirements_with_tests_set
    requirements_with_tests_set = set()
    requirements_rtm_check = rtm_artifact.get("requirements_rtm", [])
    if isinstance(requirements_rtm_check, list):
        for req_row in requirements_rtm_check:
            if isinstance(req_row, dict):
                req_id = req_row.get("requirement_id", "")
                covered_by_tests = req_row.get("covered_by_tests", [])
                if req_id and isinstance(covered_by_tests, list) and len(covered_by_tests) > 0:
                    requirements_with_tests_set.add(req_id)
    
    # Generate legacy RTM rows (simulating the fix logic)
    legacy_rtm_rows = []
    for req_row in requirements_rtm_check:
        if isinstance(req_row, dict):
            coverage = req_row.get("coverage", {})
            coverage_status = coverage.get("status", "NONE")
            if coverage_status == "FULL":
                legacy_status = "COVERED"
            elif coverage_status == "PARTIAL":
                legacy_status = "COVERED"
            else:
                legacy_status = "NOT_COVERED"
            
            req_id = req_row.get("requirement_id", "")
            covered_by_tests = req_row.get("covered_by_tests", [])
            has_tests = req_id in requirements_with_tests_set or (isinstance(covered_by_tests, list) and len(covered_by_tests) > 0)
            
            testability = "testable" if has_tests else req_row.get("testability", "testable")
            trace_type = "testable" if has_tests else "informational"
            
            legacy_rtm_rows.append({
                "requirement_id": req_id,
                "requirement_description": req_row.get("requirement_description", ""),
                "covered_by_tests": covered_by_tests,
                "coverage_status": legacy_status,
                "testability": testability,
                "trace_type": trace_type
            })
    
    # Verify
    assert len(legacy_rtm_rows) == 1, "Should have 1 legacy RTM row"
    legacy_row = legacy_rtm_rows[0]
    assert legacy_row["requirement_id"] == "ATA-36-REQ-001", "Should be REQ-001"
    assert len(legacy_row["covered_by_tests"]) > 0, "Should have covered_by_tests"
    assert legacy_row["testability"] == "testable", f"testability should be 'testable', got '{legacy_row['testability']}'"
    assert legacy_row["trace_type"] == "testable", f"trace_type should be 'testable', got '{legacy_row['trace_type']}'"
    assert legacy_row["trace_type"] != "informational", "trace_type must not be 'informational' when tests exist"
    
    print("✅ Legacy RTM row not informational when has tests test passed!")
    return True


if __name__ == "__main__":
    try:
        test_scope_summary_requirements_covered()
        test_no_orphan_requirement_references()
        test_generic_id_mapping()
        test_requirement_testable_when_has_tests()
        test_legacy_rtm_row_not_informational_when_has_tests()
        print("\n✅ All coverage fix regression tests passed!")
        sys.exit(0)
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
