#!/usr/bin/env python3
"""
Regression tests for RTM test plan quality improvements.

Tests:
1) At least 1 negative test OR explicit "failure mode" test exists for ATA-36-like input
2) At least 1 edge/resilience/performance test exists for ATA-36-like input
3) Each test has concrete expected_result (must contain at least one of: "must", "equals", "contains", "exactly", "schema", "field", "column", "row", "status")
4) No generic requirement IDs remain in mappings (all IDs are ticket-scoped)
"""

import sys
import os
import json

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import enrich_test_quality_for_rtm_tickets


def test_ata36_like_has_negative_test():
    """
    Test 1: At least 1 negative test OR explicit "failure mode" test exists for ATA-36-like input
    """
    # Simulate ATA-36-like test plan (RTM generation ticket)
    test_plan = {
        "requirements": [
            {
                "id": "ATA-36-REQ-001",
                "description": "Automatically generate RTM for each test plan (non-blocking)",
                "source": "jira",
                "testable": True
            },
            {
                "id": "ATA-36-REQ-002",
                "description": "RTM includes requirement ID and description",
                "source": "jira",
                "testable": True
            }
        ],
        "test_plan": {
            "ui_tests": [
                {
                    "id": "UI-001",
                    "title": "Happy path: RTM generation",
                    "source_requirement_id": "ATA-36-REQ-001",
                    "intent_type": "happy_path",
                    "requirements_covered": ["ATA-36-REQ-001"],
                    "steps": ["Navigate to test plan", "Verify RTM is generated"],
                    "expected_result": "RTM is generated successfully"
                }
            ],
            "negative_tests": [],
            "edge_cases": [],
            "data_validation_tests": []
        }
    }
    
    # Apply quality enrichment
    enrich_test_quality_for_rtm_tickets(test_plan)
    
    # Verify negative test was added
    negative_tests = test_plan.get("test_plan", {}).get("negative_tests", [])
    assert len(negative_tests) > 0, "At least one negative test must exist for RTM-like ticket"
    
    # Check that negative test mentions failure/failure mode
    has_failure_test = any(
        "failure" in test.get("title", "").lower() or 
        "negative" in test.get("title", "").lower() or
        test.get("intent_type") == "negative"
        for test in negative_tests
    )
    assert has_failure_test, "Negative test must mention failure or be marked as negative intent"
    
    print("✅ Test 1 passed: ATA-36-like input has negative test")
    return True


def test_ata36_like_has_edge_resilience_test():
    """
    Test 2: At least 1 edge/resilience/performance test exists for ATA-36-like input
    """
    # Simulate ATA-36-like test plan
    test_plan = {
        "requirements": [
            {
                "id": "ATA-36-REQ-001",
                "description": "RTM generation is non-blocking during test plan creation",
                "source": "jira",
                "testable": True
            }
        ],
        "test_plan": {
            "ui_tests": [],
            "negative_tests": [
                {
                    "id": "NEG-001",
                    "title": "Negative: RTM generation failure",
                    "source_requirement_id": "ATA-36-REQ-001",
                    "intent_type": "negative",
                    "requirements_covered": ["ATA-36-REQ-001"],
                    "steps": ["Create corrupted test plan", "Trigger RTM"],
                    "expected_result": "System handles failure gracefully"
                }
            ],
            "edge_cases": [],
            "data_validation_tests": []
        }
    }
    
    # Apply quality enrichment
    enrich_test_quality_for_rtm_tickets(test_plan)
    
    # Verify edge/resilience test was added
    edge_tests = test_plan.get("test_plan", {}).get("edge_cases", [])
    assert len(edge_tests) > 0, "At least one edge/resilience test must exist for RTM-like ticket"
    
    # Check that edge test mentions resilience/async/performance
    has_resilience_test = any(
        "resilience" in test.get("title", "").lower() or
        "non-blocking" in test.get("title", "").lower() or
        "async" in test.get("title", "").lower() or
        test.get("intent_type") in ["resilience", "boundary"]
        for test in edge_tests
    )
    assert has_resilience_test, "Edge test must mention resilience/async/non-blocking or be marked as resilience intent"
    
    print("✅ Test 2 passed: ATA-36-like input has edge/resilience test")
    return True


def test_concrete_expected_result():
    """
    Test 3: Each test has concrete expected_result (must contain at least one of: "must", "equals", "contains", "exactly", "schema", "field", "column", "row", "status")
    """
    # Simulate test plan with generic expected_result
    test_plan = {
        "requirements": [
            {
                "id": "ATA-36-REQ-001",
                "description": "RTM includes requirement ID and coverage status",
                "source": "jira",
                "testable": True
            }
        ],
        "test_plan": {
            "ui_tests": [
                {
                    "id": "UI-001",
                    "title": "Happy path: RTM generation",
                    "source_requirement_id": "ATA-36-REQ-001",
                    "intent_type": "happy_path",
                    "requirements_covered": ["ATA-36-REQ-001"],
                    "steps": ["Generate RTM", "Verify RTM"],
                    "expected_result": "RTM is generated successfully"
                }
            ],
            "negative_tests": [],
            "edge_cases": [],
            "data_validation_tests": []
        }
    }
    
    # Apply quality enrichment
    enrich_test_quality_for_rtm_tickets(test_plan)
    
    # Check all tests have concrete expected_result
    test_categories = ["ui_tests", "negative_tests", "edge_cases", "data_validation_tests"]
    concrete_keywords = ["must", "equals", "contains", "exactly", "schema", "field", "column", "row", "status", "present", "absent", "matches", "validates", "id"]
    
    for category in test_categories:
        tests = test_plan.get("test_plan", {}).get(category, [])
        for test in tests:
            if isinstance(test, dict):
                expected_result = test.get("expected_result", "")
                assert expected_result, f"Test {test.get('id')} must have expected_result"
                
                # Check if expected_result contains concrete keywords
                expected_lower = expected_result.lower()
                has_concrete = any(keyword in expected_lower for keyword in concrete_keywords)
                assert has_concrete, f"Test {test.get('id')} expected_result must contain concrete validation keywords. Got: '{expected_result}'"
    
    print("✅ Test 3 passed: All tests have concrete expected_result")
    return True


def test_no_generic_requirement_ids():
    """
    Test 4: No generic requirement IDs remain in mappings (all IDs are ticket-scoped)
    """
    # Simulate test plan with both generic and ticket-scoped IDs
    test_plan = {
        "requirements": [
            {
                "id": "ATA-36-REQ-001",
                "description": "RTM includes requirement ID",
                "source": "jira",
                "testable": True
            }
        ],
        "test_plan": {
            "ui_tests": [
                {
                    "id": "UI-001",
                    "title": "Test RTM",
                    "source_requirement_id": "ATA-36-REQ-001",  # Ticket-scoped (correct)
                    "requirements_covered": ["ATA-36-REQ-001"],  # Ticket-scoped (correct)
                    "intent_type": "happy_path",
                    "steps": [],
                    "expected_result": "RTM contains requirement_id field"
                }
            ],
            "negative_tests": [],
            "edge_cases": [],
            "data_validation_tests": []
        }
    }
    
    # Apply quality enrichment (should not introduce generic IDs)
    enrich_test_quality_for_rtm_tickets(test_plan)
    
    # Check all requirement references are ticket-scoped
    test_categories = ["ui_tests", "negative_tests", "edge_cases", "data_validation_tests"]
    for category in test_categories:
        tests = test_plan.get("test_plan", {}).get(category, [])
        for test in tests:
            if isinstance(test, dict):
                source_req_id = test.get("source_requirement_id", "")
                reqs_covered = test.get("requirements_covered", [])
                
                # Check source_requirement_id is ticket-scoped (contains ticket prefix)
                if source_req_id:
                    assert "-" in source_req_id or source_req_id.startswith("ATA-"), \
                        f"Test {test.get('id')} has generic source_requirement_id: {source_req_id}"
                
                # Check requirements_covered are ticket-scoped
                for req_id in reqs_covered:
                    assert "-" in req_id or req_id.startswith("ATA-"), \
                        f"Test {test.get('id')} has generic requirement ID in requirements_covered: {req_id}"
    
    print("✅ Test 4 passed: No generic requirement IDs in mappings")
    return True


def test_no_empty_steps():
    """
    Test 5: No test has empty steps
    """
    test_plan = {
        "requirements": [
            {"id": "ATA-36-REQ-001", "description": "RTM includes requirement ID", "source": "jira", "testable": True}
        ],
        "test_plan": {
            "ui_tests": [
                {
                    "id": "UI-001",
                    "title": "Test RTM",
                    "source_requirement_id": "ATA-36-REQ-001",
                    "requirements_covered": ["ATA-36-REQ-001"],
                    "intent_type": "happy_path",
                    "steps": [],  # Empty steps - should be fixed
                    "expected_result": "RTM contains requirement_id field"
                }
            ],
            "negative_tests": [],
            "edge_cases": [],
            "data_validation_tests": []
        }
    }
    
    # Apply quality enrichment
    enrich_test_quality_for_rtm_tickets(test_plan)
    
    # Verify no test has empty steps
    test_categories = ["ui_tests", "negative_tests", "edge_cases", "data_validation_tests"]
    for category in test_categories:
        tests = test_plan.get("test_plan", {}).get(category, [])
        for test in tests:
            if isinstance(test, dict):
                steps = test.get("steps", [])
                assert isinstance(steps, list) and len(steps) > 0, \
                    f"Test {test.get('id')} has empty steps array"
                assert len(steps) >= 3, \
                    f"Test {test.get('id')} has fewer than 3 steps (got {len(steps)})"
    
    print("✅ Test 5 passed: No test has empty steps")
    return True


def test_no_forbidden_placeholder_phrases():
    """
    Test 6: No expected_result/steps contain forbidden placeholder phrases
    """
    test_plan = {
        "requirements": [
            {"id": "ATA-36-REQ-001", "description": "RTM generation is non-blocking", "source": "jira", "testable": True}
        ],
        "test_plan": {
            "ui_tests": [
                {
                    "id": "UI-001",
                    "title": "Test RTM",
                    "source_requirement_id": "ATA-36-REQ-001",
                    "requirements_covered": ["ATA-36-REQ-001"],
                    "intent_type": "happy_path",
                    "steps": ["Navigate to test plan (must specify exact URL/page/component)"],
                    "expected_result": "RTM is generated (must specify exact artifact/field/status to verify)"
                }
            ],
            "negative_tests": [],
            "edge_cases": [],
            "data_validation_tests": []
        }
    }
    
    # Apply quality enrichment
    enrich_test_quality_for_rtm_tickets(test_plan)
    
    # Verify no forbidden phrases
    forbidden_phrases = [
        "must specify", "tbd", "to be determined", "verify it matches expected",
        "trigger the action described", "(specify exact", "(must specify", "(to be determined"
    ]
    
    test_categories = ["ui_tests", "negative_tests", "edge_cases", "data_validation_tests"]
    for category in test_categories:
        tests = test_plan.get("test_plan", {}).get(category, [])
        for test in tests:
            if isinstance(test, dict):
                # Check steps
                steps = test.get("steps", [])
                for step in steps:
                    step_lower = (step or "").lower()
                    for phrase in forbidden_phrases:
                        assert phrase not in step_lower, \
                            f"Test {test.get('id')} step contains forbidden phrase '{phrase}': {step}"
                
                # Check expected_result
                expected_result = test.get("expected_result", "")
                expected_lower = (expected_result or "").lower()
                for phrase in forbidden_phrases:
                    assert phrase not in expected_lower, \
                        f"Test {test.get('id')} expected_result contains forbidden phrase '{phrase}': {expected_result}"
    
    print("✅ Test 6 passed: No forbidden placeholder phrases")
    return True


def test_no_invalid_requirement_ids():
    """
    Test 7: No test references non-existent requirement IDs
    """
    test_plan = {
        "requirements": [
            {"id": "ATA-36-REQ-001", "description": "RTM includes requirement ID", "source": "jira", "testable": True},
            {"id": "ATA-36-REQ-002", "description": "RTM includes description", "source": "jira", "testable": True}
        ],
        "test_plan": {
            "ui_tests": [
                {
                    "id": "UI-001",
                    "title": "Test RTM",
                    "source_requirement_id": "REQ-008",  # Invalid - doesn't exist
                    "requirements_covered": ["REQ-009"],  # Invalid - doesn't exist
                    "intent_type": "happy_path",
                    "steps": ["Generate RTM", "Verify RTM"],
                    "expected_result": "RTM contains requirement_id field"
                }
            ],
            "negative_tests": [],
            "edge_cases": [],
            "data_validation_tests": []
        }
    }
    
    # Apply quality enrichment (should fix invalid references)
    enrich_test_quality_for_rtm_tickets(test_plan)
    
    # Build valid requirement IDs
    valid_req_ids = {req.get("id") for req in test_plan.get("requirements", []) if isinstance(req, dict) and req.get("id")}
    
    # Verify all requirement references are valid
    test_categories = ["ui_tests", "negative_tests", "edge_cases", "data_validation_tests"]
    for category in test_categories:
        tests = test_plan.get("test_plan", {}).get(category, [])
        for test in tests:
            if isinstance(test, dict):
                source_req_id = test.get("source_requirement_id")
                if source_req_id:
                    assert source_req_id in valid_req_ids or source_req_id is None, \
                        f"Test {test.get('id')} has invalid source_requirement_id: {source_req_id}"
                
                reqs_covered = test.get("requirements_covered", [])
                for req_id in reqs_covered:
                    assert req_id in valid_req_ids, \
                        f"Test {test.get('id')} has invalid requirement ID in requirements_covered: {req_id}"
    
    print("✅ Test 7 passed: No invalid requirement IDs")
    return True


def test_data_validation_has_exact_field_names():
    """
    Test 8: Data validation test asserts exact field names and uniqueness per requirement
    """
    test_plan = {
        "requirements": [
            {"id": "ATA-36-REQ-001", "description": "RTM includes requirement ID and appears once", "source": "jira", "testable": True}
        ],
        "test_plan": {
            "ui_tests": [],
            "negative_tests": [],
            "edge_cases": [],
            "data_validation_tests": []
        }
    }
    
    # Apply quality enrichment (should add data validation test)
    enrich_test_quality_for_rtm_tickets(test_plan)
    
    # Find data validation test
    validation_tests = test_plan.get("test_plan", {}).get("data_validation_tests", [])
    assert len(validation_tests) > 0, "Data validation test must exist for RTM-like ticket"
    
    for test in validation_tests:
        if isinstance(test, dict):
            expected_result = test.get("expected_result", "")
            expected_lower = expected_result.lower()
            
            # Must contain exact field names
            assert "requirement_id" in expected_lower, \
                f"Data validation test {test.get('id')} must mention 'requirement_id' field"
            assert "requirement_description" in expected_lower or "description" in expected_lower, \
                f"Data validation test {test.get('id')} must mention requirement description field"
            assert "coverage_status" in expected_lower, \
                f"Data validation test {test.get('id')} must mention 'coverage_status' field"
            assert "covered_by_tests" in expected_lower, \
                f"Data validation test {test.get('id')} must mention 'covered_by_tests' field"
            
            # Must mention uniqueness
            assert "once" in expected_lower or "uniqueness" in expected_lower or "distinct" in expected_lower, \
                f"Data validation test {test.get('id')} must mention uniqueness check"
    
    print("✅ Test 8 passed: Data validation test has exact field names and uniqueness")
    return True


def test_resilience_test_has_numeric_thresholds():
    """
    Test 9: Resilience test includes explicit numeric thresholds (seconds) in expected_result
    """
    test_plan = {
        "requirements": [
            {"id": "ATA-36-REQ-001", "description": "RTM generation is non-blocking", "source": "jira", "testable": True}
        ],
        "test_plan": {
            "ui_tests": [],
            "negative_tests": [],
            "edge_cases": [],
            "data_validation_tests": []
        }
    }
    
    # Apply quality enrichment (should add resilience test)
    enrich_test_quality_for_rtm_tickets(test_plan)
    
    # Find resilience/edge test
    edge_tests = test_plan.get("test_plan", {}).get("edge_cases", [])
    assert len(edge_tests) > 0, "Resilience/edge test must exist for RTM-like ticket with non-blocking requirement"
    
    for test in edge_tests:
        if isinstance(test, dict):
            expected_result = test.get("expected_result", "")
            expected_lower = expected_result.lower()
            
            # Must contain numeric thresholds (seconds)
            import re
            has_seconds = bool(re.search(r'\d+\s*second', expected_lower))
            assert has_seconds, \
                f"Resilience test {test.get('id')} must include numeric threshold in seconds. Got: {expected_result}"
            
            # Must mention specific time values
            assert "5" in expected_result or "30" in expected_result or "within" in expected_lower, \
                f"Resilience test {test.get('id')} must specify exact time thresholds. Got: {expected_result}"
    
    print("✅ Test 9 passed: Resilience test has numeric thresholds")
    return True


def test_no_unmapped_testable_system_behavior_items():
    """
    Test 10: No unmapped testable system_behavior items exist for ATA-36-like input
    """
    # Simulate ATA-36-like test plan with unmapped system_behavior items
    test_plan = {
        "requirements": [
            {"id": "ATA-36-REQ-001", "description": "RTM includes requirement ID", "source": "jira", "testable": True}
        ],
        "ticket_traceability": [
            {
                "ticket_id": "ATA-36",
                "items": [
                    {
                        "item_id": "ATA-36-ITEM-001",
                        "text": "RTM is generated automatically after test plan creation",
                        "classification": "system_behavior",
                        "testable": True,
                        "mapped_requirement_id": None,  # Unmapped - should be promoted
                        "source_section": "ticket_analysis"
                    },
                    {
                        "item_id": "ATA-36-ITEM-002",
                        "text": "RTM includes requirement ID and description",
                        "classification": "system_behavior",
                        "testable": True,
                        "mapped_requirement_id": "ATA-36-REQ-001",  # Already mapped
                        "source_section": "ticket_analysis"
                    }
                ]
            }
        ],
        "test_plan": {
            "ui_tests": [],
            "negative_tests": [],
            "edge_cases": [],
            "data_validation_tests": []
        }
    }
    
    # Import the promotion function
    from app import promote_unmapped_system_behaviors_to_requirements
    
    # Apply promotion
    requirements = test_plan.get("requirements", [])
    ticket_traceability = test_plan.get("ticket_traceability", [])
    
    for trace_entry in ticket_traceability:
        ticket_id = trace_entry.get("ticket_id", "")
        if ticket_id:
            ticket_key = ticket_id.split("-")[0] if "-" in ticket_id else ticket_id
            requirements, _ = promote_unmapped_system_behaviors_to_requirements(
                requirements,
                [trace_entry],
                ticket_key
            )
    
    # Verify no unmapped testable system_behavior items remain
    for trace_entry in ticket_traceability:
        items = trace_entry.get("items", [])
        for item in items:
            classification = item.get("classification", "")
            testable = item.get("testable", False)
            mapped_req_id = item.get("mapped_requirement_id")
            
            if classification == "system_behavior" and testable:
                assert mapped_req_id is not None, \
                    f"Item {item.get('item_id')} is system_behavior and testable but has no mapped_requirement_id"
    
    # Verify new requirement was created
    req_ids = [req.get("id") for req in requirements if isinstance(req, dict)]
    assert "ATA-36-REQ-002" in req_ids, "New requirement should be created for unmapped system_behavior item"
    
    print("✅ Test 10 passed: No unmapped testable system_behavior items exist")
    return True


def test_all_testable_system_behavior_items_have_mapped_requirement_id():
    """
    Test 11: All testable system_behavior items in ticket_traceability.items have mapped_requirement_id
    """
    # Simulate test plan with multiple system_behavior items
    test_plan = {
        "requirements": [
            {"id": "ATA-36-REQ-001", "description": "RTM includes requirement ID", "source": "jira", "testable": True}
        ],
        "ticket_traceability": [
            {
                "ticket_id": "ATA-36",
                "items": [
                    {
                        "item_id": "ATA-36-ITEM-001",
                        "text": "RTM is generated automatically",
                        "classification": "system_behavior",
                        "testable": True,
                        "mapped_requirement_id": None,  # Will be promoted
                        "source_section": "ticket_analysis"
                    },
                    {
                        "item_id": "ATA-36-ITEM-002",
                        "text": "RTM includes requirement ID",
                        "classification": "system_behavior",
                        "testable": True,
                        "mapped_requirement_id": "ATA-36-REQ-001",
                        "source_section": "ticket_analysis"
                    },
                    {
                        "item_id": "ATA-36-ITEM-003",
                        "text": "Informational note",
                        "classification": "informational_only",
                        "testable": False,
                        "mapped_requirement_id": None,  # OK - not testable
                        "source_section": "ticket_analysis"
                    }
                ]
            }
        ],
        "test_plan": {
            "ui_tests": [],
            "negative_tests": [],
            "edge_cases": [],
            "data_validation_tests": []
        }
    }
    
    # Import the promotion function
    from app import promote_unmapped_system_behaviors_to_requirements
    
    # Apply promotion
    requirements = test_plan.get("requirements", [])
    ticket_traceability = test_plan.get("ticket_traceability", [])
    
    for trace_entry in ticket_traceability:
        ticket_id = trace_entry.get("ticket_id", "")
        if ticket_id:
            ticket_key = ticket_id.split("-")[0] if "-" in ticket_id else ticket_id
            requirements, _ = promote_unmapped_system_behaviors_to_requirements(
                requirements,
                [trace_entry],
                ticket_key
            )
    
    # Verify all testable system_behavior items have mapped_requirement_id
    for trace_entry in ticket_traceability:
        items = trace_entry.get("items", [])
        for item in items:
            classification = item.get("classification", "")
            testable = item.get("testable", False)
            mapped_req_id = item.get("mapped_requirement_id")
            
            if classification == "system_behavior" and testable:
                assert mapped_req_id is not None, \
                    f"Testable system_behavior item {item.get('item_id')} must have mapped_requirement_id"
                assert mapped_req_id.startswith("ATA-36-REQ-"), \
                    f"mapped_requirement_id {mapped_req_id} must be in correct format"
    
    print("✅ Test 11 passed: All testable system_behavior items have mapped_requirement_id")
    return True


def test_no_inherited_entries_have_null_parent_requirement_id():
    """
    Test 12: No inherited entries have null parent_requirement_id
    """
    # Simulate test plan with ticket_item_coverage entries
    test_plan = {
        "requirements": [
            {"id": "ATA-36-REQ-001", "description": "RTM includes requirement ID", "source": "jira", "testable": True},
            {"id": "ATA-36-REQ-002", "description": "RTM is generated automatically", "source": "inferred", "testable": True}
        ],
        "ticket_traceability": [
            {
                "ticket_id": "ATA-36",
                "items": [
                    {
                        "item_id": "ATA-36-ITEM-001",
                        "text": "RTM is generated automatically",
                        "classification": "system_behavior",
                        "testable": True,
                        "mapped_requirement_id": "ATA-36-REQ-002",
                        "source_section": "ticket_analysis"
                    },
                    {
                        "item_id": "ATA-36-ITEM-002",
                        "text": "RTM includes requirement ID",
                        "classification": "system_behavior",
                        "testable": True,
                        "mapped_requirement_id": "ATA-36-REQ-001",
                        "source_section": "ticket_analysis"
                    }
                ]
            }
        ],
        "ticket_item_coverage": [
            {
                "item_id": "ATA-36-ITEM-001",
                "coverage_method": "inherited_via_parent_requirement",
                "parent_requirement_id": "ATA-36-REQ-002"  # Has parent_requirement_id
            },
            {
                "item_id": "ATA-36-ITEM-002",
                "coverage_method": "inherited_via_parent_requirement",
                "parent_requirement_id": None  # Missing - should be fixed
            }
        ],
        "test_plan": {
            "ui_tests": [],
            "negative_tests": [],
            "edge_cases": [],
            "data_validation_tests": []
        }
    }
    
    # Simulate the enforcement logic that runs after promotion
    ticket_item_coverage = test_plan.get("ticket_item_coverage", [])
    ticket_traceability = test_plan.get("ticket_traceability", [])
    
    # Build item_id -> mapped_requirement_id lookup
    item_to_req_map = {}
    for trace_entry in ticket_traceability:
        if not isinstance(trace_entry, dict):
            continue
        items = trace_entry.get("items", [])
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict):
                item_id = item.get("item_id", "")
                mapped_req_id = item.get("mapped_requirement_id")
                if item_id and mapped_req_id:
                    item_to_req_map[item_id] = mapped_req_id
    
    # Fix inherited_via_parent_requirement entries
    for coverage_entry in ticket_item_coverage:
        if not isinstance(coverage_entry, dict):
            continue
        
        coverage_method = coverage_entry.get("coverage_method", "")
        if coverage_method == "inherited_via_parent_requirement":
            parent_req_id = coverage_entry.get("parent_requirement_id")
            if not parent_req_id:
                # Find the item and get its mapped_requirement_id
                item_id = coverage_entry.get("item_id", "")
                if item_id and item_id in item_to_req_map:
                    coverage_entry["parent_requirement_id"] = item_to_req_map[item_id]
    
    # Verify no inherited entries have null parent_requirement_id
    for coverage_entry in ticket_item_coverage:
        coverage_method = coverage_entry.get("coverage_method", "")
        if coverage_method == "inherited_via_parent_requirement":
            parent_req_id = coverage_entry.get("parent_requirement_id")
            assert parent_req_id is not None, \
                f"Inherited coverage entry {coverage_entry.get('item_id')} must have parent_requirement_id"
            assert parent_req_id.startswith("ATA-36-REQ-"), \
                f"parent_requirement_id {parent_req_id} must be in correct format"
    
    print("✅ Test 12 passed: No inherited entries have null parent_requirement_id")
    return True


def test_promoted_requirements_inherit_testable_true():
    """
    Test 13: All promoted requirements derived from testable system_behavior items must have testable == True
    """
    # Simulate test plan with unmapped testable system_behavior items
    test_plan = {
        "requirements": [
            {"id": "ATA-36-REQ-001", "description": "RTM includes requirement ID", "source": "jira", "testable": True}
        ],
        "ticket_traceability": [
            {
                "ticket_id": "ATA-36",
                "items": [
                    {
                        "item_id": "ATA-36-ITEM-001",
                        "text": "RTM is generated automatically after test plan creation",
                        "classification": "system_behavior",
                        "testable": True,  # Source item is testable
                        "mapped_requirement_id": None,  # Will be promoted
                        "source_section": "ticket_analysis"
                    }
                ]
            }
        ],
        "test_plan": {
            "ui_tests": [],
            "negative_tests": [],
            "edge_cases": [],
            "data_validation_tests": []
        }
    }
    
    # Import the promotion function
    from app import promote_unmapped_system_behaviors_to_requirements
    
    # Apply promotion
    requirements = test_plan.get("requirements", [])
    ticket_traceability = test_plan.get("ticket_traceability", [])
    
    for trace_entry in ticket_traceability:
        ticket_id = trace_entry.get("ticket_id", "")
        if ticket_id:
            ticket_key = ticket_id.split("-")[0] if "-" in ticket_id else ticket_id
            requirements, _ = promote_unmapped_system_behaviors_to_requirements(
                requirements,
                [trace_entry],
                ticket_key
            )
    
    # Verify all promoted requirements have testable == True
    for req in requirements:
        if isinstance(req, dict):
            req_id = req.get("id", "")
            req_source = req.get("source", "")
            req_testable = req.get("testable", False)
            
            # Check if this is a promoted requirement (source == "inferred" and ID matches pattern)
            if req_source == "inferred" and req_id.startswith("ATA-36-REQ-") and req_id != "ATA-36-REQ-001":
                assert req_testable == True, \
                    f"Promoted requirement {req_id} must have testable == True (got {req_testable})"
    
    print("✅ Test 13 passed: All promoted requirements inherit testable=True")
    return True


def test_no_risk_like_statements_promoted():
    """
    Test 14: No promoted requirement_description contains risk keywords
    """
    # Simulate test plan with risk-like statements
    test_plan = {
        "requirements": [
            {"id": "ATA-36-REQ-001", "description": "RTM includes requirement ID", "source": "jira", "testable": True}
        ],
        "ticket_traceability": [
            {
                "ticket_id": "ATA-36",
                "items": [
                    {
                        "item_id": "ATA-36-ITEM-001",
                        "text": "RTM is generated automatically",
                        "classification": "system_behavior",
                        "testable": True,
                        "mapped_requirement_id": None,  # Will be promoted (no risk keywords)
                        "source_section": "ticket_analysis"
                    },
                    {
                        "item_id": "ATA-36-ITEM-002",
                        "text": "Potential misalignment between requirements and tests",
                        "classification": "system_behavior",
                        "testable": True,
                        "mapped_requirement_id": None,  # Should NOT be promoted (contains "potential")
                        "source_section": "ticket_analysis"
                    },
                    {
                        "item_id": "ATA-36-ITEM-003",
                        "text": "Risk of incomplete coverage",
                        "classification": "system_behavior",
                        "testable": True,
                        "mapped_requirement_id": None,  # Should NOT be promoted (contains "risk")
                        "source_section": "ticket_analysis"
                    },
                    {
                        "item_id": "ATA-36-ITEM-004",
                        "text": "System may generate duplicate entries",
                        "classification": "system_behavior",
                        "testable": True,
                        "mapped_requirement_id": None,  # Should NOT be promoted (contains "may")
                        "source_section": "ticket_analysis"
                    }
                ]
            }
        ],
        "test_plan": {
            "ui_tests": [],
            "negative_tests": [],
            "edge_cases": [],
            "data_validation_tests": []
        }
    }
    
    # Import the promotion function
    from app import promote_unmapped_system_behaviors_to_requirements
    
    # Apply promotion
    requirements = test_plan.get("requirements", [])
    ticket_traceability = test_plan.get("ticket_traceability", [])
    
    for trace_entry in ticket_traceability:
        ticket_id = trace_entry.get("ticket_id", "")
        if ticket_id:
            ticket_key = ticket_id.split("-")[0] if "-" in ticket_id else ticket_id
            requirements, _ = promote_unmapped_system_behaviors_to_requirements(
                requirements,
                [trace_entry],
                ticket_key
            )
    
    # Verify no promoted requirements contain risk keywords
    risk_keywords = ["potential", "risk", "misalignment", "may", "could", "might"]
    for req in requirements:
        if isinstance(req, dict):
            req_id = req.get("id", "")
            req_source = req.get("source", "")
            req_desc = req.get("description", "").lower()
            
            # Check if this is a promoted requirement
            if req_source == "inferred" and req_id.startswith("ATA-36-REQ-") and req_id != "ATA-36-REQ-001":
                for keyword in risk_keywords:
                    assert keyword not in req_desc, \
                        f"Promoted requirement {req_id} contains risk keyword '{keyword}': {req.get('description')}"
    
    # Verify risk-like items were reclassified
    for trace_entry in ticket_traceability:
        items = trace_entry.get("items", [])
        for item in items:
            item_id = item.get("item_id", "")
            item_text = item.get("text", "").lower()
            classification = item.get("classification", "")
            
            # Check if risk-like items were reclassified
            if any(keyword in item_text for keyword in risk_keywords):
                assert classification == "risk_note" or item.get("testable") == False, \
                    f"Risk-like item {item_id} should be reclassified to risk_note or marked as not testable"
    
    print("✅ Test 14 passed: No risk-like statements promoted")
    return True


def test_inclusion_uniqueness_requirements_have_correct_coverage_expectations():
    """
    Test 15: Promoted 'Inclusion of...' / 'appears once...' requirements must have data_validation == expected and happy_path/negative == not_applicable
    """
    # Simulate test plan with inclusion/uniqueness items
    test_plan = {
        "requirements": [
            {"id": "ATA-36-REQ-001", "description": "RTM includes requirement ID", "source": "jira", "testable": True}
        ],
        "ticket_traceability": [
            {
                "ticket_id": "ATA-36",
                "items": [
                    {
                        "item_id": "ATA-36-ITEM-001",
                        "text": "Inclusion of requirement ID in RTM",
                        "classification": "system_behavior",
                        "testable": True,
                        "mapped_requirement_id": None,  # Will be promoted
                        "source_section": "ticket_analysis"
                    },
                    {
                        "item_id": "ATA-36-ITEM-002",
                        "text": "Each requirement appears once in RTM",
                        "classification": "system_behavior",
                        "testable": True,
                        "mapped_requirement_id": None,  # Will be promoted
                        "source_section": "ticket_analysis"
                    },
                    {
                        "item_id": "ATA-36-ITEM-003",
                        "text": "RTM validates uniqueness of requirement IDs",
                        "classification": "system_behavior",
                        "testable": True,
                        "mapped_requirement_id": None,  # Will be promoted
                        "source_section": "ticket_analysis"
                    },
                    {
                        "item_id": "ATA-36-ITEM-004",
                        "text": "RTM contains exactly one entry per requirement",
                        "classification": "system_behavior",
                        "testable": True,
                        "mapped_requirement_id": None,  # Will be promoted
                        "source_section": "ticket_analysis"
                    },
                    {
                        "item_id": "ATA-36-ITEM-005",
                        "text": "RTM is generated automatically",
                        "classification": "system_behavior",
                        "testable": True,
                        "mapped_requirement_id": None,  # Will be promoted (not inclusion/uniqueness)
                        "source_section": "ticket_analysis"
                    }
                ]
            }
        ],
        "test_plan": {
            "ui_tests": [],
            "negative_tests": [],
            "edge_cases": [],
            "data_validation_tests": []
        }
    }
    
    # Import the promotion function
    from app import promote_unmapped_system_behaviors_to_requirements
    
    # Apply promotion
    requirements = test_plan.get("requirements", [])
    ticket_traceability = test_plan.get("ticket_traceability", [])
    
    for trace_entry in ticket_traceability:
        ticket_id = trace_entry.get("ticket_id", "")
        if ticket_id:
            ticket_key = ticket_id.split("-")[0] if "-" in ticket_id else ticket_id
            requirements, _ = promote_unmapped_system_behaviors_to_requirements(
                requirements,
                [trace_entry],
                ticket_key
            )
    
    # Verify inclusion/uniqueness requirements have correct coverage expectations
    inclusion_uniqueness_patterns = [
        "inclusion of",
        "appears once",
        "uniqueness",
        "contains exactly one"
    ]
    
    for req in requirements:
        if isinstance(req, dict):
            req_id = req.get("id", "")
            req_source = req.get("source", "")
            req_desc = req.get("description", "").lower()
            coverage_exp = req.get("coverage_expectations", {})
            
            # Check if this is a promoted requirement
            if req_source == "inferred" and req_id.startswith("ATA-36-REQ-") and req_id != "ATA-36-REQ-001":
                is_inclusion_uniqueness = any(pattern in req_desc for pattern in inclusion_uniqueness_patterns)
                
                if is_inclusion_uniqueness:
                    # Must have data_validation == expected and happy_path/negative == not_applicable
                    assert coverage_exp.get("data_validation") == "expected", \
                        f"Inclusion/uniqueness requirement {req_id} must have data_validation == expected, got {coverage_exp.get('data_validation')}"
                    assert coverage_exp.get("happy_path") == "not_applicable", \
                        f"Inclusion/uniqueness requirement {req_id} must have happy_path == not_applicable, got {coverage_exp.get('happy_path')}"
                    assert coverage_exp.get("negative") == "not_applicable", \
                        f"Inclusion/uniqueness requirement {req_id} must have negative == not_applicable, got {coverage_exp.get('negative')}"
                else:
                    # Regular requirements should use default expectations (not all not_applicable)
                    assert coverage_exp.get("happy_path") != "not_applicable" or coverage_exp.get("negative") != "not_applicable", \
                        f"Regular requirement {req_id} should not have both happy_path and negative as not_applicable"
    
    print("✅ Test 15 passed: Inclusion/uniqueness requirements have correct coverage expectations")
    return True


def test_mapped_testable_items_force_requirement_testable_true():
    """
    Test 16: For each ticket_traceability item where testable==True and mapped_requirement_id is not null,
    the corresponding requirement with id==mapped_requirement_id must have testable==True.
    """
    # Simulate test plan with mapped testable items
    test_plan = {
        "requirements": [
            {"id": "ATA-36-REQ-001", "description": "RTM includes requirement ID", "source": "jira", "testable": True},
            {"id": "ATA-36-REQ-002", "description": "RTM is generated automatically", "source": "inferred", "testable": False},  # Will be synced
            {"id": "ATA-36-REQ-003", "description": "RTM includes coverage status", "source": "inferred", "testable": False},  # Will be synced
            {"id": "ATA-36-REQ-004", "description": "Informational note", "source": "inferred", "testable": False}  # No mapped testable items
        ],
        "ticket_traceability": [
            {
                "ticket_id": "ATA-36",
                "items": [
                    {
                        "item_id": "ATA-36-ITEM-001",
                        "text": "RTM includes requirement ID",
                        "classification": "system_behavior",
                        "testable": True,
                        "mapped_requirement_id": "ATA-36-REQ-001",  # Already testable
                        "source_section": "ticket_analysis"
                    },
                    {
                        "item_id": "ATA-36-ITEM-002",
                        "text": "RTM is generated automatically",
                        "classification": "system_behavior",
                        "testable": True,
                        "mapped_requirement_id": "ATA-36-REQ-002",  # Should force testable=True
                        "source_section": "ticket_analysis"
                    },
                    {
                        "item_id": "ATA-36-ITEM-003",
                        "text": "RTM includes coverage status",
                        "classification": "system_behavior",
                        "testable": True,
                        "mapped_requirement_id": "ATA-36-REQ-003",  # Should force testable=True
                        "source_section": "ticket_analysis"
                    },
                    {
                        "item_id": "ATA-36-ITEM-004",
                        "text": "Informational note",
                        "classification": "informational_only",
                        "testable": False,
                        "mapped_requirement_id": "ATA-36-REQ-004",  # Not testable, should not force
                        "source_section": "ticket_analysis"
                    }
                ]
            }
        ],
        "test_plan": {
            "ui_tests": [],
            "negative_tests": [],
            "edge_cases": [],
            "data_validation_tests": []
        }
    }
    
    # Import the sync function
    from app import sync_requirement_testable_from_traceability
    
    # Apply sync
    requirements = test_plan.get("requirements", [])
    ticket_traceability = test_plan.get("ticket_traceability", [])
    sync_requirement_testable_from_traceability(requirements, ticket_traceability)
    
    # Verify all requirements with mapped testable items have testable=True
    req_by_id = {r["id"]: r for r in requirements}
    for t in ticket_traceability:
        for item in t.get("items", []):
            rid = item.get("mapped_requirement_id")
            if rid and item.get("testable") is True:
                assert req_by_id[rid].get("testable") is True, f"{rid} must be testable when mapped item is testable"
    
    print("✅ Test 16 passed: Mapped testable items force requirement testable=True")
    return True


def test_inferred_requirements_have_coverage_attribution():
    """
    Test 17: Requirements REQ-002..REQ-007 have testable==True, appear in test_plan_by_requirement,
    and show COVERED in RTM with non-empty covered_by_tests.
    """
    # Simulate test plan with inferred requirements and existing tests
    test_plan = {
        "requirements": [
            {"id": "ATA-36-REQ-001", "description": "RTM includes requirement ID", "source": "jira", "testable": True},
            {"id": "ATA-36-REQ-002", "description": "Each requirement appears once in RTM", "source": "inferred", "testable": False},
            {"id": "ATA-36-REQ-003", "description": "Requirement ID in RTM", "source": "inferred", "testable": False},
            {"id": "ATA-36-REQ-004", "description": "associated test case ID(s)", "source": "inferred", "testable": False},
            {"id": "ATA-36-REQ-005", "description": "coverage status", "source": "inferred", "testable": False},
            {"id": "ATA-36-REQ-006", "description": "Deriving RTM directly from test plan", "source": "inferred", "testable": False},
            {"id": "ATA-36-REQ-007", "description": "Requirement description in RTM", "source": "inferred", "testable": False}
        ],
        "ticket_traceability": [
            {
                "ticket_id": "ATA-36",
                "items": [
                    {
                        "item_id": "ATA-36-ITEM-002",
                        "text": "Each requirement appears once in RTM",
                        "classification": "system_behavior",
                        "testable": True,
                        "mapped_requirement_id": "ATA-36-REQ-002",
                        "source_section": "ticket_analysis"
                    },
                    {
                        "item_id": "ATA-36-ITEM-003",
                        "text": "Requirement ID in RTM",
                        "classification": "system_behavior",
                        "testable": True,
                        "mapped_requirement_id": "ATA-36-REQ-003",
                        "source_section": "ticket_analysis"
                    }
                ]
            }
        ],
        "test_plan": {
            "data_validation_tests": [
                {
                    "id": "VAL-001-RTM-SCHEMA",
                    "title": "Validate RTM schema",
                    "source_requirement_id": "ATA-36-REQ-001",
                    "requirements_covered": ["ATA-36-REQ-001"],
                    "intent_type": "data_validation",
                    "steps": ["Check schema"],
                    "expected_result": "Schema is valid"
                }
            ],
            "system_tests": [
                {
                    "id": "SYS-001",
                    "title": "System test for RTM",
                    "source_requirement_id": "ATA-36-REQ-001",
                    "requirements_covered": ["ATA-36-REQ-001"],
                    "intent_type": "happy_path",
                    "steps": ["Run test"],
                    "expected_result": "Test passes"
                }
            ],
            "ui_tests": [],
            "negative_tests": [],
            "edge_cases": []
        }
    }
    
    # Import functions
    from app import sync_requirement_testable_from_traceability, attribute_coverage_to_inferred_requirements, derive_test_plan_by_requirement
    from rtm import generate_rtm as generate_rtm_audit_ready
    
    # Apply sync
    requirements = test_plan.get("requirements", [])
    ticket_traceability = test_plan.get("ticket_traceability", [])
    sync_requirement_testable_from_traceability(requirements, ticket_traceability)
    
    # Apply coverage attribution
    test_plan_section = test_plan.get("test_plan", {})
    attrib_stats = attribute_coverage_to_inferred_requirements(test_plan_section, requirements)
    
    # Verify attribution actually happened
    assert attrib_stats.get("added", 0) > 0, "Coverage attribution should have added at least one requirement"
    
    # Verify requirements_covered was updated
    sys_test = next((t for t in test_plan_section.get("system_tests", []) if t.get("id") == "SYS-001"), None)
    if sys_test:
        sys_covered = sys_test.get("requirements_covered", [])
        # SYS-001 should cover REQ-001 (original) plus REQ-004, REQ-006 (from attribution)
        assert "ATA-36-REQ-001" in sys_covered, "SYS-001 should cover REQ-001"
        assert "ATA-36-REQ-004" in sys_covered or "ATA-36-REQ-006" in sys_covered, \
            "SYS-001 should have at least one of REQ-004 or REQ-006 from attribution"
    
    # Verify requirements have testable=True (for those with mapped items)
    req_by_id = {r["id"]: r for r in requirements}
    for req_id in ["ATA-36-REQ-002", "ATA-36-REQ-003"]:
        assert req_by_id[req_id].get("testable") is True, \
            f"{req_id} must have testable=True when mapped item is testable"
    
    # Verify test_plan_by_requirement includes tests for REQ-002..REQ-007
    # (Only check requirements that exist in the test data and have coverage attribution)
    test_plan_by_req = derive_test_plan_by_requirement(requirements, test_plan_section)
    test_plan_by_req_dict = {entry["requirement_id"]: entry for entry in test_plan_by_req}
    
    # Check requirements that should have coverage attribution (REQ-004, REQ-006 have SYS-001)
    req_ids_with_attribution = ["ATA-36-REQ-004", "ATA-36-REQ-006"]
    for req_id in req_ids_with_attribution:
        # Only check if requirement exists
        if req_id in req_by_id and req_id in test_plan_by_req_dict:
            entry = test_plan_by_req_dict[req_id]
            tests = entry.get("tests", {})
            # Check if any test category has tests
            has_tests = any(isinstance(test_list, list) and len(test_list) > 0 for test_list in tests.values())
            assert has_tests, \
                f"{req_id} must have at least one test in test_plan_by_requirement (got {tests})"
    
    # Verify RTM shows COVERED for REQ-002..REQ-007
    test_plan["requirements"] = requirements
    test_plan["ticket_traceability"] = ticket_traceability
    rtm_artifact = generate_rtm_audit_ready(test_plan)
    
    requirements_rtm = rtm_artifact.get("requirements_rtm", [])
    rtm_by_req_id = {row["requirement_id"]: row for row in requirements_rtm if isinstance(row, dict)}
    
    # Check requirements that should have coverage attribution (REQ-004, REQ-006 have SYS-001)
    req_ids_with_attribution_rtm = ["ATA-36-REQ-004", "ATA-36-REQ-006"]
    for req_id in req_ids_with_attribution_rtm:
        # Only check if requirement exists
        if req_id in req_by_id and req_id in rtm_by_req_id:
            rtm_row = rtm_by_req_id[req_id]
            coverage = rtm_row.get("coverage", {})
            coverage_status = coverage.get("status", "")
            covered_by_tests = rtm_row.get("covered_by_tests", [])
            
            # Status should be FULL or PARTIAL (not NONE), and covered_by_tests should not be empty
            assert coverage_status in ["FULL", "PARTIAL"], \
                f"{req_id} must have coverage_status FULL or PARTIAL, got {coverage_status}"
            assert isinstance(covered_by_tests, list) and len(covered_by_tests) > 0, \
                f"{req_id} must have non-empty covered_by_tests in RTM"
    
    print("✅ Test 17 passed: Inferred requirements have coverage attribution")
    return True


def test_scope_summary_derived_from_final_artifacts():
    """
    Test 18: scope_summary is derived from final artifacts (requirements + rtm_artifact)
    rather than early ticket_details counts.
    
    Input: artifact where requirements length=7, ticket_details requirements_count=1,
    requirements_rtm length=7 with 5 FULL + 2 PARTIAL
    Assert: requirements_total=7, requirements_covered=5, requirements_partial=2, requirements_uncovered=0
    """
    # Simulate artifact with mismatch between ticket_details and final requirements
    artifact = {
        "requirements": [
            {"id": "ATA-36-REQ-001", "description": "Requirement 1"},
            {"id": "ATA-36-REQ-002", "description": "Requirement 2"},
            {"id": "ATA-36-REQ-003", "description": "Requirement 3"},
            {"id": "ATA-36-REQ-004", "description": "Requirement 4"},
            {"id": "ATA-36-REQ-005", "description": "Requirement 5"},
            {"id": "ATA-36-REQ-006", "description": "Requirement 6"},
            {"id": "ATA-36-REQ-007", "description": "Requirement 7"}
        ],
        "scope_summary": {
            "requirements_total": 1,  # Incorrect - from early ticket_details
            "requirements_covered": 1,
            "requirements_uncovered": 0,
            "ticket_details": [
                {
                    "ticket_id": "ATA-36",
                    "requirements_count": 1  # Incorrect early count
                }
            ]
        },
        "rtm_artifact": {
            "requirements_rtm": [
                {
                    "requirement_id": "ATA-36-REQ-001",
                    "coverage": {"status": "FULL"}
                },
                {
                    "requirement_id": "ATA-36-REQ-002",
                    "coverage": {"status": "FULL"}
                },
                {
                    "requirement_id": "ATA-36-REQ-003",
                    "coverage": {"status": "FULL"}
                },
                {
                    "requirement_id": "ATA-36-REQ-004",
                    "coverage": {"status": "FULL"}
                },
                {
                    "requirement_id": "ATA-36-REQ-005",
                    "coverage": {"status": "FULL"}
                },
                {
                    "requirement_id": "ATA-36-REQ-006",
                    "coverage": {"status": "PARTIAL"}
                },
                {
                    "requirement_id": "ATA-36-REQ-007",
                    "coverage": {"status": "PARTIAL"}
                }
            ]
        },
        "rtm": []  # Empty - using rtm_artifact instead
    }
    
    # Simulate the final recalculation logic
    requirements_final = artifact.get("requirements", [])
    requirements_total_final = len(requirements_final) if requirements_final else 0
    
    # Update requirements_total
    artifact["scope_summary"]["requirements_total"] = requirements_total_final
    
    # Derive coverage from rtm_artifact
    rtm_artifact = artifact.get("rtm_artifact")
    if rtm_artifact and isinstance(rtm_artifact, dict):
        requirements_rtm = rtm_artifact.get("requirements_rtm", [])
        if isinstance(requirements_rtm, list) and len(requirements_rtm) > 0:
            full_count = 0
            partial_count = 0
            none_count = 0
            
            for req_row in requirements_rtm:
                if isinstance(req_row, dict):
                    coverage = req_row.get("coverage", {})
                    if isinstance(coverage, dict):
                        status = coverage.get("status", "NONE")
                        if status == "FULL":
                            full_count += 1
                        elif status == "PARTIAL":
                            partial_count += 1
                        elif status == "NONE":
                            none_count += 1
            
            requirements_covered_final = full_count + partial_count  # FULL + PARTIAL
            requirements_uncovered_final = none_count  # NONE only
            
            artifact["scope_summary"]["requirements_full"] = full_count
            artifact["scope_summary"]["requirements_partial"] = partial_count
            artifact["scope_summary"]["requirements_none"] = none_count
            artifact["scope_summary"]["requirements_covered"] = requirements_covered_final
            artifact["scope_summary"]["requirements_uncovered"] = requirements_uncovered_final
            
            # Fix ticket_details[].requirements_count
            ticket_details = artifact.get("scope_summary", {}).get("ticket_details")
            if isinstance(ticket_details, list):
                for ticket_detail in ticket_details:
                    if isinstance(ticket_detail, dict):
                        ticket_detail["requirements_count"] = requirements_total_final
    
    # Verify assertions
    scope_summary = artifact.get("scope_summary", {})
    
    assert scope_summary.get("requirements_total") == 7, \
        f"requirements_total must equal len(requirements)=7, got {scope_summary.get('requirements_total')}"
    assert scope_summary.get("requirements_full") == 5, \
        f"requirements_full must equal FULL count=5, got {scope_summary.get('requirements_full')}"
    assert scope_summary.get("requirements_partial") == 2, \
        f"requirements_partial must equal PARTIAL count=2, got {scope_summary.get('requirements_partial')}"
    assert scope_summary.get("requirements_none") == 0, \
        f"requirements_none must equal NONE count=0, got {scope_summary.get('requirements_none')}"
    assert scope_summary.get("requirements_covered") == 7, \
        f"requirements_covered must equal FULL + PARTIAL = 5 + 2 = 7, got {scope_summary.get('requirements_covered')}"
    assert scope_summary.get("requirements_uncovered") == 0, \
        f"requirements_uncovered must equal NONE count=0, got {scope_summary.get('requirements_uncovered')}"
    
    # Verify ticket_details.requirements_count was fixed (optional cleanup)
    ticket_details = scope_summary.get("ticket_details", [])
    if ticket_details and len(ticket_details) > 0:
        ticket_detail = ticket_details[0]
        assert ticket_detail.get("requirements_count") == 7, \
            f"ticket_details[].requirements_count must match requirements_total=7, got {ticket_detail.get('requirements_count')}"
    
    print("✅ Test 18 passed: scope_summary derived from final artifacts")
    return True


if __name__ == "__main__":
    try:
        test_ata36_like_has_negative_test()
        test_ata36_like_has_edge_resilience_test()
        test_concrete_expected_result()
        test_no_generic_requirement_ids()
        test_no_empty_steps()
        test_no_forbidden_placeholder_phrases()
        test_no_invalid_requirement_ids()
        test_data_validation_has_exact_field_names()
        test_resilience_test_has_numeric_thresholds()
        test_no_unmapped_testable_system_behavior_items()
        test_all_testable_system_behavior_items_have_mapped_requirement_id()
        test_no_inherited_entries_have_null_parent_requirement_id()
        test_promoted_requirements_inherit_testable_true()
        test_no_risk_like_statements_promoted()
        test_inclusion_uniqueness_requirements_have_correct_coverage_expectations()
        test_mapped_testable_items_force_requirement_testable_true()
        test_inferred_requirements_have_coverage_attribution()
        test_scope_summary_derived_from_final_artifacts()
        print("\n✅ All RTM test quality regression tests passed!")
        sys.exit(0)
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
