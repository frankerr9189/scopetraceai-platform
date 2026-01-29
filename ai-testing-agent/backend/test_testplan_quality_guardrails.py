#!/usr/bin/env python3
"""
Regression/self-check for test plan quality guardrails (testplan-v1.1).

Asserts:
1) Number of BRs (requirements) covered remains unchanged for a known fixture.
2) Number of RTM rows unchanged.
3) No test step contains the exact phrase "Trigger the action described".
4) When data_validation is expected, at least one DATA-VAL test exists per BR.
"""

import sys
import os
import copy

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rtm import generate_rtm


def _fixture_test_plan():
    """Minimal test plan fixture: 2 requirements, one with data_validation expected; one step has vague trigger phrase."""
    return {
        "requirements": [
            {
                "id": "KBTS-1-REQ-001",
                "description": "The system shall provide Excel export.",
                "coverage_expectations": {
                    "data_validation": "not_applicable",
                    "happy_path": "covered",
                    "negative": "covered",
                },
                "coverage_confidence": {"level": "medium", "reasons": [], "score": 0.8},
            },
            {
                "id": "KBTS-1-REQ-002",
                "description": "The system shall validate requirement_id before generating RTM.",
                "coverage_expectations": {
                    "data_validation": "expected",
                    "happy_path": "covered",
                    "negative": "covered",
                },
                "coverage_confidence": {"level": "medium", "reasons": [], "score": 0.8},
            },
        ],
        "test_plan": {
            "api_tests": [
                {
                    "id": "API-001",
                    "source_requirement_id": "KBTS-1-REQ-001",
                    "requirements_covered": ["KBTS-1-REQ-001"],
                    "steps": [
                        "Navigate to export page",
                        "Trigger the action described in the requirement",
                        "Verify file downloads",
                    ],
                    "expected_result": "Excel file is downloaded",
                }
            ],
            "ui_tests": [],
            "negative_tests": [],
            "data_validation_tests": [],
            "edge_cases": [],
            "system_tests": [],
        },
        "audit_metadata": {"run_id": "fixture-run-001", "generated_at": "2026-01-28T00:00:00Z"},
    }


def test_br_count_unchanged_after_guardrails():
    """1) Number of BRs (requirements) remains unchanged for known fixture."""
    from app import (
        replace_vague_trigger_steps_with_observable_outcomes,
        add_risk_tags_to_tests,
        generate_dimension_specific_inferred_tests,
    )

    plan = _fixture_test_plan()
    requirements = plan["requirements"]
    br_count_before = len(requirements)
    all_tests = {}
    for cat, tests in plan["test_plan"].items():
        all_tests[cat] = list(tests) if isinstance(tests, list) else []

    replace_vague_trigger_steps_with_observable_outcomes(plan)
    add_risk_tags_to_tests(plan)
    dimension_tests = generate_dimension_specific_inferred_tests(requirements, all_tests)
    for category, tests in dimension_tests.items():
        if tests and category in plan["test_plan"]:
            plan["test_plan"][category].extend(tests)

    br_count_after = len(plan["requirements"])
    assert br_count_before == br_count_after, (
        f"BR count must remain unchanged: before={br_count_before}, after={br_count_after}"
    )
    print("✅ BR count unchanged")


def test_rtm_row_count_unchanged():
    """2) Number of RTM rows unchanged (one row per requirement)."""
    from app import (
        replace_vague_trigger_steps_with_observable_outcomes,
        add_risk_tags_to_tests,
        generate_dimension_specific_inferred_tests,
    )

    plan = _fixture_test_plan()
    requirements = plan["requirements"]
    all_tests = {}
    for cat, tests in plan["test_plan"].items():
        all_tests[cat] = list(tests) if isinstance(tests, list) else []

    replace_vague_trigger_steps_with_observable_outcomes(plan)
    add_risk_tags_to_tests(plan)
    dimension_tests = generate_dimension_specific_inferred_tests(requirements, all_tests)
    for category, tests in dimension_tests.items():
        if tests and category in plan["test_plan"]:
            plan["test_plan"][category].extend(tests)

    rtm = generate_rtm(plan)
    requirements_rtm = rtm.get("requirements_rtm", [])
    expected_rtm_rows = len(requirements)
    assert len(requirements_rtm) == expected_rtm_rows, (
        f"RTM row count must match requirement count: requirements={expected_rtm_rows}, rtm_rows={len(requirements_rtm)}"
    )
    print("✅ RTM row count unchanged")


def test_no_trigger_action_described_in_steps():
    """3) No test step contains the exact phrase 'Trigger the action described'."""
    from app import replace_vague_trigger_steps_with_observable_outcomes

    plan = _fixture_test_plan()
    replace_vague_trigger_steps_with_observable_outcomes(plan)

    forbidden = "trigger the action described"
    for category, tests in plan["test_plan"].items():
        if not isinstance(tests, list):
            continue
        for test in tests:
            if not isinstance(test, dict):
                continue
            for step in test.get("steps", []):
                if isinstance(step, str) and forbidden in step.lower():
                    raise AssertionError(
                        f"Step must not contain '{forbidden}': {step!r} in {category} test {test.get('id')}"
                    )
    print("✅ No step contains 'Trigger the action described'")


def test_data_validation_expected_has_data_val_test():
    """4) When data_validation is expected, at least one DATA-VAL test exists per BR."""
    from app import (
        replace_vague_trigger_steps_with_observable_outcomes,
        add_risk_tags_to_tests,
        generate_dimension_specific_inferred_tests,
    )

    plan = _fixture_test_plan()
    requirements = plan["requirements"]
    all_tests = {}
    for cat, tests in plan["test_plan"].items():
        all_tests[cat] = list(tests) if isinstance(tests, list) else []

    dimension_tests = generate_dimension_specific_inferred_tests(requirements, all_tests)
    for category, tests in dimension_tests.items():
        if tests and category in plan["test_plan"]:
            plan["test_plan"][category].extend(tests)

    data_val_tests = plan["test_plan"].get("data_validation_tests", [])
    reqs_expecting_data_val = [
        req["id"]
        for req in requirements
        if isinstance(req.get("coverage_expectations"), dict)
        and req["coverage_expectations"].get("data_validation") == "expected"
    ]
    for req_id in reqs_expecting_data_val:
        covered = any(
            req_id in (t.get("requirements_covered") or [])
            for t in data_val_tests
            if isinstance(t, dict)
        )
        assert covered, (
            f"Requirement {req_id} has data_validation=expected but no DATA-VAL test covers it. "
            f"data_validation_tests count={len(data_val_tests)}"
        )
    print("✅ DATA-VAL test exists per BR when data_validation expected")


def run_self_check():
    """Run all four assertions (script entry point)."""
    test_br_count_unchanged_after_guardrails()
    test_rtm_row_count_unchanged()
    test_no_trigger_action_described_in_steps()
    test_data_validation_expected_has_data_val_test()
    print("All test plan quality guardrail checks passed.")


if __name__ == "__main__":
    run_self_check()
