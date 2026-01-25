"""
RTM (Requirements Traceability Matrix) Generation Module

ISO 27001 Audit-Credible Implementation (Day-1 Audit-Ready):
- REQ-first: RTM rows contain ONLY requirements (IDs like *-REQ-*)
- Source evidence: ticket_ids[], breakdown_item_ids[], derivation
- Expectation-based coverage: status (FULL|PARTIAL|NONE), expected[], covered[], missing[]
- Unmapped items preserved in ticket_traceability.unmapped_items[]
- Audit metadata: rtm_metadata with run_id, generated_at, tenant_id, inputs_hash, etc.
"""

import hashlib
import json
from datetime import datetime, timezone


def is_requirement_testable_by_mapping(req_id: str, test_plan: dict = None, test_plan_by_requirement: dict = None, rtm_artifact: dict = None) -> bool:
    """
    Determine if a requirement is testable based on actual test mappings.
    
    A requirement is testable if ANY of the following are true:
    1) test_plan.ui_tests[*].requirements_covered contains the requirement ID
    2) test_plan_by_requirement[*].tests has ANY non-empty bucket for that requirement
    3) rtm_artifact.requirements_rtm[*].covered_by_tests is non-empty
    
    Args:
        req_id: Requirement ID to check
        test_plan: Test plan dict with test categories (ui_tests, api_tests, etc.)
        test_plan_by_requirement: Dict mapping requirement_id -> {tests: {...}}
        rtm_artifact: RTM artifact with requirements_rtm array
    
    Returns:
        bool: True if requirement has mapped tests, False otherwise
    """
    if not req_id:
        return False
    
    # Check 1: test_plan test categories
    if test_plan and isinstance(test_plan, dict):
        test_categories = ["api_tests", "ui_tests", "negative_tests", "data_validation_tests", "edge_cases", "system_tests"]
        for category in test_categories:
            tests = test_plan.get(category, [])
            if isinstance(tests, list):
                for test in tests:
                    if isinstance(test, dict):
                        reqs_covered = test.get("requirements_covered", [])
                        if isinstance(reqs_covered, list) and req_id in reqs_covered:
                            return True
    
    # Check 2: test_plan_by_requirement
    if test_plan_by_requirement and isinstance(test_plan_by_requirement, dict):
        req_bucket = test_plan_by_requirement.get(req_id)
        if req_bucket and isinstance(req_bucket, dict):
            tests_bucket = req_bucket.get("tests", {})
            if isinstance(tests_bucket, dict):
                # Check if ANY test category has non-empty list
                for test_list in tests_bucket.values():
                    if isinstance(test_list, list) and len(test_list) > 0:
                        return True
    
    # Check 3: rtm_artifact.requirements_rtm
    if rtm_artifact and isinstance(rtm_artifact, dict):
        requirements_rtm = rtm_artifact.get("requirements_rtm", [])
        if isinstance(requirements_rtm, list):
            for req_row in requirements_rtm:
                if isinstance(req_row, dict):
                    row_req_id = req_row.get("requirement_id", "")
                    covered_by_tests = req_row.get("covered_by_tests", [])
                    if row_req_id == req_id and isinstance(covered_by_tests, list) and len(covered_by_tests) > 0:
                        return True
    
    return False


def generate_rtm(test_plan_json: dict) -> dict:
    """
    Generate Requirement Traceability Matrix (RTM) from test plan JSON.
    
    REQ-FIRST IMPLEMENTATION (Day-1 Audit-Ready):
    - Iterates over requirements (primary source of truth)
    - Every requirement produces exactly one RTM row
    - Breakdown items that map to requirements are linked via source.breakdown_item_ids
    - Breakdown items that don't map to requirements go to unmapped_items
    - Coverage is expectation-based (FULL|PARTIAL|NONE) with expected/covered/missing arrays
    
    Args:
        test_plan_json: The complete test plan JSON structure
    
    Returns:
        dict: RTM artifact with structure:
        {
            "rtm_metadata": {
                "run_id": str,
                "generated_at": str (ISO UTC),
                "tenant_id": str (if available),
                "inputs_hash": str (sha256),
                "generator_version": str,
                "prompt_version": str,
                "generated_by": str
            },
            "requirements_rtm": [
                {
                    "requirement_id": str (REQ-* format),
                    "requirement_description": str,
                    "source": {
                        "ticket_ids": [str],
                        "breakdown_item_ids": [str],
                        "derivation": "explicit" | "inferred"
                    },
                    "coverage": {
                        "status": "FULL" | "PARTIAL" | "NONE",
                        "expected": [str],  # e.g., ["happy_path", "negative", "boundary"]
                        "covered": [str],
                        "missing": [str]
                    },
                    "covered_by_tests": [str],
                    "testability": "testable" | "not_testable"
                }
            ],
            "ticket_traceability": {
                "unmapped_items": [
                    {
                        "item_id": str (ITEM-* format),
                        "text": str,
                        "source_section": str,
                        "classification": str,
                        "testable": bool,
                        "rationale": str | "reason_code": str
                    }
                ]
            }
        }
    """
    # Extract audit metadata
    audit_metadata = test_plan_json.get("audit_metadata", {})
    # DAY-1 AUDIT FIX: Ensure run_id is never empty - try multiple sources
    run_id = audit_metadata.get("run_id", "") or test_plan_json.get("run_id", "")
    # If still empty, this is an error condition - log warning but continue
    if not run_id:
        import logging
        logger = logging.getLogger(__name__)
        logger.warning("rtm_metadata.run_id is empty - audit_metadata.run_id and result.run_id both missing")
        # Generate a fallback run_id for audit continuity (should not happen in normal flow)
        import uuid
        run_id = str(uuid.uuid4())
        logger.warning(f"Generated fallback run_id for RTM: {run_id}")
    
    generated_at = audit_metadata.get("generated_at", "")
    if not generated_at:
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    # Extract tenant_id if available (from request context or metadata)
    tenant_id = test_plan_json.get("tenant_id", "") or audit_metadata.get("tenant_id", "")
    
    # Compute inputs_hash (sha256 of normalized input)
    inputs_for_hash = {
        "tickets": test_plan_json.get("scope_summary", {}).get("ticket_details", []),
        "requirements": test_plan_json.get("requirements", []),
        "scope": test_plan_json.get("scope_summary", {})
    }
    inputs_json = json.dumps(inputs_for_hash, sort_keys=True, default=str)
    inputs_hash = hashlib.sha256(inputs_json.encode('utf-8')).hexdigest()
    
    # Get generator version (try git sha, fallback to hardcoded version)
    import os
    generator_version = os.getenv("GIT_SHA", "") or os.getenv("AGENT_VERSION", "1.0.0")
    prompt_version = "rtm-v2.0-req-first"  # Hardcoded for now
    
    # Get generated_by from audit_metadata or default
    generated_by = audit_metadata.get("created_by", "") or audit_metadata.get("generated_by", "system")
    
    # Build rtm_metadata
    rtm_metadata = {
        "run_id": run_id,
        "generated_at": generated_at,
        "tenant_id": tenant_id,
        "inputs_hash": inputs_hash,
        "generator_version": generator_version,
        "prompt_version": prompt_version,
        "generated_by": generated_by,
        "rtm_schema_version": "2.0"  # Audit polish: schema version for audit tracking
    }
    
    # Collect all tests across categories
    test_plan = test_plan_json.get("test_plan", {})
    all_tests = []
    test_categories = [
        "api_tests",
        "ui_tests",
        "data_validation_tests",
        "edge_cases",
        "negative_tests",
        "system_tests"
    ]
    
    for category in test_categories:
        category_tests = test_plan.get(category, [])
        if isinstance(category_tests, list):
            all_tests.extend(category_tests)
    
    # Build test map by requirement ID
    tests_by_req = {}
    test_intent_by_req = {}  # req_id -> set of intent_types (happy_path, negative, etc.)
    for test in all_tests:
        if isinstance(test, dict):
            test_id = test.get("id", "")
            requirements_covered = test.get("requirements_covered", [])
            intent_type = test.get("intent_type", "").lower() or "happy_path"  # Default to happy_path
            if test_id and isinstance(requirements_covered, list):
                for req_id in requirements_covered:
                    if req_id not in tests_by_req:
                        tests_by_req[req_id] = []
                        test_intent_by_req[req_id] = set()
                    tests_by_req[req_id].append(test_id)
                    # Map intent_type to coverage expectation dimension
                    intent_mapping = {
                        "happy_path": "happy_path",
                        "negative": "negative",
                        "boundary": "boundary",
                        "edge": "boundary",
                        "authorization": "authorization",
                        "permission": "authorization",
                        "security": "authorization",
                        "data_validation": "data_validation",
                        "stateful": "stateful",
                        "performance": "performance",
                        "audit_logging": "audit_logging"
                    }
                    mapped_dimension = intent_mapping.get(intent_type, "happy_path")
                    test_intent_by_req[req_id].add(mapped_dimension)
    
    # Build reverse mapping: requirement_id -> list of breakdown item_ids
    # Also collect unmapped items (items without mapped_requirement_id)
    ticket_traceability = test_plan_json.get("ticket_traceability", [])
    req_to_items = {}  # req_id -> list of {item_id, ticket_id}
    unmapped_items = []
    
    if ticket_traceability and isinstance(ticket_traceability, list):
        for trace_entry in ticket_traceability:
            if not isinstance(trace_entry, dict):
                continue
            
            ticket_id = trace_entry.get("ticket_id", "")
            items = trace_entry.get("items", [])
            if not isinstance(items, list):
                continue
            
            for item in items:
                if not isinstance(item, dict):
                    continue
                
                item_id = item.get("item_id", "")
                mapped_req_id = item.get("mapped_requirement_id")
                testable = item.get("testable", True)
                classification = item.get("classification", "")
                
                # Check if item is unmapped (no mapped_requirement_id) or not testable
                if not mapped_req_id or not testable or classification == "informational_only":
                    # Add to unmapped_items
                    rationale = item.get("note", "") or item.get("non_testable_reason", "")
                    if not rationale:
                        if classification == "informational_only":
                            rationale = "Informational content; not independently testable"
                        elif not testable:
                            rationale = "Item marked as not independently testable"
                        else:
                            rationale = "Item does not map to any requirement"
                    
                    # Audit polish: Determine reason_code enum
                    if classification == "informational_only" or not testable:
                        reason_code = "INFORMATIONAL_ONLY"
                    elif not mapped_req_id:
                        reason_code = "NO_MATCH_FOUND"
                    else:
                        reason_code = "OTHER"
                    
                    unmapped_items.append({
                        "item_id": item_id,
                        "text": item.get("text", ""),
                        "source_section": item.get("source_section", "unknown"),
                        "classification": classification,
                        "testable": testable,
                        "rationale": rationale,
                        "reason_code": reason_code  # Audit polish: enum for audit tracking
                    })
                else:
                    # Item maps to a requirement - add to reverse mapping
                    if mapped_req_id not in req_to_items:
                        req_to_items[mapped_req_id] = []
                    req_to_items[mapped_req_id].append({
                        "item_id": item_id,
                        "ticket_id": ticket_id
                    })
    
    # Build requirements_rtm: iterate over requirements
    requirements = test_plan_json.get("requirements", [])
    requirements_rtm = []
    req_ids_processed = set()
    
    for req in requirements:
        if not isinstance(req, dict):
            continue
        
        req_id = req.get("id", "")
        req_desc = req.get("description", "")
        
        if not req_id:
            continue
        
        # Skip if already processed (avoid duplicates)
        if req_id in req_ids_processed:
            continue
        req_ids_processed.add(req_id)
        
        # Get source evidence
        mapped_items = req_to_items.get(req_id, [])
        ticket_ids = list(set([item["ticket_id"] for item in mapped_items if item.get("ticket_id")]))
        breakdown_item_ids = [item["item_id"] for item in mapped_items]
        
        # Determine derivation: "explicit" if source is "jira", else "inferred"
        req_source = req.get("source", "inferred")
        derivation = "explicit" if req_source == "jira" else "inferred"
        
        # Get coverage expectations
        coverage_expectations = req.get("coverage_expectations", {})
        if not coverage_expectations:
            # Default: expect happy_path
            coverage_expectations = {"happy_path": "expected"}
        
        # Build expected array (dimensions marked as "expected")
        expected_dimensions = []
        for dimension, status in coverage_expectations.items():
            if status == "expected":
                expected_dimensions.append(dimension)
        
        # If no expectations set, default to happy_path
        if not expected_dimensions:
            expected_dimensions = ["happy_path"]
        
        # Get covered dimensions from test_intent_by_req
        covered_dimensions = list(test_intent_by_req.get(req_id, set()))
        
        # Compute missing dimensions
        missing_dimensions = [dim for dim in expected_dimensions if dim not in covered_dimensions]
        
        # Determine coverage status
        if len(covered_dimensions) >= len(expected_dimensions) and len(missing_dimensions) == 0:
            coverage_status = "FULL"
        elif len(covered_dimensions) > 0:
            coverage_status = "PARTIAL"
        else:
            coverage_status = "NONE"
        
        # Get covered_by_tests
        covered_by_tests = tests_by_req.get(req_id, [])
        
        # Determine testability: If covered_by_tests is non-empty, mark as testable
        # Otherwise, use requirement's testable flag (preserves informational-only items)
        has_tests = isinstance(covered_by_tests, list) and len(covered_by_tests) > 0
        if has_tests:
            testability = "testable"
        else:
            req_testable = req.get("testable", True)
            testability = "testable" if req_testable else "not_testable"
        
        requirements_rtm.append({
            "requirement_id": req_id,
            "requirement_description": req_desc,
            "source": {
                "ticket_ids": ticket_ids,
                "breakdown_item_ids": breakdown_item_ids,
                "derivation": derivation
            },
            "coverage": {
                "status": coverage_status,
                "expected": expected_dimensions,
                "covered": covered_dimensions,
                "missing": missing_dimensions
            },
            "covered_by_tests": covered_by_tests,
            "testability": testability,
            "mapping": {  # Audit polish: mapping metadata for audit tracking
                "method": "reverse_map_from_ticket_traceability",
                "score": None
            }
        })
    
    # Build final RTM artifact
    rtm_artifact = {
        "rtm_metadata": rtm_metadata,
        "requirements_rtm": requirements_rtm,
        "ticket_traceability": {
            "unmapped_items": unmapped_items
        }
    }
    
    return rtm_artifact


def validate_rtm(rtm_artifact: dict) -> tuple:
    """
    Validate RTM artifact for ISO 27001 audit compliance.
    
    Checks:
    - Required top-level fields exist
    - requirements_rtm contains only REQ-* IDs (no ITEM-* IDs)
    - unmapped_items contains only ITEM-* IDs
    - Every requirements_rtm row has source.ticket_ids and source.breakdown_item_ids
    - rtm_metadata keys exist
    
    Args:
        rtm_artifact: RTM artifact dictionary
    
    Returns:
        tuple: (is_valid, list_of_errors)
    """
    errors = []
    
    if not isinstance(rtm_artifact, dict):
        return False, ["RTM artifact must be a dictionary"]
    
    # Check required top-level fields
    if "rtm_metadata" not in rtm_artifact:
        errors.append("Missing required field 'rtm_metadata'")
    if "requirements_rtm" not in rtm_artifact:
        errors.append("Missing required field 'requirements_rtm'")
    if "ticket_traceability" not in rtm_artifact:
        errors.append("Missing required field 'ticket_traceability'")
    
    # Validate rtm_metadata
    rtm_metadata = rtm_artifact.get("rtm_metadata", {})
    required_metadata_fields = ["run_id", "generated_at", "inputs_hash", "generator_version", "prompt_version", "generated_by"]
    for field in required_metadata_fields:
        if field not in rtm_metadata:
            errors.append(f"rtm_metadata missing required field '{field}'")
    
    # Validate requirements_rtm
    requirements_rtm = rtm_artifact.get("requirements_rtm", [])
    if not isinstance(requirements_rtm, list):
        errors.append("requirements_rtm must be a list")
    else:
        seen_req_ids = set()
        for idx, req_row in enumerate(requirements_rtm):
            if not isinstance(req_row, dict):
                errors.append(f"requirements_rtm[{idx}]: Must be a dictionary")
                continue
            
            req_id = req_row.get("requirement_id", "")
            if not req_id:
                errors.append(f"requirements_rtm[{idx}]: Missing 'requirement_id'")
            elif req_id in seen_req_ids:
                errors.append(f"requirements_rtm[{idx}]: Duplicate requirement_id '{req_id}'")
            else:
                seen_req_ids.add(req_id)
            
            # Check requirement_id format (must be REQ-*, not ITEM-*)
            if req_id and "-ITEM-" in req_id:
                errors.append(f"requirements_rtm[{idx}]: requirement_id '{req_id}' contains '-ITEM-', must be REQ-based")
            
            # Check source field
            source = req_row.get("source", {})
            if not isinstance(source, dict):
                errors.append(f"requirements_rtm[{idx}]: 'source' must be a dictionary")
            else:
                if "ticket_ids" not in source:
                    errors.append(f"requirements_rtm[{idx}]: source missing 'ticket_ids'")
                if "breakdown_item_ids" not in source:
                    errors.append(f"requirements_rtm[{idx}]: source missing 'breakdown_item_ids'")
                if "derivation" not in source:
                    errors.append(f"requirements_rtm[{idx}]: source missing 'derivation'")
                elif source.get("derivation") not in ["explicit", "inferred"]:
                    errors.append(f"requirements_rtm[{idx}]: source.derivation must be 'explicit' or 'inferred'")
            
            # Check coverage field
            coverage = req_row.get("coverage", {})
            if not isinstance(coverage, dict):
                errors.append(f"requirements_rtm[{idx}]: 'coverage' must be a dictionary")
            else:
                if "status" not in coverage:
                    errors.append(f"requirements_rtm[{idx}]: coverage missing 'status'")
                elif coverage.get("status") not in ["FULL", "PARTIAL", "NONE"]:
                    errors.append(f"requirements_rtm[{idx}]: coverage.status must be 'FULL', 'PARTIAL', or 'NONE'")
                if "expected" not in coverage:
                    errors.append(f"requirements_rtm[{idx}]: coverage missing 'expected'")
                if "covered" not in coverage:
                    errors.append(f"requirements_rtm[{idx}]: coverage missing 'covered'")
                if "missing" not in coverage:
                    errors.append(f"requirements_rtm[{idx}]: coverage missing 'missing'")
    
    # Validate unmapped_items
    ticket_traceability = rtm_artifact.get("ticket_traceability", {})
    if not isinstance(ticket_traceability, dict):
        errors.append("ticket_traceability must be a dictionary")
    else:
        unmapped_items = ticket_traceability.get("unmapped_items", [])
        if not isinstance(unmapped_items, list):
            errors.append("ticket_traceability.unmapped_items must be a list")
        else:
            for idx, item in enumerate(unmapped_items):
                if not isinstance(item, dict):
                    errors.append(f"unmapped_items[{idx}]: Must be a dictionary")
                    continue
                
                item_id = item.get("item_id", "")
                if not item_id:
                    errors.append(f"unmapped_items[{idx}]: Missing 'item_id'")
                elif "-REQ-" in item_id:
                    errors.append(f"unmapped_items[{idx}]: item_id '{item_id}' contains '-REQ-', must be ITEM-based")
                
                # Check required fields
                required_item_fields = ["item_id", "text", "source_section", "classification", "testable"]
                for field in required_item_fields:
                    if field not in item:
                        errors.append(f"unmapped_items[{idx}]: Missing required field '{field}'")
                
                # Check rationale or reason_code
                if "rationale" not in item and "reason_code" not in item:
                    errors.append(f"unmapped_items[{idx}]: Must have either 'rationale' or 'reason_code'")
    
    is_valid = len(errors) == 0
    return is_valid, errors


def extract_expected_item_ids(test_plan_json: dict) -> set:
    """
    Extract all item_ids from ticket_traceability (for backward compatibility).
    
    Args:
        test_plan_json: The complete test plan JSON structure
    
    Returns:
        set: Set of all item_ids found in ticket_traceability
    """
    expected_item_ids = set()
    
    ticket_traceability = test_plan_json.get("ticket_traceability", [])
    if ticket_traceability and isinstance(ticket_traceability, list):
        for trace_entry in ticket_traceability:
            if not isinstance(trace_entry, dict):
                continue
            
            items = trace_entry.get("items", [])
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        item_id = item.get("item_id", "")
                        if item_id:
                            expected_item_ids.add(item_id)
    
    return expected_item_ids


# Test function for validation
def test_rtm_generation():
    """
    Test RTM generation with requirement-based structure.
    """
    sample_payload = {
        "audit_metadata": {
            "run_id": "test-run-123",
            "generated_at": "2026-01-24T12:00:00Z",
            "created_by": "test-user"
        },
        "requirements": [
            {
                "id": "ATA-36-REQ-001",
                "description": "The system shall automatically generate a Requirement Traceability Matrix",
                "source": "jira",
                "testable": True,
                "coverage_expectations": {
                    "happy_path": "expected",
                    "negative": "not_applicable"
                }
            },
            {
                "id": "ATA-36-REQ-002",
                "description": "Each requirement must appear once in RTM",
                "source": "inferred",
                "testable": True,
                "coverage_expectations": {
                    "happy_path": "expected"
                }
            }
        ],
        "ticket_traceability": [
            {
                "ticket_id": "ATA-36",
                "items": [
                    {
                        "item_id": "ATA-36-ITEM-001",
                        "text": "Automatic generation of Requirement Traceability Matrix (RTM)",
                        "testable": True,
                        "classification": "system_behavior",
                        "mapped_requirement_id": "ATA-36-REQ-001",
                        "source_section": "description"
                    },
                    {
                        "item_id": "ATA-36-ITEM-002",
                        "text": "Ensuring each requirement appears once in RTM",
                        "testable": True,
                        "classification": "system_behavior",
                        "mapped_requirement_id": "ATA-36-REQ-002",
                        "source_section": "description"
                    },
                    {
                        "item_id": "ATA-36-ITEM-003",
                        "text": "Informational note about RTM",
                        "testable": False,
                        "classification": "informational_only",
                        "note": "Informational content; not independently testable",
                        "source_section": "description"
                    }
                ]
            }
        ],
        "test_plan": {
            "ui_tests": [
                {
                    "id": "UI-001",
                    "requirements_covered": ["ATA-36-REQ-001"],
                    "intent_type": "happy_path"
                },
                {
                    "id": "UI-002",
                    "requirements_covered": ["ATA-36-REQ-002"],
                    "intent_type": "happy_path"
                }
            ]
        }
    }
    
    # Generate RTM
    rtm_artifact = generate_rtm(sample_payload)
    
    # Validate
    is_valid, errors = validate_rtm(rtm_artifact)
    assert is_valid, f"RTM validation failed: {errors}"
    
    # Assertions
    assert "rtm_metadata" in rtm_artifact, "Missing rtm_metadata"
    assert "requirements_rtm" in rtm_artifact, "Missing requirements_rtm"
    assert "ticket_traceability" in rtm_artifact, "Missing ticket_traceability"
    
    # Check rtm_metadata
    metadata = rtm_artifact["rtm_metadata"]
    assert metadata["run_id"] == "test-run-123", "run_id mismatch"
    assert "inputs_hash" in metadata, "Missing inputs_hash"
    assert "generator_version" in metadata, "Missing generator_version"
    
    # Check requirements_rtm contains only REQ-* IDs
    requirements_rtm = rtm_artifact["requirements_rtm"]
    assert len(requirements_rtm) == 2, f"Expected 2 requirement rows, got {len(requirements_rtm)}"
    
    for req_row in requirements_rtm:
        req_id = req_row["requirement_id"]
        assert "-REQ-" in req_id, f"requirement_id '{req_id}' must contain '-REQ-'"
        assert "-ITEM-" not in req_id, f"requirement_id '{req_id}' must not contain '-ITEM-'"
        assert "source" in req_row, f"Row {req_id} missing 'source'"
        assert "ticket_ids" in req_row["source"], f"Row {req_id} missing source.ticket_ids"
        assert "breakdown_item_ids" in req_row["source"], f"Row {req_id} missing source.breakdown_item_ids"
        assert "derivation" in req_row["source"], f"Row {req_id} missing source.derivation"
        assert "coverage" in req_row, f"Row {req_id} missing 'coverage'"
        assert req_row["coverage"]["status"] in ["FULL", "PARTIAL", "NONE"], f"Row {req_id} invalid coverage.status"
    
    # Check REQ-001 has breakdown_item_ids
    req_001 = next((r for r in requirements_rtm if r["requirement_id"] == "ATA-36-REQ-001"), None)
    assert req_001 is not None, "REQ-001 not found"
    assert "ATA-36-ITEM-001" in req_001["source"]["breakdown_item_ids"], "REQ-001 missing ITEM-001 in breakdown_item_ids"
    assert req_001["source"]["derivation"] == "explicit", "REQ-001 should be explicit"
    assert req_001["coverage"]["status"] == "FULL", "REQ-001 should be FULL coverage"
    assert "happy_path" in req_001["coverage"]["covered"], "REQ-001 should have happy_path covered"
    
    # Check REQ-002
    req_002 = next((r for r in requirements_rtm if r["requirement_id"] == "ATA-36-REQ-002"), None)
    assert req_002 is not None, "REQ-002 not found"
    assert req_002["source"]["derivation"] == "inferred", "REQ-002 should be inferred"
    
    # Check unmapped_items contains only ITEM-* IDs
    unmapped_items = rtm_artifact["ticket_traceability"]["unmapped_items"]
    assert len(unmapped_items) == 1, f"Expected 1 unmapped item, got {len(unmapped_items)}"
    assert unmapped_items[0]["item_id"] == "ATA-36-ITEM-003", "Unmapped item should be ITEM-003"
    assert "-ITEM-" in unmapped_items[0]["item_id"], "Unmapped item must be ITEM-based"
    assert "rationale" in unmapped_items[0], "Unmapped item must have rationale"
    
    print("✅ All RTM generation tests passed!")
    print(f"✅ requirements_rtm contains {len(requirements_rtm)} REQ rows (no ITEM rows)")
    print(f"✅ unmapped_items contains {len(unmapped_items)} ITEM rows")
    return True


if __name__ == "__main__":
    test_rtm_generation()
