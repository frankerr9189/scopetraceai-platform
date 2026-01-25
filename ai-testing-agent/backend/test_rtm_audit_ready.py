#!/usr/bin/env python3
"""
Unit test for Day-1 Audit-Ready RTM generation.

Tests:
- requirements_rtm contains only REQ-* IDs (no ITEM-* IDs)
- unmapped_items contains only ITEM-* IDs
- Every requirements_rtm row has source.ticket_ids and source.breakdown_item_ids
- rtm_metadata keys exist
"""

import sys
import os
import json

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rtm import generate_rtm, validate_rtm


def test_rtm_audit_ready():
    """Test Day-1 Audit-Ready RTM structure."""
    sample_payload = {
        "audit_metadata": {
            "run_id": "test-run-audit-123",
            "generated_at": "2026-01-24T12:00:00Z",
            "created_by": "test-user@example.com"
        },
        "tenant_id": "test-tenant-123",
        "requirements": [
            {
                "id": "ATA-36-REQ-001",
                "description": "The system shall automatically generate RTM",
                "source": "jira",
                "testable": True,
                "coverage_expectations": {
                    "happy_path": "expected",
                    "negative": "not_applicable",
                    "boundary": "expected"
                }
            },
            {
                "id": "ATA-36-REQ-002",
                "description": "Inferred requirement without explicit mapping",
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
                        "text": "Automatic generation of RTM",
                        "testable": True,
                        "classification": "system_behavior",
                        "mapped_requirement_id": "ATA-36-REQ-001",
                        "source_section": "description"
                    },
                    {
                        "item_id": "ATA-36-ITEM-002",
                        "text": "Informational note",
                        "testable": False,
                        "classification": "informational_only",
                        "note": "Informational content",
                        "source_section": "description"
                    },
                    {
                        "item_id": "ATA-36-ITEM-003",
                        "text": "Unmapped testable item",
                        "testable": True,
                        "classification": "system_behavior",
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
                    "requirements_covered": ["ATA-36-REQ-001"],
                    "intent_type": "boundary"
                }
            ]
        }
    }
    
    # Generate RTM
    rtm_artifact = generate_rtm(sample_payload)
    
    # Validate structure
    is_valid, errors = validate_rtm(rtm_artifact)
    assert is_valid, f"RTM validation failed: {errors}"
    
    # Test 1: requirements_rtm contains no ITEM-* IDs
    requirements_rtm = rtm_artifact.get("requirements_rtm", [])
    for req_row in requirements_rtm:
        req_id = req_row.get("requirement_id", "")
        assert "-ITEM-" not in req_id, f"requirements_rtm contains ITEM ID: {req_id}"
        assert "-REQ-" in req_id, f"requirements_rtm ID must be REQ-based: {req_id}"
    
    # Test 2: unmapped_items contains only ITEM-* IDs
    unmapped_items = rtm_artifact.get("ticket_traceability", {}).get("unmapped_items", [])
    for item in unmapped_items:
        item_id = item.get("item_id", "")
        assert "-REQ-" not in item_id, f"unmapped_items contains REQ ID: {item_id}"
        assert "-ITEM-" in item_id, f"unmapped_items ID must be ITEM-based: {item_id}"
    
    # Test 3: Every requirements_rtm row has source.ticket_ids and source.breakdown_item_ids
    for req_row in requirements_rtm:
        source = req_row.get("source", {})
        assert "ticket_ids" in source, f"Row {req_row.get('requirement_id')} missing source.ticket_ids"
        assert "breakdown_item_ids" in source, f"Row {req_row.get('requirement_id')} missing source.breakdown_item_ids"
        assert "derivation" in source, f"Row {req_row.get('requirement_id')} missing source.derivation"
        assert isinstance(source["ticket_ids"], list), "source.ticket_ids must be a list"
        assert isinstance(source["breakdown_item_ids"], list), "source.breakdown_item_ids must be a list"
        assert source["derivation"] in ["explicit", "inferred"], "source.derivation must be 'explicit' or 'inferred'"
    
    # Test 4: rtm_metadata keys exist
    rtm_metadata = rtm_artifact.get("rtm_metadata", {})
    required_metadata_keys = ["run_id", "generated_at", "inputs_hash", "generator_version", "prompt_version", "generated_by"]
    for key in required_metadata_keys:
        assert key in rtm_metadata, f"rtm_metadata missing required key: {key}"
    
    # Test 4a: rtm_schema_version audit polish
    assert "rtm_schema_version" in rtm_metadata, "rtm_metadata missing rtm_schema_version"
    assert rtm_metadata["rtm_schema_version"] == "2.0", f"rtm_schema_version should be '2.0', got '{rtm_metadata['rtm_schema_version']}'"
    
    # Test 5: Coverage structure
    for req_row in requirements_rtm:
        coverage = req_row.get("coverage", {})
        assert "status" in coverage, f"Row {req_row.get('requirement_id')} missing coverage.status"
        assert coverage["status"] in ["FULL", "PARTIAL", "NONE"], f"Invalid coverage.status: {coverage['status']}"
        assert "expected" in coverage, f"Row {req_row.get('requirement_id')} missing coverage.expected"
        assert "covered" in coverage, f"Row {req_row.get('requirement_id')} missing coverage.covered"
        assert "missing" in coverage, f"Row {req_row.get('requirement_id')} missing coverage.missing"
        assert isinstance(coverage["expected"], list), "coverage.expected must be a list"
        assert isinstance(coverage["covered"], list), "coverage.covered must be a list"
        assert isinstance(coverage["missing"], list), "coverage.missing must be a list"
    
    # Test 6: REQ-001 has breakdown_item_ids
    req_001 = next((r for r in requirements_rtm if r["requirement_id"] == "ATA-36-REQ-001"), None)
    assert req_001 is not None, "REQ-001 not found"
    assert "ATA-36-ITEM-001" in req_001["source"]["breakdown_item_ids"], "REQ-001 missing ITEM-001"
    assert req_001["source"]["derivation"] == "explicit", "REQ-001 should be explicit"
    assert req_001["coverage"]["status"] == "FULL", "REQ-001 should be FULL coverage"
    assert "happy_path" in req_001["coverage"]["covered"], "REQ-001 should have happy_path covered"
    assert "boundary" in req_001["coverage"]["covered"], "REQ-001 should have boundary covered"
    
    # Test 7: REQ-002 has no breakdown_item_ids (inferred)
    req_002 = next((r for r in requirements_rtm if r["requirement_id"] == "ATA-36-REQ-002"), None)
    assert req_002 is not None, "REQ-002 not found"
    assert req_002["source"]["derivation"] == "inferred", "REQ-002 should be inferred"
    assert len(req_002["source"]["breakdown_item_ids"]) == 0, "REQ-002 should have no breakdown_item_ids"
    
    # Test 8: Unmapped items
    assert len(unmapped_items) == 2, f"Expected 2 unmapped items, got {len(unmapped_items)}"
    unmapped_ids = [item["item_id"] for item in unmapped_items]
    assert "ATA-36-ITEM-002" in unmapped_ids, "ITEM-002 should be unmapped"
    assert "ATA-36-ITEM-003" in unmapped_ids, "ITEM-003 should be unmapped"
    
    # Test 8a: Unmapped items have reason_code audit polish
    for item in unmapped_items:
        assert "reason_code" in item, f"Unmapped item {item.get('item_id')} missing reason_code"
        assert item["reason_code"] in ["INFORMATIONAL_ONLY", "NO_MATCH_FOUND", "OTHER"], \
            f"Invalid reason_code: {item.get('reason_code')}"
    
    # Verify specific reason_code values
    item_002 = next((i for i in unmapped_items if i["item_id"] == "ATA-36-ITEM-002"), None)
    assert item_002 is not None, "ITEM-002 not found"
    assert item_002["reason_code"] == "INFORMATIONAL_ONLY", "ITEM-002 should have reason_code INFORMATIONAL_ONLY"
    
    item_003 = next((i for i in unmapped_items if i["item_id"] == "ATA-36-ITEM-003"), None)
    assert item_003 is not None, "ITEM-003 not found"
    assert item_003["reason_code"] == "NO_MATCH_FOUND", "ITEM-003 should have reason_code NO_MATCH_FOUND"
    
    # Test 9: requirements_rtm rows have mapping audit polish
    for req_row in requirements_rtm:
        assert "mapping" in req_row, f"Row {req_row.get('requirement_id')} missing mapping"
        mapping = req_row.get("mapping", {})
        assert "method" in mapping, f"Row {req_row.get('requirement_id')} mapping missing method"
        assert "score" in mapping, f"Row {req_row.get('requirement_id')} mapping missing score"
        assert mapping["method"] == "reverse_map_from_ticket_traceability", \
            f"mapping.method should be 'reverse_map_from_ticket_traceability', got '{mapping['method']}'"
        assert mapping["score"] is None, f"mapping.score should be None, got '{mapping['score']}'"
    
    print("✅ All audit-ready RTM tests passed!")
    print(f"✅ requirements_rtm: {len(requirements_rtm)} REQ rows (no ITEM rows)")
    print(f"✅ unmapped_items: {len(unmapped_items)} ITEM rows")
    print(f"✅ rtm_metadata: All required keys present")
    
    # Print example
    print("\n📋 Example RTM Artifact Structure:")
    print(json.dumps({
        "rtm_metadata": rtm_metadata,
        "requirements_rtm_count": len(requirements_rtm),
        "unmapped_items_count": len(unmapped_items),
        "example_req_row": requirements_rtm[0] if requirements_rtm else None,
        "example_unmapped_item": unmapped_items[0] if unmapped_items else None
    }, indent=2, default=str))
    
    return True


def test_persisted_rtm_artifact_structure():
    """
    Test that persisted RTM artifact on disk has the correct structure.
    This simulates what persist_test_plan_result() would save.
    """
    sample_payload = {
        "audit_metadata": {
            "run_id": "test-persistence-123",
            "generated_at": "2026-01-24T12:00:00Z",
            "created_by": "test-user@example.com"
        },
        "tenant_id": "test-tenant-123",
        "requirements": [
            {
                "id": "ATA-36-REQ-001",
                "description": "Test requirement",
                "source": "jira",
                "testable": True,
                "coverage_expectations": {"happy_path": "expected"}
            }
        ],
        "ticket_traceability": [
            {
                "ticket_id": "ATA-36",
                "items": [
                    {
                        "item_id": "ATA-36-ITEM-001",
                        "text": "Test item",
                        "mapped_requirement_id": "ATA-36-REQ-001",
                        "testable": True,
                        "classification": "system_behavior",
                        "source_section": "description"
                    },
                    {
                        "item_id": "ATA-36-ITEM-002",
                        "text": "Informational item",
                        "testable": False,
                        "classification": "informational_only",
                        "source_section": "description",
                        "note": "Informational"
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
                }
            ]
        }
    }
    
    # Generate RTM artifact
    rtm_artifact = generate_rtm(sample_payload)
    
    # Simulate what persist_test_plan_result() does:
    # It should save result.get("rtm_artifact", result.get("rtm", []))
    # In this case, we're testing that rtm_artifact is the object structure
    persisted_rtm = rtm_artifact  # This is what should be saved
    
    # Test a) persisted RTM artifact on disk is an object with rtm_metadata + requirements_rtm + ticket_traceability
    assert isinstance(persisted_rtm, dict), "Persisted RTM must be a dict/object, not a list"
    assert "rtm_metadata" in persisted_rtm, "Persisted RTM missing rtm_metadata"
    assert "requirements_rtm" in persisted_rtm, "Persisted RTM missing requirements_rtm"
    assert "ticket_traceability" in persisted_rtm, "Persisted RTM missing ticket_traceability"
    
    # Test b) rtm_metadata.rtm_schema_version == "2.0"
    rtm_metadata = persisted_rtm.get("rtm_metadata", {})
    assert rtm_metadata.get("rtm_schema_version") == "2.0", \
        f"rtm_schema_version should be '2.0', got '{rtm_metadata.get('rtm_schema_version')}'"
    
    # Test c) each unmapped_item has reason_code
    unmapped_items = persisted_rtm.get("ticket_traceability", {}).get("unmapped_items", [])
    for item in unmapped_items:
        assert "reason_code" in item, f"Unmapped item {item.get('item_id')} missing reason_code"
        assert item["reason_code"] in ["INFORMATIONAL_ONLY", "NO_MATCH_FOUND", "OTHER"], \
            f"Invalid reason_code: {item.get('reason_code')}"
    
    # Test d) each requirements_rtm row has mapping.method and mapping.score keys
    requirements_rtm = persisted_rtm.get("requirements_rtm", [])
    for req_row in requirements_rtm:
        assert "mapping" in req_row, f"Row {req_row.get('requirement_id')} missing mapping"
        mapping = req_row.get("mapping", {})
        assert "method" in mapping, f"Row {req_row.get('requirement_id')} mapping missing method"
        assert "score" in mapping, f"Row {req_row.get('requirement_id')} mapping missing score"
        assert mapping["method"] == "reverse_map_from_ticket_traceability", \
            f"mapping.method should be 'reverse_map_from_ticket_traceability'"
        assert mapping["score"] is None, f"mapping.score should be None"
    
    print("✅ Persistence structure tests passed!")
    print(f"✅ Persisted RTM is a dict with {len(requirements_rtm)} requirements and {len(unmapped_items)} unmapped items")
    
    return True


def test_rtm_metadata_run_id_never_empty():
    """
    Regression test: Ensure rtm_metadata.run_id is always non-empty and equals audit_metadata.run_id.
    """
    # Test case 1: Normal case with audit_metadata.run_id
    sample_payload_1 = {
        "audit_metadata": {
            "run_id": "test-run-123",
            "generated_at": "2026-01-24T12:00:00Z"
        },
        "requirements": [],
        "ticket_traceability": [],
        "test_plan": {}
    }
    
    rtm_artifact_1 = generate_rtm(sample_payload_1)
    rtm_metadata_1 = rtm_artifact_1.get("rtm_metadata", {})
    assert rtm_metadata_1.get("run_id") == "test-run-123", \
        f"run_id should be 'test-run-123', got '{rtm_metadata_1.get('run_id')}'"
    assert rtm_metadata_1.get("run_id") != "", "run_id must not be empty"
    
    # Test case 2: Fallback to result.run_id if audit_metadata.run_id is missing
    sample_payload_2 = {
        "audit_metadata": {
            "generated_at": "2026-01-24T12:00:00Z"
            # run_id missing
        },
        "run_id": "fallback-run-456",  # Direct run_id in result
        "requirements": [],
        "ticket_traceability": [],
        "test_plan": {}
    }
    
    rtm_artifact_2 = generate_rtm(sample_payload_2)
    rtm_metadata_2 = rtm_artifact_2.get("rtm_metadata", {})
    assert rtm_metadata_2.get("run_id") == "fallback-run-456", \
        f"run_id should be 'fallback-run-456', got '{rtm_metadata_2.get('run_id')}'"
    assert rtm_metadata_2.get("run_id") != "", "run_id must not be empty"
    
    # Test case 3: Both missing - should generate fallback UUID (should not happen in production)
    sample_payload_3 = {
        "audit_metadata": {
            "generated_at": "2026-01-24T12:00:00Z"
            # run_id missing
        },
        # run_id also missing from result
        "requirements": [],
        "ticket_traceability": [],
        "test_plan": {}
    }
    
    rtm_artifact_3 = generate_rtm(sample_payload_3)
    rtm_metadata_3 = rtm_artifact_3.get("rtm_metadata", {})
    run_id_3 = rtm_metadata_3.get("run_id", "")
    assert run_id_3 != "", "run_id must not be empty even when audit_metadata.run_id is missing"
    # Should be a UUID format (36 chars with dashes)
    assert len(run_id_3) == 36, f"Fallback run_id should be UUID format, got '{run_id_3}'"
    
    print("✅ rtm_metadata.run_id never empty test passed!")
    return True


if __name__ == "__main__":
    try:
        test_rtm_audit_ready()
        test_persisted_rtm_artifact_structure()
        test_rtm_metadata_run_id_never_empty()
        print("\n✅ All tests passed!")
        sys.exit(0)
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
