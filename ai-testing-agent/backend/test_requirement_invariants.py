"""
Regression tests for requirement invariant enforcement.

These tests verify that requirements are never removed, merged, or collapsed
across source artifacts, regardless of processing order.

Run with: python -m pytest test_requirement_invariants.py -v
"""

import pytest
from app import (
    prefix_requirement_ids,
    merge_test_plans,
    get_requirement_identity_key,
    filter_container_requirements
)


def test_requirement_identity_key_stability():
    """Test that requirement identity keys are stable and deterministic."""
    req1 = {
        "id": "REQ-001",
        "source": "jira",
        "description": "The system shall provide a URL input field",
        "_source_id": "ATA-18"
    }
    
    req2 = {
        "id": "REQ-001",
        "source": "jira",
        "description": "The system shall provide a URL input field",
        "_source_id": "ATA-18"
    }
    
    key1 = get_requirement_identity_key(req1, "ATA-18")
    key2 = get_requirement_identity_key(req2, "ATA-18")
    
    # Same requirement should produce same key
    assert key1 == key2
    assert key1 == "ATA-18:jira:ATA-18-REQ-001"
    
    # Different source should produce different key
    req3 = req1.copy()
    req3["_source_id"] = "ATA-20"
    key3 = get_requirement_identity_key(req3, "ATA-20")
    assert key3 != key1
    assert key3 == "ATA-20:jira:ATA-20-REQ-001"


def test_requirement_identity_key_without_id():
    """Test that requirements without IDs get deterministic generated IDs."""
    req1 = {
        "source": "inferred",
        "description": "The system shall provide a URL input field",
        "_source_id": "ATA-18"
    }
    
    key1 = get_requirement_identity_key(req1, "ATA-18")
    
    # Should generate deterministic ID
    assert key1.startswith("ATA-18:inferred:ATA-18-REQ-")
    assert len(key1.split(":")[2]) > len("ATA-18-REQ-")  # Has hash suffix
    
    # Same requirement should produce same key
    req2 = req1.copy()
    key2 = get_requirement_identity_key(req2, "ATA-18")
    assert key1 == key2


def test_prefix_requirement_ids_preserves_all():
    """Test that prefix_requirement_ids preserves all requirements."""
    requirements = [
        {"id": "REQ-001", "source": "jira", "description": "Requirement 1"},
        {"id": "REQ-002", "source": "inferred", "description": "Requirement 2"},
        {"id": "", "source": "inferred", "description": "Requirement 3"},  # No ID
    ]
    
    prefixed = prefix_requirement_ids(requirements, "ATA-18")
    
    # All requirements should be preserved
    assert len(prefixed) == len(requirements)
    
    # All should have prefixed IDs
    assert prefixed[0]["id"] == "ATA-18-REQ-001"
    assert prefixed[1]["id"] == "ATA-18-REQ-002"
    assert prefixed[2]["id"].startswith("ATA-18-REQ-")  # Generated ID
    
    # All should have identity keys
    assert "_identity_key" in prefixed[0]
    assert "_identity_key" in prefixed[1]
    assert "_identity_key" in prefixed[2]
    
    # All should be locked
    assert prefixed[0].get("_locked", False) == True
    assert prefixed[1].get("_locked", False) == True
    assert prefixed[2].get("_locked", False) == True


def test_merge_test_plans_preserves_all_requirements():
    """Test that merge_test_plans preserves all requirements from all sources."""
    plan1 = {
        "requirements": [
            {"id": "ATA-18-REQ-001", "source": "jira", "description": "Req 1", "_source_id": "ATA-18", "_identity_key": "ATA-18:jira:ATA-18-REQ-001"},
            {"id": "ATA-18-REQ-002", "source": "inferred", "description": "Req 2", "_source_id": "ATA-18", "_identity_key": "ATA-18:inferred:ATA-18-REQ-002"},
        ],
        "_extracted_requirement_counts": {"ATA-18": 2},
        "_extracted_identity_keys": {
            "ATA-18": {"ATA-18:jira:ATA-18-REQ-001", "ATA-18:inferred:ATA-18-REQ-002"}
        }
    }
    
    plan2 = {
        "requirements": [
            {"id": "ATA-20-REQ-001", "source": "jira", "description": "Req 3", "_source_id": "ATA-20", "_identity_key": "ATA-20:jira:ATA-20-REQ-001"},
        ],
        "_extracted_requirement_counts": {"ATA-20": 1},
        "_extracted_identity_keys": {
            "ATA-20": {"ATA-20:jira:ATA-20-REQ-001"}
        }
    }
    
    merged = merge_test_plans([plan1, plan2])
    
    # All requirements should be preserved
    assert len(merged["requirements"]) == 3
    
    # Counts should be preserved
    assert merged["_extracted_requirement_counts"]["ATA-18"] == 2
    assert merged["_extracted_requirement_counts"]["ATA-20"] == 1
    
    # Identity keys should be preserved
    assert len(merged["_extracted_identity_keys"]["ATA-18"]) == 2
    assert len(merged["_extracted_identity_keys"]["ATA-20"]) == 1


def test_merge_test_plans_order_independence():
    """Test that merge_test_plans produces same result regardless of order."""
    plan1 = {
        "requirements": [
            {"id": "ATA-18-REQ-001", "_source_id": "ATA-18", "_identity_key": "ATA-18:jira:ATA-18-REQ-001"},
        ],
        "_extracted_requirement_counts": {"ATA-18": 1},
        "_extracted_identity_keys": {"ATA-18": {"ATA-18:jira:ATA-18-REQ-001"}}
    }
    
    plan2 = {
        "requirements": [
            {"id": "ATA-20-REQ-001", "_source_id": "ATA-20", "_identity_key": "ATA-20:jira:ATA-20-REQ-001"},
        ],
        "_extracted_requirement_counts": {"ATA-20": 1},
        "_extracted_identity_keys": {"ATA-20": {"ATA-20:jira:ATA-20-REQ-001"}}
    }
    
    merged1 = merge_test_plans([plan1, plan2])
    merged2 = merge_test_plans([plan2, plan1])
    
    # Should have same number of requirements
    assert len(merged1["requirements"]) == len(merged2["requirements"]) == 2
    
    # Should have same identity keys
    keys1 = {req.get("_identity_key") for req in merged1["requirements"] if req.get("_identity_key")}
    keys2 = {req.get("_identity_key") for req in merged2["requirements"] if req.get("_identity_key")}
    assert keys1 == keys2


def test_filter_container_requirements_preserves_locked():
    """Test that filter_container_requirements never removes locked requirements."""
    requirements = [
        {"id": "REQ-001", "_locked": True, "description": "Container requirement"},
        {"id": "REQ-002", "_locked": False, "description": "Regular requirement"},
        {"id": "REQ-003", "_locked": True, "description": "Another locked requirement"},
    ]
    
    filtered = filter_container_requirements(requirements)
    
    # All locked requirements should be preserved
    locked_ids = {req["id"] for req in filtered if req.get("_locked", False)}
    assert "REQ-001" in locked_ids
    assert "REQ-003" in locked_ids
    
    # At least the locked ones should be present
    assert len(filtered) >= 2


def test_requirement_count_invariant():
    """Test that requirement counts never decrease during processing."""
    # Simulate extraction
    extracted_counts = {"ATA-18": 3, "ATA-20": 2}
    
    # Simulate final output
    final_requirements = [
        {"_source_id": "ATA-18", "_identity_key": "ATA-18:jira:ATA-18-REQ-001"},
        {"_source_id": "ATA-18", "_identity_key": "ATA-18:jira:ATA-18-REQ-002"},
        {"_source_id": "ATA-18", "_identity_key": "ATA-18:jira:ATA-18-REQ-003"},
        {"_source_id": "ATA-20", "_identity_key": "ATA-20:jira:ATA-20-REQ-001"},
        {"_source_id": "ATA-20", "_identity_key": "ATA-20:jira:ATA-20-REQ-002"},
    ]
    
    # Count final requirements by source
    final_counts = {}
    for req in final_requirements:
        source_id = req.get("_source_id", "")
        if source_id:
            final_counts[source_id] = final_counts.get(source_id, 0) + 1
    
    # Verify invariant: final_count >= extracted_count
    for source_id, extracted_count in extracted_counts.items():
        final_count = final_counts.get(source_id, 0)
        assert final_count >= extracted_count, f"Source {source_id}: final count {final_count} < extracted count {extracted_count}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

