"""
Unit tests for RTM informational/non-testable items.

Tests that RTM includes informational items from ticket_item_coverage
and that they have the correct structure and ordering.
"""
import pytest
from app import generate_rtm


def test_rtm_includes_informational_items():
    """Test that RTM includes informational items when present in ticket_item_coverage."""
    test_plan = {
        "requirements": [
            {
                "id": "REQ-001",
                "description": "Testable requirement"
            }
        ],
        "test_plan": {
            "api_tests": [
                {
                    "id": "API-001",
                    "requirements_covered": ["REQ-001"]
                }
            ]
        },
        "ticket_item_coverage": [
            {
                "item_id": "ATA-41-ITEM-001",
                "text": "Secure storage for third-party API credentials",
                "classification": "informational_only",
                "testable": False,
                "coverage_method": "not_independently_testable",
                "non_testable_reason": "Informational content; not independently testable"
            },
            {
                "item_id": "ATA-41-ITEM-002",
                "text": "Secure storage of base_url",
                "classification": "informational_only",
                "testable": False,
                "coverage_method": "not_independently_testable",
                "non_testable_reason": "Informational content; not independently testable"
            }
        ],
        "ticket_traceability": [
            {
                "ticket_id": "ATA-41",
                "items": [
                    {
                        "item_id": "ATA-41-ITEM-001",
                        "text": "Secure storage for third-party API credentials",
                        "source_section": "description",
                        "classification": "informational_only",
                        "testable": False
                    },
                    {
                        "item_id": "ATA-41-ITEM-002",
                        "text": "Secure storage of base_url",
                        "source_section": "description",
                        "classification": "informational_only",
                        "testable": False
                    }
                ]
            }
        ]
    }
    
    rtm = generate_rtm(test_plan)
    
    # Should have testable requirement + 2 informational items
    assert len(rtm) == 3
    
    # First entry should be testable requirement
    assert rtm[0]["requirement_id"] == "REQ-001"
    assert rtm[0]["trace_type"] == "testable"
    assert rtm[0]["testability"] == "testable"
    assert rtm[0]["coverage_status"] == "COVERED"
    
    # Last two entries should be informational
    informational_entries = [e for e in rtm if e.get("trace_type") == "informational"]
    assert len(informational_entries) == 2
    
    for entry in informational_entries:
        assert entry["trace_type"] == "informational"
        assert entry["testability"] == "not_testable"
        assert entry["covered_by_tests"] == []
        assert entry["coverage_status"] == "N/A"
        assert entry["rationale"] is not None
        assert len(entry["rationale"]) > 0


def test_informational_rtm_rows_have_required_fields():
    """Test that informational RTM rows have all required fields."""
    test_plan = {
        "requirements": [],
        "test_plan": {},
        "ticket_item_coverage": [
            {
                "item_id": "ATA-41-ITEM-001",
                "text": "Informational item",
                "classification": "informational_only",
                "testable": False,
                "coverage_method": "not_independently_testable",
                "non_testable_reason": "Informational content; not independently testable"
            }
        ],
        "ticket_traceability": [
            {
                "ticket_id": "ATA-41",
                "items": [
                    {
                        "item_id": "ATA-41-ITEM-001",
                        "text": "Informational item",
                        "source_section": "description",
                        "classification": "informational_only",
                        "testable": False
                    }
                ]
            }
        ]
    }
    
    rtm = generate_rtm(test_plan)
    
    assert len(rtm) == 1
    entry = rtm[0]
    
    # Required fields
    assert entry["trace_type"] == "informational"
    assert entry["testability"] == "not_testable"
    assert entry["covered_by_tests"] == []
    assert entry["rationale"] is not None
    assert len(entry["rationale"]) > 0
    assert "source_section" in entry
    assert entry["source_section"] is not None


def test_rtm_ordering_testable_first_then_informational():
    """Test that RTM ordering is deterministic: testable rows first, then informational items in stable order."""
    test_plan = {
        "requirements": [
            {"id": "REQ-001", "description": "Requirement 1"},
            {"id": "REQ-002", "description": "Requirement 2"}
        ],
        "test_plan": {
            "api_tests": [
                {"id": "API-001", "requirements_covered": ["REQ-001"]}
            ]
        },
        "ticket_item_coverage": [
            {
                "item_id": "ATA-41-ITEM-003",
                "text": "Item 3",
                "classification": "informational_only",
                "testable": False,
                "coverage_method": "not_independently_testable",
                "non_testable_reason": "Informational"
            },
            {
                "item_id": "ATA-41-ITEM-001",
                "text": "Item 1",
                "classification": "informational_only",
                "testable": False,
                "coverage_method": "not_independently_testable",
                "non_testable_reason": "Informational"
            },
            {
                "item_id": "ATA-41-ITEM-002",
                "text": "Item 2",
                "classification": "informational_only",
                "testable": False,
                "coverage_method": "not_independently_testable",
                "non_testable_reason": "Informational"
            }
        ],
        "ticket_traceability": []
    }
    
    rtm = generate_rtm(test_plan)
    
    # Should have 2 testable + 3 informational = 5 total
    assert len(rtm) == 5
    
    # First 2 should be testable requirements
    assert rtm[0]["trace_type"] == "testable"
    assert rtm[0]["requirement_id"] == "REQ-001"
    assert rtm[1]["trace_type"] == "testable"
    assert rtm[1]["requirement_id"] == "REQ-002"
    
    # Last 3 should be informational, sorted by item_id
    assert rtm[2]["trace_type"] == "informational"
    assert rtm[2]["requirement_id"] == "ATA-41-ITEM-001"
    assert rtm[3]["trace_type"] == "informational"
    assert rtm[3]["requirement_id"] == "ATA-41-ITEM-002"
    assert rtm[4]["trace_type"] == "informational"
    assert rtm[4]["requirement_id"] == "ATA-41-ITEM-003"


def test_rtm_informational_items_use_item_id():
    """Test that informational RTM rows use the item_id from ticket_item_coverage."""
    test_plan = {
        "requirements": [],
        "test_plan": {},
        "ticket_item_coverage": [
            {
                "item_id": "ATA-41-ITEM-025",
                "text": "Rotation",
                "classification": "unclear_needs_clarification",
                "testable": False,
                "coverage_method": "not_independently_testable",
                "non_testable_reason": "Item text is unclear or incomplete; needs clarification"
            }
        ],
        "ticket_traceability": []
    }
    
    rtm = generate_rtm(test_plan)
    
    assert len(rtm) == 1
    assert rtm[0]["requirement_id"] == "ATA-41-ITEM-025"
    assert rtm[0]["requirement_description"] == "Rotation"


def test_rtm_generates_deterministic_id_when_missing():
    """Test that RTM generates deterministic item_id when missing from ticket_item_coverage."""
    test_plan = {
        "requirements": [
            {"id": "ATA-41-REQ-001", "description": "Requirement"}
        ],
        "test_plan": {},
        "ticket_item_coverage": [
            {
                "text": "Informational item without ID",
                "classification": "informational_only",
                "testable": False,
                "coverage_method": "not_independently_testable",
                "non_testable_reason": "Informational"
            }
        ],
        "ticket_traceability": []
    }
    
    rtm = generate_rtm(test_plan)
    
    # Should have 1 testable + 1 informational
    assert len(rtm) == 2
    
    # Informational entry should have generated ID
    informational = [e for e in rtm if e.get("trace_type") == "informational"][0]
    assert informational["requirement_id"].startswith("ATA-41-ITEM-")
    assert "001" in informational["requirement_id"]


def test_rtm_preserves_existing_testable_rows():
    """Test that existing testable RTM rows are preserved unchanged."""
    test_plan = {
        "requirements": [
            {"id": "REQ-001", "description": "Requirement 1"},
            {"id": "REQ-002", "description": "Requirement 2"}
        ],
        "test_plan": {
            "api_tests": [
                {"id": "API-001", "requirements_covered": ["REQ-001"]},
                {"id": "API-002", "requirements_covered": ["REQ-002"]}
            ]
        },
        "ticket_item_coverage": [],
        "ticket_traceability": []
    }
    
    rtm = generate_rtm(test_plan)
    
    # Should have 2 testable requirements
    assert len(rtm) == 2
    
    # Both should be testable
    assert all(e.get("trace_type") == "testable" for e in rtm)
    assert all(e.get("testability") == "testable" for e in rtm)
    
    # REQ-001 should be COVERED, REQ-002 should be COVERED
    req1_entry = next(e for e in rtm if e["requirement_id"] == "REQ-001")
    req2_entry = next(e for e in rtm if e["requirement_id"] == "REQ-002")
    
    assert req1_entry["coverage_status"] == "COVERED"
    assert req1_entry["covered_by_tests"] == ["API-001"]
    assert req2_entry["coverage_status"] == "COVERED"
    assert req2_entry["covered_by_tests"] == ["API-002"]
