"""
Unit tests for Test Execution Report CSV export endpoint.
"""
import pytest
import csv
import io
from app import app, load_test_plan_by_run_id, extract_non_testable_items_from_rtm, generate_execution_report_csv, format_steps_for_csv


@pytest.fixture
def client():
    """Create Flask test client."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def sample_test_plan():
    """Create a sample test plan with tests and non-testable items."""
    run_id = "test-run-123"
    return {
        "schema_version": "1.0",
        "metadata": {
            "source": "jira",
            "source_id": "ATA-41",
            "generated_at": "2024-01-01T00:00:00Z"
        },
        "requirements": [
            {
                "id": "ATA-41-REQ-001",
                "description": "Test requirement"
            }
        ],
        "test_plan": {
            "api_tests": [
                {
                    "id": "API-001",
                    "title": "Test API endpoint",
                    "source_requirement_id": "ATA-41-REQ-001",
                    "requirements_covered": ["ATA-41-REQ-001"],
                    "intent_type": "happy_path",
                    "steps": ["Step 1", "Step 2", "Step 3"],
                    "expected_result": "Success response",
                    "steps_origin": "requirement-derived",
                    "priority": "high",
                    "confidence": "explicit"
                }
            ],
            "ui_tests": [
                {
                    "id": "UI-001",
                    "title": "Test UI element",
                    "source_requirement_id": "ATA-41-REQ-001",
                    "requirements_covered": ["ATA-41-REQ-001"],
                    "intent_type": "happy_path",
                    "steps": ["Click button", "Verify result"],
                    "expected_result": "Button works",
                    "steps_origin": "requirement-derived",
                    "priority": "medium",
                    "confidence": "explicit"
                }
            ],
            "data_validation_tests": [],
            "edge_cases": [],
            "negative_tests": []
        },
        "rtm": [
            {
                "requirement_id": "ATA-41-REQ-001",
                "requirement_description": "Test requirement",
                "covered_by_tests": ["API-001", "UI-001"],
                "coverage_status": "COVERED",
                "trace_type": "testable",
                "testability": "testable"
            },
            {
                "requirement_id": "ATA-41-ITEM-001",
                "requirement_description": "Informational item",
                "covered_by_tests": [],
                "coverage_status": "N/A",
                "trace_type": "informational",
                "testability": "not_testable",
                "rationale": "Informational content; not independently testable",
                "source_section": "description"
            }
        ],
        "audit_metadata": {
            "run_id": run_id,
            "generated_at": "2024-01-01T00:00:00Z",
            "agent_version": "1.0.0",
            "model": {
                "name": "gpt-4o-mini",
                "temperature": 0.2
            },
            "environment": "test",
            "source": {
                "type": "jira",
                "ticket_count": 1
            },
            "agent_metadata": {
                "agent": "test-plan-agent",
                "agent_version": "1.0.0",
                "logic_version": "testplan-v1+coverage-enforcer-v1",
                "determinism": "LLM + deterministic post-pass",
                "change_policy": "idempotent"
            }
        }
    }


def test_execution_report_csv_headers_exact(client, sample_test_plan, monkeypatch):
    """Test that CSV headers are in exact required order."""
    # Mock load_test_plan_by_run_id to return sample test plan
    def mock_load(run_id):
        if run_id == "test-run-123":
            return sample_test_plan
        return None
    
    monkeypatch.setattr(app_module, "load_test_plan_by_run_id", mock_load)
    
    response = client.get("/api/v1/test-plan/test-run-123/execution-report.csv")
    
    assert response.status_code == 200
    assert response.content_type == "text/csv; charset=utf-8"
    
    # Parse first line as headers
    csv_text = response.data.decode('utf-8')
    reader = csv.reader(io.StringIO(csv_text))
    headers = next(reader)
    
    expected_headers = [
        "Logic Version",
        "Agent Version",
        "Run ID",
        "Section",
        "Item Type",
        "Test ID",
        "Title",
        "Source Requirement ID",
        "Requirements Covered",
        "Intent Type",
        "Steps",
        "Expected Result",
        "Steps Origin",
        "Priority",
        "Confidence",
        "Traceability Note",
        "Result",
        "Tester Notes",
        "Executed At"
    ]
    
    assert headers == expected_headers


def test_execution_report_deterministic_order(client, sample_test_plan, monkeypatch):
    """Test that rows appear in required section order and preserve per-list order."""
    # Add more tests to verify ordering
    sample_test_plan["test_plan"]["data_validation_tests"] = [
        {
            "id": "DATA-001",
            "title": "Data validation test",
            "source_requirement_id": "ATA-41-REQ-001",
            "requirements_covered": ["ATA-41-REQ-001"],
            "intent_type": "happy_path",
            "steps": ["Validate data"],
            "expected_result": "Data valid",
            "steps_origin": "requirement-derived",
            "priority": "medium",
            "confidence": "explicit"
        }
    ]
    sample_test_plan["test_plan"]["edge_cases"] = [
        {
            "id": "EDGE-001",
            "title": "Edge case test",
            "source_requirement_id": "ATA-41-REQ-001",
            "requirements_covered": ["ATA-41-REQ-001"],
            "intent_type": "boundary",
            "steps": ["Test edge"],
            "expected_result": "Edge handled",
            "steps_origin": "requirement-derived",
            "priority": "low",
            "confidence": "inferred"
        }
    ]
    sample_test_plan["test_plan"]["negative_tests"] = [
        {
            "id": "NEG-001",
            "title": "Negative test",
            "source_requirement_id": "ATA-41-REQ-001",
            "requirements_covered": ["ATA-41-REQ-001"],
            "intent_type": "negative",
            "steps": ["Test negative"],
            "expected_result": "Error handled",
            "steps_origin": "requirement-derived",
            "priority": "medium",
            "confidence": "explicit"
        }
    ]
    
    def mock_load(run_id):
        if run_id == "test-run-123":
            return sample_test_plan
        return None
    
    monkeypatch.setattr(app_module, "load_test_plan_by_run_id", mock_load)
    
    response = client.get("/api/v1/test-plan/test-run-123/execution-report.csv")
    assert response.status_code == 200
    
    csv_text = response.data.decode('utf-8')
    reader = csv.DictReader(io.StringIO(csv_text))
    rows = list(reader)
    
    # Verify section order: API, UI, Data Validation, Edge Case, Negative, Informational
    sections = [row["Section"] for row in rows]
    
    # Find indices of each section
    api_idx = sections.index("API") if "API" in sections else -1
    ui_idx = sections.index("UI") if "UI" in sections else -1
    data_idx = sections.index("Data Validation") if "Data Validation" in sections else -1
    edge_idx = sections.index("Edge Case") if "Edge Case" in sections else -1
    neg_idx = sections.index("Negative") if "Negative" in sections else -1
    info_idx = sections.index("Informational") if "Informational" in sections else -1
    
    # Verify order: API < UI < Data Validation < Edge Case < Negative < Informational
    if api_idx >= 0 and ui_idx >= 0:
        assert api_idx < ui_idx
    if ui_idx >= 0 and data_idx >= 0:
        assert ui_idx < data_idx
    if data_idx >= 0 and edge_idx >= 0:
        assert data_idx < edge_idx
    if edge_idx >= 0 and neg_idx >= 0:
        assert edge_idx < neg_idx
    if neg_idx >= 0 and info_idx >= 0:
        assert neg_idx < info_idx
    
    # Verify test IDs within sections preserve order
    api_tests = [row["Test ID"] for row in rows if row["Section"] == "API"]
    assert api_tests == ["API-001"]
    
    ui_tests = [row["Test ID"] for row in rows if row["Section"] == "UI"]
    assert ui_tests == ["UI-001"]


def test_execution_report_includes_blank_result_notes_columns(client, sample_test_plan, monkeypatch):
    """Test that Result and Tester Notes columns exist and are blank in all rows."""
    def mock_load(run_id):
        if run_id == "test-run-123":
            return sample_test_plan
        return None
    
    monkeypatch.setattr(app_module, "load_test_plan_by_run_id", mock_load)
    
    response = client.get("/api/v1/test-plan/test-run-123/execution-report.csv")
    assert response.status_code == 200
    
    csv_text = response.data.decode('utf-8')
    reader = csv.DictReader(io.StringIO(csv_text))
    rows = list(reader)
    
    # Verify all rows have Result and Tester Notes columns and they are blank
    for row in rows:
        assert "Result" in row
        assert "Tester Notes" in row
        assert row["Result"] == ""
        assert row["Tester Notes"] == ""
        # Assert Logic Version and Agent Version are present and have stable values
        assert "Logic Version" in row
        assert "Agent Version" in row
        assert row["Logic Version"] == "testplan-v1+coverage-enforcer-v1"
        assert row["Agent Version"] == "1.0.0"


def test_execution_report_includes_non_testable_rows(client, sample_test_plan, monkeypatch):
    """Test that non-testable items show up at bottom with Section='Informational'."""
    def mock_load(run_id):
        if run_id == "test-run-123":
            return sample_test_plan
        return None
    
    monkeypatch.setattr(app_module, "load_test_plan_by_run_id", mock_load)
    
    response = client.get("/api/v1/test-plan/test-run-123/execution-report.csv")
    assert response.status_code == 200
    
    csv_text = response.data.decode('utf-8')
    reader = csv.DictReader(io.StringIO(csv_text))
    rows = list(reader)
    
    # Find informational rows
    informational_rows = [row for row in rows if row["Section"] == "Informational"]
    
    assert len(informational_rows) > 0
    
    # Verify informational row properties
    info_row = informational_rows[0]
    assert info_row["Item Type"] == "Informational Only"
    assert info_row["Test ID"] == "ATA-41-ITEM-001"
    assert info_row["Title"] == "Informational item"
    assert info_row["Intent Type"] == "not_testable"
    assert info_row["Steps Origin"] == "source-only"
    assert "Not Testable:" in info_row["Traceability Note"]
    assert "Source Section:" in info_row["Traceability Note"]
    
    # Verify informational rows are at the end
    last_section = rows[-1]["Section"]
    assert last_section == "Informational"


def test_execution_report_steps_numbering(client, sample_test_plan, monkeypatch):
    """Test that Steps cell contains numbered format '1) ...\\n2) ...' for multi-step tests."""
    def mock_load(run_id):
        if run_id == "test-run-123":
            return sample_test_plan
        return None
    
    monkeypatch.setattr(app_module, "load_test_plan_by_run_id", mock_load)
    
    response = client.get("/api/v1/test-plan/test-run-123/execution-report.csv")
    assert response.status_code == 200
    
    csv_text = response.data.decode('utf-8')
    reader = csv.DictReader(io.StringIO(csv_text))
    rows = list(reader)
    
    # Find API test row
    api_row = next((row for row in rows if row["Test ID"] == "API-001"), None)
    assert api_row is not None
    
    steps = api_row["Steps"]
    # Verify numbered format
    assert "1) Step 1" in steps
    assert "2) Step 2" in steps
    assert "3) Step 3" in steps
    assert "\n" in steps  # Should have newlines


def test_execution_report_404_when_run_missing(client, monkeypatch):
    """Test that endpoint returns 404 when run_id is not found."""
    def mock_load(run_id):
        return None
    
    monkeypatch.setattr(app_module, "load_test_plan_by_run_id", mock_load)
    
    response = client.get("/api/v1/test-plan/nonexistent-run/execution-report.csv")
    
    assert response.status_code == 404
    data = response.get_json()
    assert data["detail"] == "Run not found"


def test_format_steps_for_csv():
    """Test format_steps_for_csv helper function."""
    steps = ["Step 1", "Step 2", "Step 3"]
    result = format_steps_for_csv(steps)
    
    assert "1) Step 1" in result
    assert "2) Step 2" in result
    assert "3) Step 3" in result
    assert "\n" in result
    
    # Test empty list
    assert format_steps_for_csv([]) == ""
    
    # Test None
    assert format_steps_for_csv(None) == ""


def test_extract_non_testable_items_from_rtm():
    """Test extract_non_testable_items_from_rtm helper function."""
    rtm = [
        {
            "requirement_id": "REQ-001",
            "requirement_description": "Testable requirement",
            "trace_type": "testable",
            "testability": "testable"
        },
        {
            "requirement_id": "ITEM-001",
            "requirement_description": "Informational item",
            "trace_type": "informational",
            "testability": "not_testable",
            "rationale": "Informational content",
            "source_section": "description"
        }
    ]
    
    items = extract_non_testable_items_from_rtm(rtm)
    
    assert len(items) == 1
    assert items[0]["id"] == "ITEM-001"
    assert items[0]["title"] == "Informational item"
    assert items[0]["rationale"] == "Informational content"
    assert items[0]["source_section"] == "description"


def test_generate_execution_report_csv():
    """Test generate_execution_report_csv function."""
    test_plan = {
        "test_plan": {
            "api_tests": [
                {
                    "id": "API-001",
                    "title": "Test API",
                    "source_requirement_id": "REQ-001",
                    "requirements_covered": ["REQ-001"],
                    "intent_type": "happy_path",
                    "steps": ["Step 1", "Step 2"],
                    "expected_result": "Success",
                    "steps_origin": "requirement-derived",
                    "priority": "high",
                    "confidence": "explicit"
                }
            ],
            "ui_tests": [],
            "data_validation_tests": [],
            "edge_cases": [],
            "negative_tests": []
        },
        "rtm": [
            {
                "requirement_id": "ITEM-001",
                "requirement_description": "Informational",
                "trace_type": "informational",
                "testability": "not_testable",
                "rationale": "Not testable",
                "source_section": "description"
            }
        ],
        "audit_metadata": {
            "run_id": "test-run-456"
        }
    }
    
    csv_content = generate_execution_report_csv(test_plan, "test-run-456")
    
    # Parse CSV
    reader = csv.DictReader(io.StringIO(csv_content))
    rows = list(reader)
    
    # Should have 2 rows: 1 test + 1 informational
    assert len(rows) == 2
    
    # Check test row
    test_row = rows[0]
    assert test_row["Run ID"] == "test-run-456"
    assert test_row["Section"] == "API"
    assert test_row["Item Type"] == "Test"
    assert test_row["Test ID"] == "API-001"
    
    # Check informational row
    info_row = rows[1]
    assert info_row["Section"] == "Informational"
    assert info_row["Item Type"] == "Informational Only"
    assert info_row["Test ID"] == "ITEM-001"
    assert "Not Testable:" in info_row["Traceability Note"]
