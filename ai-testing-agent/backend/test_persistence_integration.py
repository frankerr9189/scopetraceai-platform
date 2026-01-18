"""
Unit tests for persistence integration in test plan generation flow.
"""
import pytest
import os
import tempfile
import shutil
import json
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db import Base, get_db
from models import Run, Artifact
from services.persistence import get_artifact_path
from app import persist_test_plan_result


@pytest.fixture
def temp_db():
    """Create a temporary SQLite database for testing."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine)
    
    # Override get_db to use our test database
    original_get_db = get_db
    def test_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()
    
    # Monkey-patch get_db for this test
    import app
    app.get_db = test_get_db
    
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        # Restore original
        app.get_db = original_get_db


@pytest.fixture
def temp_artifacts_dir():
    """Create a temporary artifacts directory for testing."""
    temp_dir = tempfile.mkdtemp()
    original_dir = os.getenv("ARTIFACTS_DIR")
    
    # Temporarily set ARTIFACTS_DIR
    os.environ["ARTIFACTS_DIR"] = temp_dir
    
    # Reload the persistence module to pick up new env var
    import importlib
    import services.persistence
    importlib.reload(services.persistence)
    
    yield temp_dir
    
    # Restore original
    if original_dir:
        os.environ["ARTIFACTS_DIR"] = original_dir
    else:
        os.environ.pop("ARTIFACTS_DIR", None)
    
    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)
    
    # Reload module again
    importlib.reload(services.persistence)


def test_persist_test_plan_result_writes_three_files(temp_db, temp_artifacts_dir):
    """Test that persist_test_plan_result writes three artifact files."""
    # Create a fake test plan result
    run_id = "test-run-persistence-001"
    result = {
        "requirements": [
            {"id": "REQ-001", "description": "Test requirement 1"},
            {"id": "REQ-002", "description": "Test requirement 2"}
        ],
        "rtm": [
            {
                "requirement_id": "REQ-001",
                "requirement_description": "Test requirement 1",
                "coverage_status": "COVERED",
                "covered_by_tests": ["API-001"]
            }
        ],
        "test_plan": {
            "api_tests": [
                {
                    "id": "API-001",
                    "title": "Test API",
                    "source_requirement_id": "REQ-001"
                }
            ]
        },
        "metadata": {
            "source": "jira",
            "source_id": "TEST-123"
        },
        "business_intent": "Test business intent",
        "audit_metadata": {
            "run_id": run_id,
            "generated_at": "2024-01-01T00:00:00Z",
            "source": {
                "type": "jira",
                "ticket_count": 1,
                "scope_type": "ticket",
                "scope_id": "TEST-123"
            },
            "model": {
                "name": "gpt-4o-mini"
            },
            "agent_metadata": {
                "logic_version": "testplan-v1+coverage-enforcer-v1"
            }
        }
    }
    
    scope = {"type": "ticket", "id": "TEST-123"}
    tickets = [{"ticket_id": "TEST-123", "source": "jira"}]
    source_type = "jira"
    
    # Call persistence function
    persist_test_plan_result(result, scope, tickets, source_type)
    
    # Verify Run was saved
    run = temp_db.query(Run).filter(Run.run_id == run_id).first()
    assert run is not None
    assert run.run_id == run_id
    assert run.source_type == "jira"
    assert run.status == "generated"
    assert run.ticket_count == 1
    assert run.scope_id == "TEST-123"
    assert run.scope_type == "ticket"
    assert run.logic_version == "testplan-v1+coverage-enforcer-v1"
    assert run.model_name == "gpt-4o-mini"
    
    # Verify four artifacts were saved
    artifacts = temp_db.query(Artifact).filter(Artifact.run_id == run_id).all()
    assert len(artifacts) == 4
    
    artifact_types = {a.artifact_type for a in artifacts}
    assert artifact_types == {"test_plan", "rtm", "analysis", "audit_metadata"}
    
    # Verify files exist on disk
    for artifact in artifacts:
        assert os.path.exists(artifact.path)
        assert artifact.sha256 is not None
        assert len(artifact.sha256) == 64  # SHA-256 hex length
    
    # Verify analysis.json content
    analysis_artifact = next(a for a in artifacts if a.artifact_type == "analysis")
    with open(analysis_artifact.path, 'r', encoding='utf-8') as f:
        analysis_data = json.load(f)
        assert "requirements" in analysis_data
        assert len(analysis_data["requirements"]) == 2
        assert analysis_data["requirements"][0]["id"] == "REQ-001"
    
    # Verify audit_metadata.json content
    audit_artifact = next(a for a in artifacts if a.artifact_type == "audit_metadata")
    with open(audit_artifact.path, 'r', encoding='utf-8') as f:
        audit_data = json.load(f)
        assert "run_id" in audit_data
        assert audit_data["run_id"] == run_id
    
    # Verify rtm.json content
    rtm_artifact = next(a for a in artifacts if a.artifact_type == "rtm")
    with open(rtm_artifact.path, 'r', encoding='utf-8') as f:
        rtm_data = json.load(f)
        assert isinstance(rtm_data, list)
        assert len(rtm_data) == 1
        assert rtm_data[0]["requirement_id"] == "REQ-001"
    
    # Verify test_plan.json content (full result)
    test_plan_artifact = next(a for a in artifacts if a.artifact_type == "test_plan")
    with open(test_plan_artifact.path, 'r', encoding='utf-8') as f:
        test_plan_data = json.load(f)
        assert "requirements" in test_plan_data
        assert "rtm" in test_plan_data
        assert "test_plan" in test_plan_data
        assert "audit_metadata" in test_plan_data
        assert test_plan_data["audit_metadata"]["run_id"] == run_id


def test_persist_test_plan_result_idempotent(temp_db, temp_artifacts_dir):
    """Test that calling persist_test_plan_result twice is idempotent."""
    run_id = "test-run-persistence-002"
    result = {
        "requirements": [{"id": "REQ-001", "description": "Test"}],
        "rtm": [],
        "test_plan": {"api_tests": []},
        "metadata": {"source": "jira", "source_id": "TEST-123"},
        "audit_metadata": {
            "run_id": run_id,
            "generated_at": "2024-01-01T00:00:00Z",
            "source": {"type": "jira", "ticket_count": 1},
            "model": {"name": "gpt-4o-mini"},
            "agent_metadata": {"logic_version": "testplan-v1"}
        }
    }
    
    scope = {"type": "ticket", "id": "TEST-123"}
    tickets = [{"ticket_id": "TEST-123", "source": "jira"}]
    
    # Call twice
    persist_test_plan_result(result, scope, tickets, "jira")
    persist_test_plan_result(result, scope, tickets, "jira")
    
    # Should only have one run
    runs = temp_db.query(Run).filter(Run.run_id == run_id).all()
    assert len(runs) == 1
    
    # Should only have four artifacts (one per type)
    artifacts = temp_db.query(Artifact).filter(Artifact.run_id == run_id).all()
    assert len(artifacts) == 4
    
    # Each artifact type should appear only once
    artifact_types = [a.artifact_type for a in artifacts]
    assert artifact_types.count("test_plan") == 1
    assert artifact_types.count("rtm") == 1
    assert artifact_types.count("analysis") == 1
    assert artifact_types.count("audit_metadata") == 1


def test_persist_test_plan_result_handles_missing_fields(temp_db, temp_artifacts_dir):
    """Test that persist_test_plan_result handles missing optional fields gracefully."""
    run_id = "test-run-persistence-003"
    result = {
        "requirements": [],
        "rtm": [],
        "test_plan": {},
        "metadata": {},
        "audit_metadata": {
            "run_id": run_id,
            "generated_at": "2024-01-01T00:00:00Z"
            # Missing source, model, agent_metadata
        }
    }
    
    scope = {}
    tickets = []
    
    # Should not raise exception
    persist_test_plan_result(result, scope, tickets, "unknown")
    
    # Verify Run was saved with defaults
    run = temp_db.query(Run).filter(Run.run_id == run_id).first()
    assert run is not None
    assert run.source_type == "unknown"
    assert run.status == "generated"
    assert run.ticket_count is None or run.ticket_count == 0
    assert run.logic_version is None
    assert run.model_name is None
    
    # Verify artifacts were still saved
    artifacts = temp_db.query(Artifact).filter(Artifact.run_id == run_id).all()
    assert len(artifacts) == 4
