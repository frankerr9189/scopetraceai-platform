"""
Unit tests for runs listing and artifact fetching endpoints.
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
from services.persistence import write_json_artifact, save_run, save_artifact
from app import app


@pytest.fixture
def temp_db():
    """Create a temporary SQLite database for testing."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine)
    
    # Create a shared session for the test
    test_session = SessionLocal()
    
    def test_get_db():
        # Return the same session each time
        yield test_session
    
    # Monkey-patch get_db in both db module and app module
    import db
    import app
    original_db_get_db = db.get_db
    original_app_get_db = getattr(app, 'get_db', None)
    
    db.get_db = test_get_db
    app.get_db = test_get_db
    
    try:
        yield test_session
    finally:
        test_session.rollback()  # Rollback any uncommitted changes
        test_session.close()
        # Restore original
        db.get_db = original_db_get_db
        if original_app_get_db:
            app.get_db = original_app_get_db


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


@pytest.fixture
def client(temp_db, temp_artifacts_dir):
    """Create Flask test client with test database."""
    # Ensure get_db is patched before creating client
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def sample_run_with_artifacts(temp_db, temp_artifacts_dir):
    """Create a sample run with artifacts for testing."""
    run_id = "test-run-endpoints-001"
    
    # Create run
    save_run(
        db=temp_db,
        run_id=run_id,
        source_type="jira",
        status="success",
        ticket_count=2,
        scope_id="TEST-123",
        scope_type="ticket",
        logic_version="testplan-v1",
        model_name="gpt-4o-mini"
    )
    
    # Ensure commit happens
    temp_db.commit()
    
    # Create artifacts
    test_plan_data = {
        "test_plan": {"api_tests": [{"id": "API-001", "title": "Test"}]},
        "requirements": [{"id": "REQ-001"}],
        "audit_metadata": {"run_id": run_id}
    }
    
    rtm_data = [
        {"requirement_id": "REQ-001", "coverage_status": "COVERED"}
    ]
    
    analysis_data = {
        "requirements": [{"id": "REQ-001", "description": "Test requirement"}],
        "metadata": {"source": "jira"}
    }
    
    audit_metadata_data = {"run_id": run_id, "generated_at": "2024-01-01T00:00:00Z"}
    
    # Write artifacts
    for artifact_type, artifact_obj in [
        ("test_plan", test_plan_data),
        ("rtm", rtm_data),
        ("analysis", analysis_data),
        ("audit_metadata", audit_metadata_data)
    ]:
        artifact_path, artifact_sha256 = write_json_artifact(
            run_id, artifact_type, artifact_obj
        )
        save_artifact(
            db=temp_db,
            run_id=run_id,
            artifact_type=artifact_type,
            path=artifact_path,
            sha256=artifact_sha256
        )
    
    # Ensure all commits happen
    temp_db.commit()
    
    return run_id


def test_list_runs_returns_runs(client, temp_db, sample_run_with_artifacts):
    """Test that GET /api/v1/runs returns list of runs."""
    response = client.get("/api/v1/runs")
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    assert isinstance(data, list)
    assert len(data) == 1
    
    run = data[0]
    assert run["run_id"] == sample_run_with_artifacts
    assert run["source_type"] == "jira"
    assert run["status"] == "success"
    assert run["ticket_count"] == 2
    assert run["logic_version"] == "testplan-v1"
    assert run["model_name"] == "gpt-4o-mini"
    assert "created_at" in run
    assert run["created_at"].endswith("Z")  # ISO8601 with Z suffix


def test_list_runs_ordered_by_created_at_desc(client, temp_db, temp_artifacts_dir):
    """Test that runs are ordered by created_at descending."""
    # Create multiple runs with slight time differences
    import time
    from datetime import datetime, timedelta
    
    run_ids = []
    for i in range(3):
        run_id = f"test-run-order-{i}"
        run_ids.append(run_id)
        
        # Create run with different created_at times
        run = Run(
            run_id=run_id,
            created_at=datetime.utcnow() - timedelta(seconds=i),
            source_type="jira",
            status="success"
        )
        temp_db.add(run)
        temp_db.commit()
    
    response = client.get("/api/v1/runs")
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    # Should be ordered by created_at desc (newest first)
    assert len(data) >= 3
    created_times = [r["created_at"] for r in data if r["run_id"] in run_ids]
    assert created_times == sorted(created_times, reverse=True)


def test_get_artifact_returns_test_plan(client, temp_db, sample_run_with_artifacts):
    """Test that GET /api/v1/runs/<run_id>/test_plan returns JSON."""
    response = client.get(f"/api/v1/runs/{sample_run_with_artifacts}/test_plan")
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    assert "test_plan" in data
    assert "requirements" in data
    assert "audit_metadata" in data
    assert data["audit_metadata"]["run_id"] == sample_run_with_artifacts


def test_get_artifact_returns_rtm(client, temp_db, sample_run_with_artifacts):
    """Test that GET /api/v1/runs/<run_id>/rtm returns JSON."""
    response = client.get(f"/api/v1/runs/{sample_run_with_artifacts}/rtm")
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["requirement_id"] == "REQ-001"


def test_get_artifact_returns_analysis(client, temp_db, sample_run_with_artifacts):
    """Test that GET /api/v1/runs/<run_id>/analysis returns JSON."""
    response = client.get(f"/api/v1/runs/{sample_run_with_artifacts}/analysis")
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    assert "requirements" in data
    assert "metadata" in data
    assert len(data["requirements"]) == 1


def test_get_artifact_returns_audit_metadata(client, temp_db, sample_run_with_artifacts):
    """Test that GET /api/v1/runs/<run_id>/audit_metadata returns JSON."""
    response = client.get(f"/api/v1/runs/{sample_run_with_artifacts}/audit_metadata")
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    assert "run_id" in data
    assert data["run_id"] == sample_run_with_artifacts


def test_get_artifact_404_when_run_missing(client):
    """Test that GET /api/v1/runs/<run_id>/test_plan returns 404 for missing run."""
    response = client.get("/api/v1/runs/nonexistent-run-id/test_plan")
    
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "detail" in data
    assert "not found" in data["detail"].lower()


def test_get_artifact_404_when_artifact_missing(client, temp_db, temp_artifacts_dir):
    """Test that GET /api/v1/runs/<run_id>/test_plan returns 404 for missing artifact."""
    # Create a run but no artifacts
    run_id = "test-run-no-artifacts"
    save_run(
        db=temp_db,
        run_id=run_id,
        source_type="jira",
        status="success"
    )
    
    response = client.get(f"/api/v1/runs/{run_id}/test_plan")
    
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "detail" in data
    assert "not found" in data["detail"].lower()


def test_get_artifact_404_when_file_missing(client, temp_db, temp_artifacts_dir):
    """Test that GET /api/v1/runs/<run_id>/test_plan returns 404 when file is missing."""
    run_id = "test-run-missing-file"
    
    # Create run and artifact record, but delete the file
    save_run(
        db=temp_db,
        run_id=run_id,
        source_type="jira",
        status="success"
    )
    
    # Create artifact with non-existent path
    artifact = Artifact(
        run_id=run_id,
        artifact_type="test_plan",
        path="/nonexistent/path/test_plan.json",
        sha256="abc123"
    )
    temp_db.add(artifact)
    temp_db.commit()
    
    response = client.get(f"/api/v1/runs/{run_id}/test_plan")
    
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "detail" in data
    assert "file not found" in data["detail"].lower() or "not found" in data["detail"].lower()


def test_get_artifact_invalid_artifact_type(client):
    """Test that GET /api/v1/runs/<run_id>/invalid returns 400."""
    response = client.get("/api/v1/runs/test-run/invalid")
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "detail" in data
    assert "invalid" in data["detail"].lower() or "allowed" in data["detail"].lower()


def test_list_runs_empty_when_no_runs(client):
    """Test that GET /api/v1/runs returns empty list when no runs exist."""
    response = client.get("/api/v1/runs")
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    assert isinstance(data, list)
    assert len(data) == 0
