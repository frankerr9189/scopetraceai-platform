"""
Unit tests for new artifact retrieval endpoints.
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
    run_id = "test-run-artifact-endpoints-001"
    
    # Create run
    save_run(
        db=temp_db,
        run_id=run_id,
        source_type="jira",
        status="generated",
        ticket_count=1
    )
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
    
    audit_metadata_data = {
        "run_id": run_id,
        "generated_at": "2024-01-01T00:00:00Z",
        "agent_version": "1.0.0"
    }
    
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
    temp_db.commit()
    
    return run_id


def test_get_test_plan_json_returns_200(client, temp_db, sample_run_with_artifacts):
    """Test that GET /api/v1/test-plan/<run_id>.json returns JSON."""
    response = client.get(f"/api/v1/test-plan/{sample_run_with_artifacts}.json")
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    assert "test_plan" in data
    assert "requirements" in data
    assert "audit_metadata" in data


def test_get_rtm_json_returns_200(client, temp_db, sample_run_with_artifacts):
    """Test that GET /api/v1/rtm/<run_id>.json returns JSON."""
    response = client.get(f"/api/v1/rtm/{sample_run_with_artifacts}.json")
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["requirement_id"] == "REQ-001"


def test_get_analysis_json_returns_200(client, temp_db, sample_run_with_artifacts):
    """Test that GET /api/v1/analysis/<run_id>.json returns JSON."""
    response = client.get(f"/api/v1/analysis/{sample_run_with_artifacts}.json")
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    assert "requirements" in data
    assert "metadata" in data
    assert len(data["requirements"]) == 1


def test_get_audit_json_returns_200(client, temp_db, sample_run_with_artifacts):
    """Test that GET /api/v1/audit/<run_id>.json returns JSON."""
    response = client.get(f"/api/v1/audit/{sample_run_with_artifacts}.json")
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    assert "run_id" in data
    assert data["run_id"] == sample_run_with_artifacts
    assert "generated_at" in data


def test_get_test_plan_json_404_when_run_missing(client):
    """Test that GET /api/v1/test-plan/<run_id>.json returns 404 for missing run."""
    response = client.get("/api/v1/test-plan/nonexistent-run-id.json")
    
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "detail" in data
    assert "Run not found" in data["detail"]


def test_get_test_plan_json_404_when_artifact_missing(client, temp_db, temp_artifacts_dir):
    """Test that GET /api/v1/test-plan/<run_id>.json returns 404 for missing artifact."""
    # Create a run but no artifacts
    run_id = "test-run-no-artifacts"
    save_run(
        db=temp_db,
        run_id=run_id,
        source_type="jira",
        status="generated"
    )
    temp_db.commit()
    
    response = client.get(f"/api/v1/test-plan/{run_id}.json")
    
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "detail" in data
    assert "Artifact not found" in data["detail"]
