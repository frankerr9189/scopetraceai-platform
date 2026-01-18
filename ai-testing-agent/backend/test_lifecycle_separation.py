"""
Unit tests for lifecycle separation: Requirements Agent owns lifecycle, Test Agent is derivative.
"""
import pytest
from unittest.mock import Mock, patch
from app import app
from db import get_db
from models import Run
from services.persistence import save_run, write_json_artifact, save_artifact
import json
import os
import tempfile
import shutil
from datetime import datetime


@pytest.fixture
def client():
    """Create Flask test client."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    import tempfile
    import os
    from db import engine, Base, SessionLocal
    from sqlalchemy import create_engine
    
    db_fd, db_path = tempfile.mkstemp(suffix='.db')
    test_db_url = f"sqlite:///{db_path}"
    test_engine = create_engine(test_db_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=test_engine)
    
    TestSessionLocal = SessionLocal
    TestSessionLocal.configure(bind=test_engine)
    
    def test_get_db():
        db = TestSessionLocal()
        try:
            yield db
        finally:
            db.close()
    
    app.get_db = test_get_db
    
    yield test_engine
    
    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture
def temp_artifacts_dir():
    """Create a temporary artifacts directory."""
    artifacts_dir = tempfile.mkdtemp()
    original_artifacts_dir = os.getenv("ARTIFACTS_DIR")
    os.environ["ARTIFACTS_DIR"] = artifacts_dir
    
    import importlib
    import services.persistence as persistence_module
    importlib.reload(persistence_module)
    
    yield artifacts_dir
    
    shutil.rmtree(artifacts_dir, ignore_errors=True)
    if original_artifacts_dir:
        os.environ["ARTIFACTS_DIR"] = original_artifacts_dir
    else:
        os.environ.pop("ARTIFACTS_DIR", None)
    
    importlib.reload(persistence_module)


def test_audit_metadata_uses_scope_fields_not_test_lifecycle(temp_db, temp_artifacts_dir):
    """Test that audit metadata uses scope_* fields, not test-level lifecycle fields."""
    db = next(get_db())
    try:
        run_id = "test-scope-lifecycle-1"
        
        # Create a run
        save_run(
            db=db,
            run_id=run_id,
            source_type="jira",
            status="generated",
            ticket_count=1
        )
        
        # Create analysis artifact with package containing scope lifecycle
        package_with_lifecycle = {
            "package_id": "test-pkg-1",
            "scope_status": "locked",
            "scope_status_transitions": [
                {
                    "previous_status": "draft",
                    "new_status": "reviewed",
                    "changed_by": "reviewer@example.com",
                    "changed_at": "2024-01-15T10:00:00Z"
                },
                {
                    "previous_status": "reviewed",
                    "new_status": "locked",
                    "changed_by": "approver@example.com",
                    "changed_at": "2024-01-15T11:00:00Z"
                }
            ],
            "requirements": []
        }
        
        analysis_data = {
            "package": package_with_lifecycle,
            "requirements": [],
            "metadata": {}
        }
        
        # Create audit metadata (initial, without scope lifecycle)
        audit_metadata = {
            "run_id": run_id,
            "generated_at": "2024-01-15T09:00:00Z",
            "scope_status": None,
            "scope_reviewed_by": None,
            "scope_reviewed_at": None,
            "scope_approved_by": None,
            "scope_approved_at": None,
            "scope_id": "test-scope-1"
        }
        
        # Save artifacts
        artifact_path, artifact_sha256 = write_json_artifact(run_id, "analysis", analysis_data)
        save_artifact(db, run_id, "analysis", artifact_path, artifact_sha256)
        
        audit_path, audit_sha256 = write_json_artifact(run_id, "audit_metadata", audit_metadata)
        save_artifact(db, run_id, "audit_metadata", audit_path, audit_sha256)
        
        db.commit()
    finally:
        db.close()
    
    # Fetch audit JSON via endpoint
    response = app.test_client().get(f"/api/v1/audit/{run_id}.json")
    
    assert response.status_code == 200
    data = response.get_json()
    
    # Verify scope_* fields are populated
    assert data["scope_status"] == "locked"
    assert data["scope_reviewed_by"] == "reviewer@example.com"
    assert data["scope_reviewed_at"] == "2024-01-15T10:00:00Z"
    assert data["scope_approved_by"] == "approver@example.com"
    assert data["scope_approved_at"] == "2024-01-15T11:00:00Z"
    assert data["scope_id"] == "test-scope-1"
    
    # Verify test-level lifecycle fields are NOT present (or None)
    assert "review_status" not in data or data.get("review_status") is None
    assert "reviewed_by" not in data or data.get("reviewed_by") is None
    assert "reviewed_at" not in data or data.get("reviewed_at") is None
    assert "approved_by" not in data or data.get("approved_by") is None
    assert "approved_at" not in data or data.get("approved_at") is None


def test_audit_metadata_handles_missing_package_gracefully(temp_db, temp_artifacts_dir):
    """Test that audit metadata handles missing package gracefully."""
    db = next(get_db())
    try:
        run_id = "test-missing-package-1"
        
        # Create a run
        save_run(
            db=db,
            run_id=run_id,
            source_type="jira",
            status="generated",
            ticket_count=1
        )
        
        # Create analysis artifact WITHOUT package
        analysis_data = {
            "requirements": [],
            "metadata": {}
        }
        
        # Create audit metadata
        audit_metadata = {
            "run_id": run_id,
            "generated_at": "2024-01-15T09:00:00Z",
            "scope_status": None,
            "scope_id": "test-scope-1"
        }
        
        # Save artifacts
        artifact_path, artifact_sha256 = write_json_artifact(run_id, "analysis", analysis_data)
        save_artifact(db, run_id, "analysis", artifact_path, artifact_sha256)
        
        audit_path, audit_sha256 = write_json_artifact(run_id, "audit_metadata", audit_metadata)
        save_artifact(db, run_id, "audit_metadata", audit_path, audit_sha256)
        
        db.commit()
    finally:
        db.close()
    
    # Fetch audit JSON via endpoint
    response = app.test_client().get(f"/api/v1/audit/{run_id}.json")
    
    assert response.status_code == 200
    data = response.get_json()
    
    # Verify scope_* fields are None (not populated)
    assert data.get("scope_status") is None
    assert data.get("scope_reviewed_by") is None
    assert data.get("scope_reviewed_at") is None
    assert data.get("scope_approved_by") is None
    assert data.get("scope_approved_at") is None
    assert data["scope_id"] == "test-scope-1"  # This comes from audit_metadata itself


def test_audit_metadata_initial_generation_uses_scope_fields():
    """Test that initial audit metadata generation uses scope_* fields structure."""
    from app import generate_audit_metadata
    
    scope = {"type": "ticket", "id": "TEST-123"}
    tickets = [{"ticket_id": "TEST-123"}]
    source_type = "jira"
    
    audit_metadata = generate_audit_metadata(scope, tickets, source_type)
    
    # Verify scope_* fields exist (initially None)
    assert "scope_status" in audit_metadata
    assert audit_metadata["scope_status"] is None
    assert "scope_reviewed_by" in audit_metadata
    assert audit_metadata["scope_reviewed_by"] is None
    assert "scope_reviewed_at" in audit_metadata
    assert audit_metadata["scope_reviewed_at"] is None
    assert "scope_approved_by" in audit_metadata
    assert audit_metadata["scope_approved_by"] is None
    assert "scope_approved_at" in audit_metadata
    assert audit_metadata["scope_approved_at"] is None
    assert "scope_id" in audit_metadata
    assert audit_metadata["scope_id"] == "TEST-123"
    
    # Verify test-level lifecycle fields are NOT present
    assert "review_status" not in audit_metadata
    assert "reviewed_by" not in audit_metadata
    assert "reviewed_at" not in audit_metadata
    assert "approved_by" not in audit_metadata
    assert "approved_at" not in audit_metadata
