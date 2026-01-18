"""
Unit tests for persistence layer.
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
from services.persistence import (
    ensure_run_dir,
    compute_sha256_bytes,
    write_json_artifact,
    save_run,
    save_artifact,
    get_artifact_path
)


@pytest.fixture
def temp_db():
    """Create a temporary SQLite database for testing."""
    # Create in-memory database
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine)
    
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def temp_artifacts_dir():
    """Create a temporary artifacts directory for testing."""
    temp_dir = tempfile.mkdtemp()
    original_dir = os.getenv("ARTIFACTS_DIR")
    
    # Temporarily set ARTIFACTS_DIR
    os.environ["ARTIFACTS_DIR"] = temp_dir
    
    # Reload the module to pick up new env var
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


def test_compute_sha256_bytes():
    """Test SHA-256 computation."""
    data = b"test data"
    hash1 = compute_sha256_bytes(data)
    hash2 = compute_sha256_bytes(data)
    
    # Should be deterministic
    assert hash1 == hash2
    assert len(hash1) == 64  # SHA-256 hex is 64 chars
    assert isinstance(hash1, str)


def test_ensure_run_dir(temp_artifacts_dir):
    """Test run directory creation."""
    run_id = "test-run-123"
    run_dir = ensure_run_dir(run_id)
    
    assert os.path.exists(run_dir)
    assert run_dir.endswith(run_id)
    
    # Should be idempotent
    run_dir2 = ensure_run_dir(run_id)
    assert run_dir == run_dir2


def test_write_json_artifact_deterministic(temp_artifacts_dir):
    """Test that write_json_artifact creates deterministic files and hashes."""
    run_id = "test-run-456"
    artifact_type = "test_plan"
    
    # Test data
    test_obj = {
        "test_id": "TEST-001",
        "title": "Test Case",
        "steps": ["Step 1", "Step 2"],
        "expected_result": "Success"
    }
    
    # Write artifact twice
    path1, sha1 = write_json_artifact(run_id, artifact_type, test_obj)
    path2, sha2 = write_json_artifact(run_id, artifact_type, test_obj)
    
    # Paths should be the same
    assert path1 == path2
    
    # Hashes should be identical (deterministic)
    assert sha1 == sha2
    
    # File should exist
    assert os.path.exists(path1)
    
    # Verify file content is valid JSON
    with open(path1, 'r', encoding='utf-8') as f:
        loaded = json.load(f)
        assert loaded == test_obj
    
    # Verify file has sorted keys and indentation
    with open(path1, 'r', encoding='utf-8') as f:
        content = f.read()
        # Should have indentation (pretty print)
        assert "  " in content
        # Should be valid JSON
        assert json.loads(content) == test_obj


def test_write_json_artifact_sha256_matches_content(temp_artifacts_dir):
    """Test that SHA-256 hash matches the file content."""
    run_id = "test-run-789"
    artifact_type = "package"
    
    test_obj = {"key": "value", "number": 42}
    path, sha256 = write_json_artifact(run_id, artifact_type, test_obj)
    
    # Read file and compute hash manually
    with open(path, 'rb') as f:
        file_bytes = f.read()
    
    computed_hash = compute_sha256_bytes(file_bytes)
    
    # Hashes should match
    assert sha256 == computed_hash


def test_save_run(temp_db):
    """Test saving a run to database."""
    run_id = "test-run-001"
    
    run = save_run(
        db=temp_db,
        run_id=run_id,
        source_type="jira",
        status="success",
        ticket_count=3,
        scope_id="ATA-41",
        scope_type="ticket",
        logic_version="testplan-v1",
        model_name="gpt-4o-mini"
    )
    
    assert run.run_id == run_id
    assert run.source_type == "jira"
    assert run.status == "success"
    assert run.ticket_count == 3
    assert run.scope_id == "ATA-41"
    assert run.scope_type == "ticket"
    assert run.logic_version == "testplan-v1"
    assert run.model_name == "gpt-4o-mini"
    assert run.created_at is not None
    
    # Verify it's in the database
    saved_run = temp_db.query(Run).filter(Run.run_id == run_id).first()
    assert saved_run is not None
    assert saved_run.run_id == run_id


def test_save_run_update_existing(temp_db):
    """Test updating an existing run."""
    run_id = "test-run-002"
    
    # Create initial run
    run1 = save_run(
        db=temp_db,
        run_id=run_id,
        source_type="jira",
        status="success"
    )
    
    # Update run
    run2 = save_run(
        db=temp_db,
        run_id=run_id,
        source_type="freeform",
        status="error",
        ticket_count=5
    )
    
    assert run1.run_id == run2.run_id
    assert run2.source_type == "freeform"
    assert run2.status == "error"
    assert run2.ticket_count == 5
    
    # Should only be one run in database
    count = temp_db.query(Run).filter(Run.run_id == run_id).count()
    assert count == 1


def test_save_artifact(temp_db, temp_artifacts_dir):
    """Test saving artifact metadata."""
    run_id = "test-run-003"
    
    # First create a run
    save_run(
        db=temp_db,
        run_id=run_id,
        source_type="jira",
        status="success"
    )
    
    # Save artifact
    artifact_path = "/path/to/artifact.json"
    artifact_sha = "abc123def456"
    
    artifact = save_artifact(
        db=temp_db,
        run_id=run_id,
        artifact_type="test_plan",
        path=artifact_path,
        sha256=artifact_sha
    )
    
    assert artifact.run_id == run_id
    assert artifact.artifact_type == "test_plan"
    assert artifact.path == artifact_path
    assert artifact.sha256 == artifact_sha
    assert artifact.created_at is not None
    
    # Verify it's in the database
    saved_artifact = temp_db.query(Artifact).filter(
        Artifact.run_id == run_id,
        Artifact.artifact_type == "test_plan"
    ).first()
    assert saved_artifact is not None
    assert saved_artifact.path == artifact_path


def test_save_artifact_update_existing(temp_db, temp_artifacts_dir):
    """Test updating an existing artifact."""
    run_id = "test-run-004"
    
    # Create run
    save_run(
        db=temp_db,
        run_id=run_id,
        source_type="jira",
        status="success"
    )
    
    # Save initial artifact
    artifact1 = save_artifact(
        db=temp_db,
        run_id=run_id,
        artifact_type="rtm",
        path="/path/old.json",
        sha256="old_hash"
    )
    
    # Update artifact
    artifact2 = save_artifact(
        db=temp_db,
        run_id=run_id,
        artifact_type="rtm",
        path="/path/new.json",
        sha256="new_hash"
    )
    
    assert artifact1.id == artifact2.id  # Same record
    assert artifact2.path == "/path/new.json"
    assert artifact2.sha256 == "new_hash"
    
    # Should only be one artifact of this type for this run
    count = temp_db.query(Artifact).filter(
        Artifact.run_id == run_id,
        Artifact.artifact_type == "rtm"
    ).count()
    assert count == 1


def test_get_artifact_path(temp_db, temp_artifacts_dir):
    """Test retrieving artifact path."""
    run_id = "test-run-005"
    
    # Create run
    save_run(
        db=temp_db,
        run_id=run_id,
        source_type="jira",
        status="success"
    )
    
    # Save artifact
    expected_path = "/path/to/test_plan.json"
    save_artifact(
        db=temp_db,
        run_id=run_id,
        artifact_type="test_plan",
        path=expected_path,
        sha256="hash123"
    )
    
    # Retrieve path
    path = get_artifact_path(temp_db, run_id, "test_plan")
    assert path == expected_path
    
    # Non-existent artifact
    path_none = get_artifact_path(temp_db, run_id, "nonexistent")
    assert path_none is None


def test_save_run_and_artifact_roundtrip(temp_db, temp_artifacts_dir):
    """Test complete roundtrip: save run, save artifact, retrieve."""
    run_id = "test-run-006"
    
    # Save run
    run = save_run(
        db=temp_db,
        run_id=run_id,
        source_type="document",
        status="success",
        ticket_count=1,
        logic_version="testplan-v1+coverage-enforcer-v1"
    )
    
    # Write artifact
    test_data = {"test": "data", "number": 42}
    artifact_path, artifact_sha = write_json_artifact(
        run_id, "test_plan", test_data
    )
    
    # Save artifact metadata
    artifact = save_artifact(
        db=temp_db,
        run_id=run_id,
        artifact_type="test_plan",
        path=artifact_path,
        sha256=artifact_sha
    )
    
    # Verify relationships
    assert artifact.run_id == run.run_id
    assert run.artifacts[0].id == artifact.id
    
    # Retrieve artifact path
    retrieved_path = get_artifact_path(temp_db, run_id, "test_plan")
    assert retrieved_path == artifact_path
    
    # Verify file exists and content matches
    assert os.path.exists(retrieved_path)
    with open(retrieved_path, 'r', encoding='utf-8') as f:
        loaded_data = json.load(f)
        assert loaded_data == test_data
