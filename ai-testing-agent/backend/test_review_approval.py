"""
Unit tests for review and approval lifecycle (Phase 2A).
"""
import pytest
from datetime import datetime
from app import app
from db import get_db
from models import Run
from services.persistence import save_run


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
    
    # Create temporary database
    db_fd, db_path = tempfile.mkstemp(suffix='.db')
    test_db_url = f"sqlite:///{db_path}"
    test_engine = create_engine(test_db_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=test_engine)
    
    # Patch get_db to use test database
    original_get_db = app.get_db if hasattr(app, 'get_db') else None
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
    
    # Cleanup
    if original_get_db:
        app.get_db = original_get_db
    else:
        delattr(app, 'get_db')
    
    os.close(db_fd)
    os.unlink(db_path)


def test_mark_run_reviewed_valid_transition(client, temp_db):
    """Test that a generated run can be marked as reviewed."""
    db = next(get_db())
    try:
        # Create a test run with status "generated"
        save_run(
            db=db,
            run_id="test-run-review-1",
            source_type="jira",
            status="generated",
            ticket_count=1,
            review_status="generated"
        )
        db.commit()
    finally:
        db.close()
    
    # Mark as reviewed
    response = client.post(
        '/api/v1/runs/test-run-review-1/review',
        headers={'X-Actor': 'test-reviewer@example.com'}
    )
    
    assert response.status_code == 200
    data = response.get_json()
    assert data['review_status'] == 'reviewed'
    assert data['reviewed_by'] == 'test-reviewer@example.com'
    assert data['reviewed_at'] is not None
    
    # Verify in database
    db = next(get_db())
    try:
        run = db.query(Run).filter(Run.run_id == "test-run-review-1").first()
        assert run.review_status == 'reviewed'
        assert run.reviewed_by == 'test-reviewer@example.com'
        assert run.reviewed_at is not None
    finally:
        db.close()


def test_approve_run_valid_transition(client, temp_db):
    """Test that a reviewed run can be approved."""
    db = next(get_db())
    try:
        # Create a test run with status "reviewed"
        save_run(
            db=db,
            run_id="test-run-approve-1",
            source_type="jira",
            status="generated",
            ticket_count=1,
            review_status="reviewed",
            reviewed_by="test-reviewer@example.com",
            reviewed_at=datetime.utcnow()
        )
        db.commit()
    finally:
        db.close()
    
    # Approve
    response = client.post(
        '/api/v1/runs/test-run-approve-1/approve',
        headers={'X-Actor': 'test-approver@example.com'}
    )
    
    assert response.status_code == 200
    data = response.get_json()
    assert data['review_status'] == 'approved'
    assert data['approved_by'] == 'test-approver@example.com'
    assert data['approved_at'] is not None
    
    # Verify in database
    db = next(get_db())
    try:
        run = db.query(Run).filter(Run.run_id == "test-run-approve-1").first()
        assert run.review_status == 'approved'
        assert run.approved_by == 'test-approver@example.com'
        assert run.approved_at is not None
    finally:
        db.close()


def test_mark_reviewed_invalid_transition_from_reviewed(client, temp_db):
    """Test that a reviewed run cannot be marked as reviewed again."""
    db = next(get_db())
    try:
        save_run(
            db=db,
            run_id="test-run-invalid-1",
            source_type="jira",
            status="generated",
            ticket_count=1,
            review_status="reviewed",
            reviewed_by="test-reviewer@example.com",
            reviewed_at=datetime.utcnow()
        )
        db.commit()
    finally:
        db.close()
    
    # Try to mark as reviewed again
    response = client.post(
        '/api/v1/runs/test-run-invalid-1/review',
        headers={'X-Actor': 'test-reviewer2@example.com'}
    )
    
    assert response.status_code == 400
    data = response.get_json()
    assert 'Invalid transition' in data['detail']


def test_approve_invalid_transition_from_generated(client, temp_db):
    """Test that a generated run cannot be approved (must be reviewed first)."""
    db = next(get_db())
    try:
        save_run(
            db=db,
            run_id="test-run-invalid-2",
            source_type="jira",
            status="generated",
            ticket_count=1,
            review_status="generated"
        )
        db.commit()
    finally:
        db.close()
    
    # Try to approve directly
    response = client.post(
        '/api/v1/runs/test-run-invalid-2/approve',
        headers={'X-Actor': 'test-approver@example.com'}
    )
    
    assert response.status_code == 400
    data = response.get_json()
    assert 'Invalid transition' in data['detail']


def test_approved_run_immutability_check(client, temp_db):
    """Test that approved runs are checked for immutability."""
    db = next(get_db())
    try:
        save_run(
            db=db,
            run_id="test-run-approved-1",
            source_type="jira",
            status="generated",
            ticket_count=1,
            review_status="approved",
            approved_by="test-approver@example.com",
            approved_at=datetime.utcnow()
        )
        db.commit()
    finally:
        db.close()
    
    # Try to mark as reviewed (should fail due to immutability)
    response = client.post(
        '/api/v1/runs/test-run-approved-1/review',
        headers={'X-Actor': 'test-reviewer@example.com'}
    )
    
    assert response.status_code == 403
    data = response.get_json()
    assert 'immutable' in data['detail'].lower()


def test_list_runs_includes_review_status(client, temp_db):
    """Test that list_runs endpoint includes review_status fields."""
    db = next(get_db())
    try:
        save_run(
            db=db,
            run_id="test-run-list-1",
            source_type="jira",
            status="generated",
            ticket_count=1,
            review_status="reviewed",
            reviewed_by="test-reviewer@example.com",
            reviewed_at=datetime.utcnow()
        )
        db.commit()
    finally:
        db.close()
    
    response = client.get('/api/v1/runs')
    assert response.status_code == 200
    data = response.get_json()
    assert isinstance(data, list)
    
    test_run = next((r for r in data if r['run_id'] == 'test-run-list-1'), None)
    assert test_run is not None
    assert 'review_status' in test_run
    assert test_run['review_status'] == 'reviewed'
    assert 'reviewed_by' in test_run
    assert 'reviewed_at' in test_run


def test_audit_metadata_enriched_with_review_info(client, temp_db, temp_artifacts_dir):
    """Test that audit metadata is enriched with review/approval info."""
    import json
    import os
    from services.persistence import write_json_artifact, save_artifact
    
    # Create run and artifact
    db = next(get_db())
    try:
        save_run(
            db=db,
            run_id="test-run-audit-1",
            source_type="jira",
            status="generated",
            ticket_count=1,
            review_status="reviewed",
            reviewed_by="test-reviewer@example.com",
            reviewed_at=datetime.utcnow()
        )
        
        # Create audit metadata artifact
        audit_data = {
            "run_id": "test-run-audit-1",
            "generated_at": "2024-01-01T00:00:00Z",
            "agent_version": "1.0.0"
        }
        artifact_path, artifact_sha256 = write_json_artifact("test-run-audit-1", "audit_metadata", audit_data)
        save_artifact(db, "test-run-audit-1", "audit_metadata", artifact_path, artifact_sha256)
        
        db.commit()
    finally:
        db.close()
    
    # Fetch audit metadata
    response = client.get('/api/v1/audit/test-run-audit-1.json')
    assert response.status_code == 200
    data = response.get_json()
    
    # Should be enriched with review info
    assert data['review_status'] == 'reviewed'
    assert data['reviewed_by'] == 'test-reviewer@example.com'
    assert data['reviewed_at'] is not None
    # Original fields should still be present
    assert data['run_id'] == 'test-run-audit-1'
    assert data['agent_version'] == '1.0.0'
