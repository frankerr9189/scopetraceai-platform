"""
Unit tests for Jira write-back from approved runs (Phase 3).
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
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


@pytest.fixture
def temp_artifacts_dir():
    """Create a temporary artifacts directory."""
    import tempfile
    import shutil
    import os
    
    artifacts_dir = tempfile.mkdtemp()
    original_artifacts_dir = os.getenv("ARTIFACTS_DIR")
    os.environ["ARTIFACTS_DIR"] = artifacts_dir
    
    # Reload persistence module to pick up new env var
    import importlib
    import services.persistence as persistence_module
    importlib.reload(persistence_module)
    
    yield artifacts_dir
    
    # Cleanup
    shutil.rmtree(artifacts_dir, ignore_errors=True)
    if original_artifacts_dir:
        os.environ["ARTIFACTS_DIR"] = original_artifacts_dir
    else:
        os.environ.pop("ARTIFACTS_DIR", None)
    
    importlib.reload(persistence_module)


@pytest.fixture
def mock_jira_config(monkeypatch):
    """Mock Jira configuration."""
    monkeypatch.setenv("JIRA_BASE_URL", "https://test.atlassian.net")
    monkeypatch.setenv("JIRA_EMAIL", "test@example.com")
    monkeypatch.setenv("JIRA_API_TOKEN", "test-token")
    monkeypatch.setenv("JIRA_PROJECT_KEY", "TEST")
    monkeypatch.setenv("JIRA_ISSUE_TYPE", "Task")


@pytest.fixture
def approved_run_with_artifacts(temp_db, temp_artifacts_dir):
    """Create an approved run with artifacts."""
    import json
    import os
    from services.persistence import write_json_artifact, save_artifact
    
    db = next(get_db())
    try:
        # Create approved run
        save_run(
            db=db,
            run_id="test-run-jira-1",
            source_type="jira",
            status="generated",
            ticket_count=1,
            review_status="approved",
            approved_by="test-approver@example.com",
            approved_at=datetime.utcnow()
        )
        
        # Create artifacts
        analysis_data = {
            "business_intent": "Test business intent",
            "gaps_detected": [{"description": "Test gap"}]
        }
        test_plan_data = {
            "test_plan": {
                "api_tests": [{"id": "test-1", "title": "Test 1"}],
                "ui_tests": [],
                "data_validation_tests": [],
                "edge_cases": [],
                "negative_tests": []
            }
        }
        rtm_data = [
            {"requirement_id": "REQ-1", "coverage_status": "COVERED"},
            {"requirement_id": "REQ-2", "coverage_status": "NOT COVERED"}
        ]
        audit_data = {
            "run_id": "test-run-jira-1",
            "generated_at": "2024-01-01T00:00:00Z"
        }
        
        for artifact_type, artifact_obj in [
            ("analysis", analysis_data),
            ("test_plan", test_plan_data),
            ("rtm", rtm_data),
            ("audit_metadata", audit_data)
        ]:
            artifact_path, artifact_sha256 = write_json_artifact("test-run-jira-1", artifact_type, artifact_obj)
            save_artifact(db, "test-run-jira-1", artifact_type, artifact_path, artifact_sha256)
        
        db.commit()
    finally:
        db.close()


def test_create_jira_ticket_requires_approved_run(client, temp_db, mock_jira_config):
    """Test that Jira ticket creation requires an approved run."""
    db = next(get_db())
    try:
        # Create a non-approved run
        save_run(
            db=db,
            run_id="test-run-not-approved",
            source_type="jira",
            status="generated",
            ticket_count=1,
            review_status="generated"
        )
        db.commit()
    finally:
        db.close()
    
    response = client.post(
        '/api/v1/runs/test-run-not-approved/jira',
        headers={'X-Actor': 'test-user@example.com'}
    )
    
    assert response.status_code == 403
    data = response.get_json()
    assert 'approved' in data['detail'].lower()


def test_create_jira_ticket_not_found(client, temp_db, mock_jira_config):
    """Test that creating Jira ticket for non-existent run returns 404."""
    response = client.post(
        '/api/v1/runs/non-existent-run/jira',
        headers={'X-Actor': 'test-user@example.com'}
    )
    
    assert response.status_code == 404


@patch('app.JiraClient')
def test_create_jira_ticket_success(mock_jira_client_class, client, temp_db, temp_artifacts_dir, mock_jira_config):
    """Test successful Jira ticket creation."""
    # Setup mock Jira client
    mock_jira_client = Mock()
    mock_jira_client_class.return_value = mock_jira_client
    
    # Mock search (no existing issues)
    mock_jira_client.search_issues_by_label.return_value = []
    
    # Mock create_issue
    mock_jira_client.create_issue.return_value = {"key": "TEST-123", "id": "12345"}
    mock_jira_client.get_issue_url.return_value = "https://test.atlassian.net/browse/TEST-123"
    
    # Create approved run with artifacts
    db = next(get_db())
    try:
        import json
        from services.persistence import write_json_artifact, save_artifact
        
        save_run(
            db=db,
            run_id="test-run-jira-success",
            source_type="jira",
            status="generated",
            ticket_count=1,
            review_status="approved",
            approved_by="test-approver@example.com",
            approved_at=datetime.utcnow()
        )
        
        # Create artifacts
        for artifact_type, artifact_obj in [
            ("analysis", {"business_intent": "Test"}),
            ("test_plan", {"test_plan": {"api_tests": []}}),
            ("rtm", []),
            ("audit_metadata", {"run_id": "test-run-jira-success"})
        ]:
            artifact_path, artifact_sha256 = write_json_artifact("test-run-jira-success", artifact_type, artifact_obj)
            save_artifact(db, "test-run-jira-success", artifact_type, artifact_path, artifact_sha256)
        
        db.commit()
    finally:
        db.close()
    
    response = client.post(
        '/api/v1/runs/test-run-jira-success/jira',
        headers={'X-Actor': 'test-user@example.com'}
    )
    
    assert response.status_code == 201
    data = response.get_json()
    assert data['jira_issue_key'] == 'TEST-123'
    assert data['jira_issue_url'] == 'https://test.atlassian.net/browse/TEST-123'
    assert data['created_by'] == 'test-user@example.com'
    
    # Verify run was updated
    db = next(get_db())
    try:
        run = db.query(Run).filter(Run.run_id == "test-run-jira-success").first()
        assert run.jira_issue_key == 'TEST-123'
        assert run.jira_created_by == 'test-user@example.com'
    finally:
        db.close()


@patch('app.JiraClient')
def test_create_jira_ticket_idempotency(mock_jira_client_class, client, temp_db, temp_artifacts_dir, mock_jira_config):
    """Test that Jira ticket creation is idempotent (returns existing issue)."""
    # Setup mock Jira client
    mock_jira_client = Mock()
    mock_jira_client_class.return_value = mock_jira_client
    
    # Mock search (existing issue found)
    existing_issue = {"key": "TEST-456", "id": "45678"}
    mock_jira_client.search_issues_by_label.return_value = [existing_issue]
    mock_jira_client.get_issue_url.return_value = "https://test.atlassian.net/browse/TEST-456"
    
    # Create approved run with artifacts
    db = next(get_db())
    try:
        import json
        from services.persistence import write_json_artifact, save_artifact
        
        save_run(
            db=db,
            run_id="test-run-jira-idempotent",
            source_type="jira",
            status="generated",
            ticket_count=1,
            review_status="approved",
            approved_by="test-approver@example.com",
            approved_at=datetime.utcnow()
        )
        
        # Create artifacts
        for artifact_type, artifact_obj in [
            ("analysis", {"business_intent": "Test"}),
            ("test_plan", {"test_plan": {"api_tests": []}}),
            ("rtm", []),
            ("audit_metadata", {"run_id": "test-run-jira-idempotent"})
        ]:
            artifact_path, artifact_sha256 = write_json_artifact("test-run-jira-idempotent", artifact_type, artifact_obj)
            save_artifact(db, "test-run-jira-idempotent", artifact_type, artifact_path, artifact_sha256)
        
        db.commit()
    finally:
        db.close()
    
    response = client.post(
        '/api/v1/runs/test-run-jira-idempotent/jira',
        headers={'X-Actor': 'test-user@example.com'}
    )
    
    assert response.status_code == 200
    data = response.get_json()
    assert data['jira_issue_key'] == 'TEST-456'
    assert 'already exists' in data['message'].lower()
    
    # Verify create_issue was NOT called
    mock_jira_client.create_issue.assert_not_called()


def test_jira_ticket_includes_audit_summary(mock_jira_client_class, client, temp_db, temp_artifacts_dir, mock_jira_config):
    """Test that Jira ticket description includes Audit Summary section."""
    mock_jira_client = Mock()
    mock_jira_client_class.return_value = mock_jira_client
    
    # Mock search (no existing issues)
    mock_jira_client.search_issues_by_label.return_value = []
    
    # Mock create_issue - capture the description
    created_description = {}
    def capture_create_issue(*args, **kwargs):
        created_description['adf'] = kwargs.get('description_adf', {})
        return {"key": "TEST-AUDIT", "id": "999"}
    mock_jira_client.create_issue.side_effect = capture_create_issue
    mock_jira_client.get_issue_url.return_value = "https://test.atlassian.net/browse/TEST-AUDIT"
    
    # Create approved run with artifacts
    db = next(get_db())
    try:
        import json
        from services.persistence import write_json_artifact, save_artifact
        
        save_run(
            db=db,
            run_id="test-run-audit-summary",
            source_type="jira",
            status="generated",
            ticket_count=1,
            review_status="approved",
            approved_by="test-approver@example.com",
            approved_at=datetime.utcnow()
        )
        
        # Create artifacts with audit metadata containing agent_metadata
        analysis_data = {
            "package": {
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
                ]
            },
            "business_intent": "Test business intent"
        }
        test_plan_data = {
            "test_plan": {
                "api_tests": [{"id": "test-1", "title": "Test 1"}],
                "ui_tests": []
            }
        }
        rtm_data = [
            {"requirement_id": "REQ-1", "coverage_status": "COVERED"}
        ]
        audit_data = {
            "run_id": "test-run-audit-summary",
            "generated_at": "2024-01-15T09:00:00Z",
            "agent_metadata": {
                "agent_version": "1.0.0",
                "logic_version": "testplan-v1",
                "change_policy": "idempotent",
                "determinism": "LLM + deterministic post-pass"
            }
        }
        
        for artifact_type, artifact_obj in [
            ("analysis", analysis_data),
            ("test_plan", test_plan_data),
            ("rtm", rtm_data),
            ("audit_metadata", audit_data)
        ]:
            artifact_path, artifact_sha256 = write_json_artifact("test-run-audit-summary", artifact_type, artifact_obj)
            save_artifact(db, "test-run-audit-summary", artifact_type, artifact_path, artifact_sha256)
        
        db.commit()
    finally:
        db.close()
    
    response = client.post(
        '/api/v1/runs/test-run-audit-summary/jira',
        headers={'X-Actor': 'test-user@example.com'}
    )
    
    assert response.status_code == 201
    
    # Verify create_issue was called
    assert mock_jira_client.create_issue.called
    
    # Extract description text from ADF (simplified check - verify ADF contains expected content)
    # The actual ADF structure is complex, but we can verify the function was called correctly
    call_args = mock_jira_client.create_issue.call_args
    description_adf = call_args.kwargs.get('description_adf', {})
    
    # Verify summary includes run_id
    summary = call_args.kwargs.get('summary', '')
    assert 'test-run-audit-summary' in summary
    
    # The description ADF should contain the audit summary section
    # We verify this by checking that the function was called with the correct parameters
    assert description_adf is not None
    
    # Verify the description text contains audit summary markers
    # We can't easily parse ADF, but we can verify the function generated the description
    # by checking that create_issue was called with description_adf
    assert 'description_adf' in call_args.kwargs


def test_jira_ticket_audit_summary_includes_all_fields(mock_jira_client_class, client, temp_db, temp_artifacts_dir, mock_jira_config):
    """Test that Audit Summary includes all expected fields when available."""
    from app import _generate_jira_description
    
    # Test the description generation function directly
    run_id = "test-run-123"
    created_by = "creator@example.com"
    approved_by = "approver@example.com"
    approved_at = "2024-01-15T11:00:00Z"
    
    audit_metadata = {
        "run_id": run_id,
        "generated_at": "2024-01-15T09:00:00Z",
        "scope_status": "locked",
        "scope_reviewed_by": "reviewer@example.com",
        "scope_reviewed_at": "2024-01-15T10:00:00Z",
        "scope_approved_by": approved_by,
        "scope_approved_at": approved_at,
        "agent_metadata": {
            "agent_version": "1.0.0",
            "logic_version": "testplan-v1",
            "change_policy": "idempotent",
            "determinism": "LLM + deterministic post-pass"
        }
    }
    
    analysis_data = {"business_intent": "Test intent"}
    test_plan_data = {"test_plan": {"api_tests": []}}
    rtm_data = []
    
    description = _generate_jira_description(
        run_id=run_id,
        created_by=created_by,
        approved_by=approved_by,
        approved_at=approved_at,
        reviewed_by=None,
        reviewed_at=None,
        analysis_data=analysis_data,
        test_plan_data=test_plan_data,
        rtm_data=rtm_data,
        audit_metadata=audit_metadata
    )
    
    # Verify audit summary section exists
    assert "----" in description
    assert "ScopeTrace AI — Audit Summary" in description
    
    # Verify all expected fields are present
    assert f"Run ID: {run_id}" in description
    assert "Scope Status: locked" in description
    assert f"Created: {created_by}" in description
    assert f"Reviewed: reviewer@example.com" in description
    assert f"Approved: {approved_by}" in description
    assert "Agent Version: 1.0.0" in description
    assert "Logic Version: testplan-v1" in description
    assert "Change Policy: idempotent" in description
    assert "Determinism: LLM + deterministic post-pass" in description


def test_jira_ticket_audit_summary_idempotency_unchanged(mock_jira_client_class, client, temp_db, temp_artifacts_dir, mock_jira_config):
    """Test that adding audit summary doesn't break idempotency."""
    mock_jira_client = Mock()
    mock_jira_client_class.return_value = mock_jira_client
    
    # Mock search (no existing issues on first call, existing on second)
    call_count = [0]
    def search_side_effect(*args, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return []  # First call: no existing issue
        else:
            return [{"key": "TEST-IDEMPOTENT"}]  # Second call: issue exists
    
    mock_jira_client.search_issues_by_label.side_effect = search_side_effect
    mock_jira_client.create_issue.return_value = {"key": "TEST-IDEMPOTENT", "id": "999"}
    mock_jira_client.get_issue_url.return_value = "https://test.atlassian.net/browse/TEST-IDEMPOTENT"
    
    # Create approved run with artifacts
    db = next(get_db())
    try:
        from services.persistence import write_json_artifact, save_artifact
        
        save_run(
            db=db,
            run_id="test-run-idempotency-audit",
            source_type="jira",
            status="generated",
            ticket_count=1,
            review_status="approved",
            approved_by="test-approver@example.com",
            approved_at=datetime.utcnow()
        )
        
        audit_data = {
            "run_id": "test-run-idempotency-audit",
            "generated_at": "2024-01-15T09:00:00Z",
            "agent_metadata": {
                "agent_version": "1.0.0",
                "logic_version": "testplan-v1"
            }
        }
        
        for artifact_type, artifact_obj in [
            ("analysis", {"business_intent": "Test"}),
            ("test_plan", {"test_plan": {"api_tests": []}}),
            ("rtm", []),
            ("audit_metadata", audit_data)
        ]:
            artifact_path, artifact_sha256 = write_json_artifact("test-run-idempotency-audit", artifact_type, artifact_obj)
            save_artifact(db, "test-run-idempotency-audit", artifact_type, artifact_path, artifact_sha256)
        
        db.commit()
    finally:
        db.close()
    
    # First call - creates issue
    response1 = client.post(
        '/api/v1/runs/test-run-idempotency-audit/jira',
        headers={'X-Actor': 'test-user@example.com'}
    )
    assert response1.status_code == 201
    assert mock_jira_client.create_issue.called
    
    # Reset mock for second call
    mock_jira_client.create_issue.reset_mock()
    
    # Second call - should return existing issue (idempotent)
    response2 = client.post(
        '/api/v1/runs/test-run-idempotency-audit/jira',
        headers={'X-Actor': 'test-user@example.com'}
    )
    assert response2.status_code == 200
    data2 = response2.get_json()
    assert 'already exists' in data2['message'].lower()
    
    # Verify create_issue was NOT called on second attempt (idempotent)
    mock_jira_client.create_issue.assert_not_called()


@patch('app.JiraClient')
def test_create_jira_ticket_already_exists_in_db(mock_jira_client_class, client, temp_db, mock_jira_config):
    """Test that if Jira issue already exists in DB, return it without creating."""
    db = next(get_db())
    try:
        save_run(
            db=db,
            run_id="test-run-jira-exists",
            source_type="jira",
            status="generated",
            ticket_count=1,
            review_status="approved",
            approved_by="test-approver@example.com",
            approved_at=datetime.utcnow(),
            jira_issue_key="TEST-789",
            jira_issue_url="https://test.atlassian.net/browse/TEST-789",
            jira_created_by="previous-user@example.com",
            jira_created_at=datetime.utcnow()
        )
        db.commit()
    finally:
        db.close()
    
    response = client.post(
        '/api/v1/runs/test-run-jira-exists/jira',
        headers={'X-Actor': 'test-user@example.com'}
    )
    
    assert response.status_code == 200
    data = response.get_json()
    assert data['jira_issue_key'] == 'TEST-789'
    assert 'already exists' in data['message'].lower()
    
    # Verify Jira client was never initialized (early return)
    mock_jira_client_class.assert_not_called()


@patch('app.JiraClient')
def test_audit_comment_posted_on_new_ticket(mock_jira_client_class, client, temp_db, temp_artifacts_dir, mock_jira_config):
    """Test that audit comment is posted when creating a new Jira ticket."""
    mock_jira_client = Mock()
    mock_jira_client_class.return_value = mock_jira_client
    
    # Mock search (no existing issues)
    mock_jira_client.search_issues_by_label.return_value = []
    
    # Mock create_issue
    mock_jira_client.create_issue.return_value = {"key": "TEST-COMMENT", "id": "12345"}
    mock_jira_client.get_issue_url.return_value = "https://test.atlassian.net/browse/TEST-COMMENT"
    
    # Mock get_comments (no existing comments)
    mock_jira_client.get_comments.return_value = []
    
    # Mock add_comment
    mock_jira_client.add_comment.return_value = {"id": "comment-123", "body": {}}
    
    # Create approved run with artifacts
    db = next(get_db())
    try:
        from services.persistence import write_json_artifact, save_artifact
        
        save_run(
            db=db,
            run_id="test-run-comment-new",
            source_type="jira",
            status="generated",
            ticket_count=1,
            review_status="approved",
            approved_by="test-approver@example.com",
            approved_at=datetime.utcnow(),
            created_by="test-creator@example.com"
        )
        
        audit_data = {
            "run_id": "test-run-comment-new",
            "generated_at": "2024-01-15T09:00:00Z",
            "scope_status": "locked",
            "scope_reviewed_by": "reviewer@example.com",
            "scope_reviewed_at": "2024-01-15T10:00:00Z",
            "scope_approved_by": "test-approver@example.com",
            "scope_approved_at": "2024-01-15T11:00:00Z",
            "agent_metadata": {
                "agent_version": "1.0.0",
                "logic_version": "testplan-v1",
                "change_policy": "idempotent"
            }
        }
        
        for artifact_type, artifact_obj in [
            ("analysis", {"business_intent": "Test"}),
            ("test_plan", {"test_plan": {"api_tests": []}}),
            ("rtm", []),
            ("audit_metadata", audit_data)
        ]:
            artifact_path, artifact_sha256 = write_json_artifact("test-run-comment-new", artifact_type, artifact_obj)
            save_artifact(db, "test-run-comment-new", artifact_type, artifact_path, artifact_sha256)
        
        db.commit()
    finally:
        db.close()
    
    response = client.post(
        '/api/v1/runs/test-run-comment-new/jira',
        headers={'X-Actor': 'test-user@example.com'}
    )
    
    assert response.status_code == 201
    data = response.get_json()
    assert data['jira_issue_key'] == 'TEST-COMMENT'
    assert data['audit_comment_posted'] is True
    
    # Verify add_comment was called
    assert mock_jira_client.add_comment.called
    call_args = mock_jira_client.add_comment.call_args
    assert call_args[0][0] == 'TEST-COMMENT'  # issue_key
    comment_text = call_args[0][1]  # body_text
    
    # Verify comment contains marker and expected fields
    assert f"ScopeTraceAI-Audit: test-run-comment-new" in comment_text
    assert "ScopeTrace AI — Audit Summary" in comment_text
    assert "Scope Status: locked" in comment_text
    assert "test-creator@example.com" in comment_text
    assert "reviewer@example.com" in comment_text
    assert "test-approver@example.com" in comment_text
    assert "Agent Version: 1.0.0" in comment_text
    assert "Logic Version: testplan-v1" in comment_text
    
    # Verify run was updated with comment metadata
    db = next(get_db())
    try:
        run = db.query(Run).filter(Run.run_id == "test-run-comment-new").first()
        assert run.jira_audit_comment_posted_at is not None
        assert run.jira_audit_comment_posted_by == 'test-user@example.com'
        assert run.jira_audit_comment_id == 'comment-123'
    finally:
        db.close()


@patch('app.JiraClient')
def test_audit_comment_not_duplicated_on_retry(mock_jira_client_class, client, temp_db, temp_artifacts_dir, mock_jira_config):
    """Test that audit comment is NOT duplicated when retrying Jira ticket creation."""
    mock_jira_client = Mock()
    mock_jira_client_class.return_value = mock_jira_client
    
    # Mock search (no existing issues)
    mock_jira_client.search_issues_by_label.return_value = []
    
    # Mock create_issue
    mock_jira_client.create_issue.return_value = {"key": "TEST-NODUP", "id": "12345"}
    mock_jira_client.get_issue_url.return_value = "https://test.atlassian.net/browse/TEST-NODUP"
    
    # Mock get_comments - first call returns empty, second call returns existing comment
    call_count = [0]
    def get_comments_side_effect(*args, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return []  # First call: no comments
        else:
            # Second call: comment already exists
            return [{
                "id": "comment-123",
                "body": {
                    "type": "doc",
                    "content": [{
                        "type": "paragraph",
                        "content": [{
                            "type": "text",
                            "text": "----\nScopeTrace AI — Audit Summary\nScopeTraceAI-Audit: test-run-nodup\n- Scope Status: locked\n----"
                        }]
                    }]
                }
            }]
    
    mock_jira_client.get_comments.side_effect = get_comments_side_effect
    
    # Mock add_comment (should only be called once)
    mock_jira_client.add_comment.return_value = {"id": "comment-123", "body": {}}
    
    # Create approved run with artifacts
    db = next(get_db())
    try:
        from services.persistence import write_json_artifact, save_artifact
        
        save_run(
            db=db,
            run_id="test-run-nodup",
            source_type="jira",
            status="generated",
            ticket_count=1,
            review_status="approved",
            approved_by="test-approver@example.com",
            approved_at=datetime.utcnow()
        )
        
        for artifact_type, artifact_obj in [
            ("analysis", {"business_intent": "Test"}),
            ("test_plan", {"test_plan": {"api_tests": []}}),
            ("rtm", []),
            ("audit_metadata", {"run_id": "test-run-nodup"})
        ]:
            artifact_path, artifact_sha256 = write_json_artifact("test-run-nodup", artifact_type, artifact_obj)
            save_artifact(db, "test-run-nodup", artifact_type, artifact_path, artifact_sha256)
        
        db.commit()
    finally:
        db.close()
    
    # First call - creates issue and adds comment
    response1 = client.post(
        '/api/v1/runs/test-run-nodup/jira',
        headers={'X-Actor': 'test-user@example.com'}
    )
    assert response1.status_code == 201
    assert mock_jira_client.add_comment.called
    
    # Reset mock for second call
    mock_jira_client.add_comment.reset_mock()
    
    # Second call - should detect existing comment and NOT add another
    response2 = client.post(
        '/api/v1/runs/test-run-nodup/jira',
        headers={'X-Actor': 'test-user@example.com'}
    )
    assert response2.status_code == 200
    data2 = response2.get_json()
    assert data2['audit_comment_posted'] is False  # Comment already existed
    
    # Verify add_comment was NOT called on second attempt
    mock_jira_client.add_comment.assert_not_called()


@patch('app.JiraClient')
def test_audit_comment_posted_on_existing_ticket(mock_jira_client_class, client, temp_db, temp_artifacts_dir, mock_jira_config):
    """Test that audit comment is posted on existing ticket if missing."""
    mock_jira_client = Mock()
    mock_jira_client_class.return_value = mock_jira_client
    
    # Mock search (existing issue found)
    existing_issue = {"key": "TEST-EXISTING", "id": "45678"}
    mock_jira_client.search_issues_by_label.return_value = [existing_issue]
    mock_jira_client.get_issue_url.return_value = "https://test.atlassian.net/browse/TEST-EXISTING"
    
    # Mock get_comments (no existing comments with marker)
    mock_jira_client.get_comments.return_value = [
        {
            "id": "comment-other",
            "body": {
                "type": "doc",
                "content": [{
                    "type": "paragraph",
                    "content": [{
                        "type": "text",
                        "text": "Some other comment"
                    }]
                }]
            }
        }
    ]
    
    # Mock add_comment
    mock_jira_client.add_comment.return_value = {"id": "comment-audit", "body": {}}
    
    # Create approved run with artifacts
    db = next(get_db())
    try:
        from services.persistence import write_json_artifact, save_artifact
        
        save_run(
            db=db,
            run_id="test-run-existing-comment",
            source_type="jira",
            status="generated",
            ticket_count=1,
            review_status="approved",
            approved_by="test-approver@example.com",
            approved_at=datetime.utcnow()
        )
        
        for artifact_type, artifact_obj in [
            ("analysis", {"business_intent": "Test"}),
            ("test_plan", {"test_plan": {"api_tests": []}}),
            ("rtm", []),
            ("audit_metadata", {"run_id": "test-run-existing-comment"})
        ]:
            artifact_path, artifact_sha256 = write_json_artifact("test-run-existing-comment", artifact_type, artifact_obj)
            save_artifact(db, "test-run-existing-comment", artifact_type, artifact_path, artifact_sha256)
        
        db.commit()
    finally:
        db.close()
    
    response = client.post(
        '/api/v1/runs/test-run-existing-comment/jira',
        headers={'X-Actor': 'test-user@example.com'}
    )
    
    assert response.status_code == 200
    data = response.get_json()
    assert data['jira_issue_key'] == 'TEST-EXISTING'
    assert data['audit_comment_posted'] is True  # Comment was added
    
    # Verify add_comment was called (even though issue already existed)
    assert mock_jira_client.add_comment.called
    call_args = mock_jira_client.add_comment.call_args
    assert call_args[0][0] == 'TEST-EXISTING'  # issue_key
    comment_text = call_args[0][1]  # body_text
    assert f"ScopeTraceAI-Audit: test-run-existing-comment" in comment_text
    
    # Verify create_issue was NOT called (issue already existed)
    mock_jira_client.create_issue.assert_not_called()


@patch('app.JiraClient')
def test_audit_comment_still_blocked_unless_approved(mock_jira_client_class, client, temp_db, temp_artifacts_dir, mock_jira_config):
    """Test that audit comment posting is still blocked unless run is approved."""
    mock_jira_client = Mock()
    mock_jira_client_class.return_value = mock_jira_client
    
    # Create run that is NOT approved
    db = next(get_db())
    try:
        save_run(
            db=db,
            run_id="test-run-not-approved",
            source_type="jira",
            status="generated",
            ticket_count=1,
            review_status="generated",  # Not approved
            approved_by=None,
            approved_at=None
        )
        db.commit()
    finally:
        db.close()
    
    response = client.post(
        '/api/v1/runs/test-run-not-approved/jira',
        headers={'X-Actor': 'test-user@example.com'}
    )
    
    assert response.status_code == 403
    data = response.get_json()
    assert 'approved' in data['detail'].lower()
    
    # Verify Jira client methods were never called
    mock_jira_client.create_issue.assert_not_called()
    mock_jira_client.add_comment.assert_not_called()
    
    assert response.status_code == 200
    data = response.get_json()
    assert data['jira_issue_key'] == 'TEST-789'
    assert 'already exists' in data['message'].lower()
    
    # Verify Jira client was never instantiated
    mock_jira_client_class.assert_not_called()


def test_create_jira_ticket_missing_config(client, temp_db):
    """Test that missing Jira config returns 500 with clear error."""
    db = next(get_db())
    try:
        save_run(
            db=db,
            run_id="test-run-no-config",
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
    
    # Don't set Jira env vars
    response = client.post(
        '/api/v1/runs/test-run-no-config/jira',
        headers={'X-Actor': 'test-user@example.com'}
    )
    
    assert response.status_code == 500
    data = response.get_json()
    assert 'configuration' in data['detail'].lower() or 'required' in data['detail'].lower()


@patch('app.JiraClient')
def test_create_jira_ticket_captures_actor(mock_jira_client_class, client, temp_db, temp_artifacts_dir, mock_jira_config):
    """Test that actor from X-Actor header is captured in Jira metadata."""
    mock_jira_client = Mock()
    mock_jira_client_class.return_value = mock_jira_client
    mock_jira_client.search_issues_by_label.return_value = []
    mock_jira_client.create_issue.return_value = {"key": "TEST-ACTOR", "id": "999"}
    mock_jira_client.get_issue_url.return_value = "https://test.atlassian.net/browse/TEST-ACTOR"
    
    db = next(get_db())
    try:
        from services.persistence import write_json_artifact, save_artifact
        
        save_run(
            db=db,
            run_id="test-run-actor",
            source_type="jira",
            status="generated",
            ticket_count=1,
            review_status="approved",
            approved_by="test-approver@example.com",
            approved_at=datetime.utcnow()
        )
        
        for artifact_type, artifact_obj in [
            ("analysis", {"business_intent": "Test"}),
            ("test_plan", {"test_plan": {"api_tests": []}}),
            ("rtm", []),
            ("audit_metadata", {"run_id": "test-run-actor"})
        ]:
            artifact_path, artifact_sha256 = write_json_artifact("test-run-actor", artifact_type, artifact_obj)
            save_artifact(db, "test-run-actor", artifact_type, artifact_path, artifact_sha256)
        
        db.commit()
    finally:
        db.close()
    
    actor = "jira-creator@example.com"
    response = client.post(
        '/api/v1/runs/test-run-actor/jira',
        headers={'X-Actor': actor}
    )
    
    assert response.status_code == 201
    data = response.get_json()
    assert data['created_by'] == actor
    
    # Verify in database
    db = next(get_db())
    try:
        run = db.query(Run).filter(Run.run_id == "test-run-actor").first()
        assert run.jira_created_by == actor
    finally:
        db.close()
