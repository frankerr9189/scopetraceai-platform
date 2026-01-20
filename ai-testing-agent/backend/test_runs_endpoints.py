"""
Unit tests for runs listing and artifact fetching endpoints.
"""
import pytest
import os
import tempfile
import shutil
import json
import uuid
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db import Base, get_db
from models import Run, Artifact, Tenant, TenantUser
from services.persistence import write_json_artifact, save_run, save_artifact
from app import app
from auth.jwt import create_access_token


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
def client(temp_db, temp_artifacts_dir, monkeypatch):
    """Create Flask test client with test database."""
    # Set JWT_SECRET for tests
    monkeypatch.setenv('JWT_SECRET', 'test-secret-key-for-runs-tests')
    
    # Reload auth module to pick up JWT_SECRET
    import importlib
    import auth.jwt as jwt_module
    importlib.reload(jwt_module)
    
    # Ensure get_db is patched before creating client
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def test_tenant_and_user(temp_db):
    """Create a test tenant and user for authentication."""
    tenant = Tenant(
        id=uuid.uuid4(),
        name="Test Tenant",
        slug="test-tenant",
        is_active=True,
        subscription_status="trial"
    )
    temp_db.add(tenant)
    temp_db.commit()
    temp_db.refresh(tenant)
    
    user = TenantUser(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        email="test@example.com",
        password_hash="dummy",
        role="owner",
        is_active=True
    )
    temp_db.add(user)
    temp_db.commit()
    temp_db.refresh(user)
    
    return {"tenant": tenant, "user": user}


@pytest.fixture
def auth_headers(test_tenant_and_user):
    """Create JWT auth headers for test requests."""
    tenant = test_tenant_and_user["tenant"]
    user = test_tenant_and_user["user"]
    token = create_access_token(str(user.id), str(tenant.id), user.role)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def sample_run_with_artifacts(temp_db, temp_artifacts_dir, test_tenant_and_user):
    """Create a sample run with artifacts for testing."""
    tenant = test_tenant_and_user["tenant"]
    run_id = "test-run-endpoints-001"
    
    # Create run with tenant_id
    save_run(
        db=temp_db,
        run_id=run_id,
        tenant_id=str(tenant.id),
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
            sha256=artifact_sha256,
            tenant_id=str(tenant.id)
        )
    
    # Ensure all commits happen
    temp_db.commit()
    
    return run_id


def test_list_runs_returns_runs(client, temp_db, sample_run_with_artifacts, auth_headers):
    """Test that GET /api/v1/runs returns paginated runs."""
    response = client.get("/api/v1/runs", headers=auth_headers)
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    assert "items" in data
    assert "pagination" in data
    assert isinstance(data["items"], list)
    assert len(data["items"]) == 1
    
    run = data["items"][0]
    assert run["run_id"] == sample_run_with_artifacts
    assert run["source_type"] == "jira"
    assert run["status"] == "success"
    assert run["ticket_count"] == 2
    assert run["logic_version"] == "testplan-v1"
    assert run["model_name"] == "gpt-4o-mini"
    assert "created_at" in run
    assert run["created_at"].endswith("Z")  # ISO8601 with Z suffix
    
    # Check pagination metadata
    pagination = data["pagination"]
    assert pagination["total"] == 1
    assert pagination["page"] == 1
    assert pagination["limit"] == 10
    assert pagination["total_pages"] == 1
    assert pagination["has_prev"] is False
    assert pagination["has_next"] is False


def test_list_runs_ordered_by_created_at_desc(client, temp_db, temp_artifacts_dir, test_tenant_and_user, auth_headers):
    """Test that runs are ordered by created_at descending."""
    # Create multiple runs with slight time differences
    from datetime import datetime, timedelta
    
    tenant = test_tenant_and_user["tenant"]
    run_ids = []
    for i in range(3):
        run_id = f"test-run-order-{i}"
        run_ids.append(run_id)
        
        # Create run with different created_at times
        run = Run(
            run_id=run_id,
            tenant_id=tenant.id,
            created_at=datetime.utcnow() - timedelta(seconds=i),
            source_type="jira",
            status="success"
        )
        temp_db.add(run)
        temp_db.commit()
    
    response = client.get("/api/v1/runs", headers=auth_headers)
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    # Should be ordered by created_at desc (newest first)
    assert len(data["items"]) >= 3
    created_times = [r["created_at"] for r in data["items"] if r["run_id"] in run_ids]
    assert created_times == sorted(created_times, reverse=True)


def test_get_artifact_returns_test_plan(client, temp_db, sample_run_with_artifacts, auth_headers):
    """Test that GET /api/v1/runs/<run_id>/test_plan returns JSON."""
    response = client.get(f"/api/v1/runs/{sample_run_with_artifacts}/test_plan", headers=auth_headers)
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    assert "test_plan" in data
    assert "requirements" in data
    assert "audit_metadata" in data
    assert data["audit_metadata"]["run_id"] == sample_run_with_artifacts


def test_get_artifact_returns_rtm(client, temp_db, sample_run_with_artifacts, auth_headers):
    """Test that GET /api/v1/runs/<run_id>/rtm returns JSON."""
    response = client.get(f"/api/v1/runs/{sample_run_with_artifacts}/rtm", headers=auth_headers)
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["requirement_id"] == "REQ-001"


def test_get_artifact_returns_analysis(client, temp_db, sample_run_with_artifacts, auth_headers):
    """Test that GET /api/v1/runs/<run_id>/analysis returns JSON."""
    response = client.get(f"/api/v1/runs/{sample_run_with_artifacts}/analysis", headers=auth_headers)
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    assert "requirements" in data
    assert "metadata" in data
    assert len(data["requirements"]) == 1


def test_get_artifact_returns_audit_metadata(client, temp_db, sample_run_with_artifacts, auth_headers):
    """Test that GET /api/v1/runs/<run_id>/audit_metadata returns JSON."""
    response = client.get(f"/api/v1/runs/{sample_run_with_artifacts}/audit_metadata", headers=auth_headers)
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    assert "run_id" in data
    assert data["run_id"] == sample_run_with_artifacts


def test_get_artifact_404_when_run_missing(client, auth_headers):
    """Test that GET /api/v1/runs/<run_id>/test_plan returns 404 for missing run."""
    response = client.get("/api/v1/runs/nonexistent-run-id/test_plan", headers=auth_headers)
    
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "detail" in data
    assert "not found" in data["detail"].lower()


def test_get_artifact_404_when_artifact_missing(client, temp_db, temp_artifacts_dir, test_tenant_and_user, auth_headers):
    """Test that GET /api/v1/runs/<run_id>/test_plan returns 404 for missing artifact."""
    # Create a run but no artifacts
    tenant = test_tenant_and_user["tenant"]
    run_id = "test-run-no-artifacts"
    save_run(
        db=temp_db,
        run_id=run_id,
        tenant_id=str(tenant.id),
        source_type="jira",
        status="success"
    )
    
    response = client.get(f"/api/v1/runs/{run_id}/test_plan", headers=auth_headers)
    
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "detail" in data
    assert "not found" in data["detail"].lower()


def test_get_artifact_404_when_file_missing(client, temp_db, temp_artifacts_dir, test_tenant_and_user, auth_headers):
    """Test that GET /api/v1/runs/<run_id>/test_plan returns 404 when file is missing."""
    tenant = test_tenant_and_user["tenant"]
    run_id = "test-run-missing-file"
    
    # Create run and artifact record, but delete the file
    save_run(
        db=temp_db,
        run_id=run_id,
        tenant_id=str(tenant.id),
        source_type="jira",
        status="success"
    )
    
    # Create artifact with non-existent path
    artifact = Artifact(
        tenant_id=tenant.id,
        run_id=run_id,
        artifact_type="test_plan",
        path="/nonexistent/path/test_plan.json",
        sha256="abc123"
    )
    temp_db.add(artifact)
    temp_db.commit()
    
    response = client.get(f"/api/v1/runs/{run_id}/test_plan", headers=auth_headers)
    
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "detail" in data
    assert "file not found" in data["detail"].lower() or "not found" in data["detail"].lower()


def test_get_artifact_invalid_artifact_type(client, auth_headers):
    """Test that GET /api/v1/runs/<run_id>/invalid returns 400."""
    response = client.get("/api/v1/runs/test-run/invalid", headers=auth_headers)
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "detail" in data
    assert "invalid" in data["detail"].lower() or "allowed" in data["detail"].lower()


def test_list_runs_empty_when_no_runs(client, auth_headers):
    """Test that GET /api/v1/runs returns empty items when no runs exist."""
    response = client.get("/api/v1/runs", headers=auth_headers)
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    assert "items" in data
    assert "pagination" in data
    assert isinstance(data["items"], list)
    assert len(data["items"]) == 0
    assert data["pagination"]["total"] == 0
    assert data["pagination"]["total_pages"] == 0


def test_list_runs_pagination_page_1(client, temp_db, temp_artifacts_dir, test_tenant_and_user, auth_headers):
    """Test pagination: page 1 returns <= 10 items."""
    from datetime import datetime
    
    tenant = test_tenant_and_user["tenant"]
    
    # Create 15 runs
    for i in range(15):
        run = Run(
            run_id=f"test-run-pag-{i}",
            tenant_id=tenant.id,
            created_at=datetime.utcnow(),
            source_type="jira",
            status="success"
        )
        temp_db.add(run)
    temp_db.commit()
    
    response = client.get("/api/v1/runs?page=1&limit=10", headers=auth_headers)
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    assert len(data["items"]) == 10
    assert data["pagination"]["page"] == 1
    assert data["pagination"]["limit"] == 10
    assert data["pagination"]["total"] == 15
    assert data["pagination"]["total_pages"] == 2
    assert data["pagination"]["has_prev"] is False
    assert data["pagination"]["has_next"] is True


def test_list_runs_pagination_page_2(client, temp_db, temp_artifacts_dir, test_tenant_and_user, auth_headers):
    """Test pagination: page 2 returns next items."""
    from datetime import datetime
    
    tenant = test_tenant_and_user["tenant"]
    
    # Create 15 runs
    for i in range(15):
        run = Run(
            run_id=f"test-run-pag-{i}",
            tenant_id=tenant.id,
            created_at=datetime.utcnow(),
            source_type="jira",
            status="success"
        )
        temp_db.add(run)
    temp_db.commit()
    
    response = client.get("/api/v1/runs?page=2&limit=10", headers=auth_headers)
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    assert len(data["items"]) == 5  # Remaining 5 items
    assert data["pagination"]["page"] == 2
    assert data["pagination"]["limit"] == 10
    assert data["pagination"]["total"] == 15
    assert data["pagination"]["total_pages"] == 2
    assert data["pagination"]["has_prev"] is True
    assert data["pagination"]["has_next"] is False


def test_list_runs_pagination_tenant_isolation(client, temp_db, temp_artifacts_dir, test_tenant_and_user):
    """Test that pagination preserves tenant isolation."""
    from datetime import datetime
    from models import Tenant, TenantUser
    
    tenant_a = test_tenant_and_user["tenant"]
    user_a = test_tenant_and_user["user"]
    
    # Create second tenant
    tenant_b = Tenant(
        id=uuid.uuid4(),
        name="Tenant B",
        slug="tenant-b",
        is_active=True,
        subscription_status="trial"
    )
    temp_db.add(tenant_b)
    temp_db.commit()
    
    # Create 5 runs for tenant A
    for i in range(5):
        run = Run(
            run_id=f"tenant-a-run-{i}",
            tenant_id=tenant_a.id,
            created_at=datetime.utcnow(),
            source_type="jira",
            status="success"
        )
        temp_db.add(run)
    
    # Create 3 runs for tenant B
    for i in range(3):
        run = Run(
            run_id=f"tenant-b-run-{i}",
            tenant_id=tenant_b.id,
            created_at=datetime.utcnow(),
            source_type="jira",
            status="success"
        )
        temp_db.add(run)
    temp_db.commit()
    
    # Create JWT token for tenant A
    token = create_access_token(str(user_a.id), str(tenant_a.id), user_a.role)
    auth_headers = {"Authorization": f"Bearer {token}"}
    
    response = client.get("/api/v1/runs?page=1&limit=10", headers=auth_headers)
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    # Should only return runs for tenant A
    assert "items" in data
    assert "pagination" in data
    assert len(data["items"]) == 5
    assert data["pagination"]["total"] == 5
    # Verify no tenant B runs
    tenant_b_run_ids = [r["run_id"] for r in data["items"] if r["run_id"].startswith("tenant-b")]
    assert len(tenant_b_run_ids) == 0


def test_list_runs_pagination_invalid_page_returns_empty(client, temp_db, test_tenant_and_user, auth_headers):
    """Test that page > total_pages returns empty items."""
    # No runs created, so total_pages = 0
    response = client.get("/api/v1/runs?page=999&limit=10", headers=auth_headers)
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    assert len(data["items"]) == 0
    assert data["pagination"]["total"] == 0
    assert data["pagination"]["total_pages"] == 0


def test_list_runs_pagination_limit_clamped(client, temp_db, temp_artifacts_dir, test_tenant_and_user, auth_headers):
    """Test that limit is clamped to max 50."""
    from datetime import datetime
    
    tenant = test_tenant_and_user["tenant"]
    
    # Create 100 runs
    for i in range(100):
        run = Run(
            run_id=f"test-run-limit-{i}",
            tenant_id=tenant.id,
            created_at=datetime.utcnow(),
            source_type="jira",
            status="success"
        )
        temp_db.add(run)
    temp_db.commit()
    
    # Request with limit > 50
    response = client.get("/api/v1/runs?page=1&limit=100", headers=auth_headers)
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    # Should be clamped to 50
    assert len(data["items"]) == 50
    assert data["pagination"]["limit"] == 50
