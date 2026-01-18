"""
Tests for tenant isolation - ensuring no cross-tenant data leakage.
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
def temp_db(monkeypatch):
    """Create a temporary Postgres-compatible database for testing."""
    # Use SQLite for testing (UUIDs will be stored as strings)
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine)
    
    # Set JWT_SECRET for tests
    monkeypatch.setenv('JWT_SECRET', 'test-secret-key-for-tenant-isolation')
    
    # Reload auth module to pick up JWT_SECRET
    import importlib
    import auth.jwt as jwt_module
    importlib.reload(jwt_module)
    
    # Create a shared session for the test
    test_session = SessionLocal()
    
    def test_get_db():
        # Return the same session each time
        yield test_session
    
    # Monkey-patch get_db
    import db
    import app
    original_db_get_db = db.get_db
    original_app_get_db = getattr(app, 'get_db', None)
    
    db.get_db = test_get_db
    app.get_db = test_get_db
    
    try:
        yield test_session
    finally:
        test_session.rollback()
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
    
    os.environ["ARTIFACTS_DIR"] = temp_dir
    
    import importlib
    import services.persistence
    importlib.reload(services.persistence)
    
    yield temp_dir
    
    if original_dir:
        os.environ["ARTIFACTS_DIR"] = original_dir
    else:
        os.environ.pop("ARTIFACTS_DIR", None)
    
    shutil.rmtree(temp_dir, ignore_errors=True)
    importlib.reload(services.persistence)


@pytest.fixture
def tenant_a(temp_db):
    """Create tenant A for testing."""
    tenant_a = Tenant(
        name="Tenant A",
        slug="tenant-a",
        is_active=True
    )
    temp_db.add(tenant_a)
    temp_db.commit()
    temp_db.refresh(tenant_a)
    return tenant_a


@pytest.fixture
def tenant_b(temp_db):
    """Create tenant B for testing."""
    tenant_b = Tenant(
        name="Tenant B",
        slug="tenant-b",
        is_active=True
    )
    temp_db.add(tenant_b)
    temp_db.commit()
    temp_db.refresh(tenant_b)
    return tenant_b


@pytest.fixture
def user_a(temp_db, tenant_a):
    """Create user for tenant A."""
    user_a = TenantUser(
        tenant_id=tenant_a.id,
        email="user_a@tenant-a.com",
        password_hash="dummy_hash",
        role="owner",
        is_active=True
    )
    temp_db.add(user_a)
    temp_db.commit()
    temp_db.refresh(user_a)
    return user_a


@pytest.fixture
def user_b(temp_db, tenant_b):
    """Create user for tenant B."""
    user_b = TenantUser(
        tenant_id=tenant_b.id,
        email="user_b@tenant-b.com",
        password_hash="dummy_hash",
        role="owner",
        is_active=True
    )
    temp_db.add(user_b)
    temp_db.commit()
    temp_db.refresh(user_b)
    return user_b


@pytest.fixture
def run_tenant_a(temp_db, temp_artifacts_dir, tenant_a):
    """Create a run for tenant A."""
    run_id = "test-run-tenant-a-001"
    run = save_run(
        db=temp_db,
        run_id=run_id,
        source_type="jira",
        status="generated",
        ticket_count=1,
        tenant_id=str(tenant_a.id)
    )
    
    # Create artifact for this run
    artifact_data = {"test": "data for tenant A"}
    artifact_path, artifact_sha256 = write_json_artifact(run_id, "test_plan", artifact_data)
    save_artifact(
        db=temp_db,
        run_id=run_id,
        artifact_type="test_plan",
        path=artifact_path,
        sha256=artifact_sha256,
        tenant_id=str(tenant_a.id)
    )
    
    return run


@pytest.fixture
def run_tenant_b(temp_db, temp_artifacts_dir, tenant_b):
    """Create a run for tenant B."""
    run_id = "test-run-tenant-b-001"
    run = save_run(
        db=temp_db,
        run_id=run_id,
        source_type="jira",
        status="generated",
        ticket_count=1,
        tenant_id=str(tenant_b.id)
    )
    
    # Create artifact for this run
    artifact_data = {"test": "data for tenant B"}
    artifact_path, artifact_sha256 = write_json_artifact(run_id, "test_plan", artifact_data)
    save_artifact(
        db=temp_db,
        run_id=run_id,
        artifact_type="test_plan",
        path=artifact_path,
        sha256=artifact_sha256,
        tenant_id=str(tenant_b.id)
    )
    
    return run


def create_jwt_token(user_id: str, tenant_id: str, role: str = "owner") -> str:
    """Helper to create JWT token for testing."""
    return create_access_token(user_id, tenant_id, role)


@pytest.fixture
def client(temp_db, temp_artifacts_dir):
    """Create Flask test client."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_list_runs_tenant_isolation(client, temp_db, tenant_a, tenant_b, run_tenant_a, run_tenant_b, user_a):
    """Test that listing runs only returns runs for the authenticated tenant."""
    # Create JWT token for tenant A user
    token = create_jwt_token(
        str(user_a.id),
        str(tenant_a.id),
        user_a.role
    )
    
    # List runs as tenant A user
    response = client.get(
        '/api/v1/runs',
        headers={'Authorization': f'Bearer {token}'}
    )
    
    assert response.status_code == 200
    runs = response.get_json()
    
    # Should only see tenant A's run
    assert len(runs) == 1
    assert runs[0]['run_id'] == run_tenant_a.run_id
    
    # Should NOT see tenant B's run
    tenant_b_run_ids = [r['run_id'] for r in runs if r['run_id'] == run_tenant_b.run_id]
    assert len(tenant_b_run_ids) == 0


def test_get_run_tenant_isolation(client, temp_db, tenant_a, tenant_b, run_tenant_a, run_tenant_b, user_a, user_b):
    """Test that getting a run by ID returns 404 if run belongs to different tenant."""
    # Create JWT token for tenant A user
    token_a = create_jwt_token(
        str(user_a.id),
        str(tenant_a.id),
        user_a.role
    )
    
    # Try to access tenant B's run as tenant A user
    response = client.get(
        f'/api/v1/runs/{run_tenant_b.run_id}/test_plan',
        headers={'Authorization': f'Bearer {token_a}'}
    )
    
    # Should return 404 (not 401) - don't leak existence
    assert response.status_code == 404
    
    # Tenant A user should be able to access their own run
    response = client.get(
        f'/api/v1/runs/{run_tenant_a.run_id}/test_plan',
        headers={'Authorization': f'Bearer {token_a}'}
    )
    assert response.status_code == 200


def test_get_artifact_tenant_isolation(client, temp_db, tenant_a, tenant_b, run_tenant_a, run_tenant_b, user_a):
    """Test that getting an artifact returns 404 if artifact belongs to different tenant."""
    # Create JWT token for tenant A user
    token_a = create_jwt_token(
        str(user_a.id),
        str(tenant_a.id),
        user_a.role
    )
    
    # Try to access tenant B's artifact as tenant A user
    response = client.get(
        f'/api/v1/test-plan/{run_tenant_b.run_id}.json',
        headers={'Authorization': f'Bearer {token_a}'}
    )
    
    # Should return 404 (not 401) - don't leak existence
    assert response.status_code == 404
    
    # Tenant A user should be able to access their own artifact
    response = client.get(
        f'/api/v1/test-plan/{run_tenant_a.run_id}.json',
        headers={'Authorization': f'Bearer {token_a}'}
    )
    assert response.status_code == 200


def test_mark_reviewed_tenant_isolation(client, temp_db, tenant_a, tenant_b, run_tenant_a, run_tenant_b, user_a):
    """Test that marking a run as reviewed returns 404 if run belongs to different tenant."""
    # Create JWT token for tenant A user
    token_a = create_jwt_token(
        str(user_a.id),
        str(tenant_a.id),
        user_a.role
    )
    
    # Try to review tenant B's run as tenant A user
    response = client.post(
        f'/api/v1/runs/{run_tenant_b.run_id}/review',
        headers={'Authorization': f'Bearer {token_a}'}
    )
    
    # Should return 404 (not 401) - don't leak existence
    assert response.status_code == 404
    
    # Tenant A user should be able to review their own run
    response = client.post(
        f'/api/v1/runs/{run_tenant_a.run_id}/review',
        headers={'Authorization': f'Bearer {token_a}'}
    )
    assert response.status_code == 200


def test_approve_run_tenant_isolation(client, temp_db, tenant_a, tenant_b, run_tenant_a, run_tenant_b, user_a):
    """Test that approving a run returns 404 if run belongs to different tenant."""
    # First mark tenant A's run as reviewed
    token_a = create_jwt_token(
        str(user_a.id),
        str(tenant_a.id),
        user_a.role
    )
    
    # Review the run first
    response = client.post(
        f'/api/v1/runs/{run_tenant_a.run_id}/review',
        headers={'Authorization': f'Bearer {token_a}'}
    )
    assert response.status_code == 200
    
    # Try to approve tenant B's run as tenant A user
    response = client.post(
        f'/api/v1/runs/{run_tenant_b.run_id}/approve',
        headers={'Authorization': f'Bearer {token_a}'}
    )
    
    # Should return 404 (not 401) - don't leak existence
    assert response.status_code == 404
    
    # Tenant A user should be able to approve their own run
    response = client.post(
        f'/api/v1/runs/{run_tenant_a.run_id}/approve',
        headers={'Authorization': f'Bearer {token_a}'}
    )
    assert response.status_code == 200


def test_create_jira_ticket_tenant_isolation(client, temp_db, tenant_a, tenant_b, run_tenant_a, run_tenant_b, user_a, monkeypatch):
    """Test that creating Jira ticket returns 404 if run belongs to different tenant."""
    # Mock Jira config to avoid actual API calls
    monkeypatch.setenv('JIRA_BASE_URL', 'https://test.atlassian.net')
    monkeypatch.setenv('JIRA_EMAIL', 'test@example.com')
    monkeypatch.setenv('JIRA_API_TOKEN', 'test-token')
    monkeypatch.setenv('JIRA_PROJECT_KEY', 'TEST')
    
    # First approve tenant A's run
    token_a = create_jwt_token(
        str(user_a.id),
        str(tenant_a.id),
        user_a.role
    )
    
    # Review and approve
    client.post(
        f'/api/v1/runs/{run_tenant_a.run_id}/review',
        headers={'Authorization': f'Bearer {token_a}'}
    )
    client.post(
        f'/api/v1/runs/{run_tenant_a.run_id}/approve',
        headers={'Authorization': f'Bearer {token_a}'}
    )
    
    # Try to create Jira ticket for tenant B's run as tenant A user
    response = client.post(
        f'/api/v1/runs/{run_tenant_b.run_id}/jira',
        headers={'Authorization': f'Bearer {token_a}'}
    )
    
    # Should return 404 (not 401) - don't leak existence
    assert response.status_code == 404


def test_persistence_save_run_tenant_isolation(temp_db, tenant_a, tenant_b):
    """Test that save_run correctly sets tenant_id."""
    run_id = "test-persistence-001"
    
    run = save_run(
        db=temp_db,
        run_id=run_id,
        source_type="jira",
        status="generated",
        tenant_id=str(tenant_a.id)
    )
    
    assert run.tenant_id == tenant_a.id
    
    # Verify run can only be queried with correct tenant_id
    run_found = temp_db.query(Run).filter(
        Run.run_id == run_id,
        Run.tenant_id == tenant_a.id
    ).first()
    assert run_found is not None
    
    # Verify run is NOT found with wrong tenant_id
    run_not_found = temp_db.query(Run).filter(
        Run.run_id == run_id,
        Run.tenant_id == tenant_b.id
    ).first()
    assert run_not_found is None


def test_persistence_save_artifact_tenant_isolation(temp_db, temp_artifacts_dir, tenant_a, tenant_b):
    """Test that save_artifact correctly sets tenant_id."""
    run_id = "test-persistence-artifact-001"
    
    # Create run for tenant A
    run = save_run(
        db=temp_db,
        run_id=run_id,
        source_type="jira",
        status="generated",
        tenant_id=str(tenant_a.id)
    )
    
    # Create artifact
    artifact_data = {"test": "data"}
    artifact_path, artifact_sha256 = write_json_artifact(run_id, "test_plan", artifact_data)
    artifact = save_artifact(
        db=temp_db,
        run_id=run_id,
        artifact_type="test_plan",
        path=artifact_path,
        sha256=artifact_sha256,
        tenant_id=str(tenant_a.id)
    )
    
    assert artifact.tenant_id == tenant_a.id
    
    # Verify artifact can only be queried with correct tenant_id
    artifact_found = temp_db.query(Artifact).filter(
        Artifact.run_id == run_id,
        Artifact.artifact_type == "test_plan",
        Artifact.tenant_id == tenant_a.id
    ).first()
    assert artifact_found is not None
    
    # Verify artifact is NOT found with wrong tenant_id
    artifact_not_found = temp_db.query(Artifact).filter(
        Artifact.run_id == run_id,
        Artifact.artifact_type == "test_plan",
        Artifact.tenant_id == tenant_b.id
    ).first()
    assert artifact_not_found is None
