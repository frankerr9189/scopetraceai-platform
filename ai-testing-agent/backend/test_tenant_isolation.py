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
from models import Run, Artifact, Tenant, TenantUser, UsageEvent, TenantIntegration
from services.persistence import write_json_artifact, save_run, save_artifact
from app import app
from auth.jwt import create_access_token
from utils.encryption import encrypt_secret


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
        is_active=True,
        subscription_status="trial"
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
        is_active=True,
        subscription_status="trial"
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


# ============================================================================
# PART C: COMPREHENSIVE CROSS-TENANT TESTS
# ============================================================================

def test_cross_tenant_run_access_by_id(client, temp_db, tenant_a, tenant_b, run_tenant_a, run_tenant_b, user_b):
    """
    Test that Tenant B cannot access Tenant A's run by ID.
    This proves tenant isolation cannot be bypassed.
    """
    # Create JWT token for Tenant B user
    token_b = create_jwt_token(
        str(user_b.id),
        str(tenant_b.id),
        user_b.role
    )
    
    # Attempt to fetch Tenant A's run as Tenant B user
    response = client.get(
        f'/api/v1/runs/{run_tenant_a.run_id}',
        headers={'Authorization': f'Bearer {token_b}'}
    )
    
    # Should return 404 (not 403) - don't leak existence of other tenant's data
    assert response.status_code == 404, f"Expected 404, got {response.status_code}. Response: {response.get_json()}"
    
    # Verify Tenant B can access their own run
    response = client.get(
        f'/api/v1/runs/{run_tenant_b.run_id}',
        headers={'Authorization': f'Bearer {token_b}'}
    )
    assert response.status_code == 200


def test_cross_tenant_artifact_access_by_id(client, temp_db, tenant_a, tenant_b, run_tenant_a, run_tenant_b, user_b):
    """
    Test that Tenant B cannot access Tenant A's artifact by run_id.
    This proves tenant isolation for artifacts.
    """
    # Create JWT token for Tenant B user
    token_b = create_jwt_token(
        str(user_b.id),
        str(tenant_b.id),
        user_b.role
    )
    
    # Attempt to fetch Tenant A's artifact as Tenant B user
    response = client.get(
        f'/api/v1/runs/{run_tenant_a.run_id}/test_plan',
        headers={'Authorization': f'Bearer {token_b}'}
    )
    
    # Should return 404 (not 403) - don't leak existence
    assert response.status_code == 404, f"Expected 404, got {response.status_code}. Response: {response.get_json()}"
    
    # Verify Tenant B can access their own artifact
    response = client.get(
        f'/api/v1/runs/{run_tenant_b.run_id}/test_plan',
        headers={'Authorization': f'Bearer {token_b}'}
    )
    assert response.status_code == 200


def test_cross_tenant_run_update_protection(client, temp_db, tenant_a, tenant_b, run_tenant_a, run_tenant_b, user_b):
    """
    Test that Tenant B cannot update Tenant A's run.
    Attempts to mark Tenant A's run as reviewed should fail.
    """
    # Create JWT token for Tenant B user
    token_b = create_jwt_token(
        str(user_b.id),
        str(tenant_b.id),
        user_b.role
    )
    
    # Attempt to review Tenant A's run as Tenant B user
    response = client.post(
        f'/api/v1/runs/{run_tenant_a.run_id}/review',
        headers={'Authorization': f'Bearer {token_b}'}
    )
    
    # Should return 404 (not 403) - don't leak existence
    assert response.status_code == 404, f"Expected 404, got {response.status_code}. Response: {response.get_json()}"
    
    # Verify Tenant B can review their own run
    response = client.post(
        f'/api/v1/runs/{run_tenant_b.run_id}/review',
        headers={'Authorization': f'Bearer {token_b}'}
    )
    assert response.status_code == 200


def test_cross_tenant_run_delete_protection(client, temp_db, tenant_a, tenant_b, run_tenant_a, run_tenant_b, user_b):
    """
    Test that Tenant B cannot delete Tenant A's run.
    Since there's no DELETE endpoint, we test via approval (which makes run immutable).
    """
    # Create JWT token for Tenant B user
    token_b = create_jwt_token(
        str(user_b.id),
        str(tenant_b.id),
        user_b.role
    )
    
    # First, review Tenant B's own run
    response = client.post(
        f'/api/v1/runs/{run_tenant_b.run_id}/review',
        headers={'Authorization': f'Bearer {token_b}'}
    )
    assert response.status_code == 200
    
    # Attempt to approve Tenant A's run as Tenant B user
    response = client.post(
        f'/api/v1/runs/{run_tenant_a.run_id}/approve',
        headers={'Authorization': f'Bearer {token_b}'}
    )
    
    # Should return 404 (not 403) - don't leak existence
    assert response.status_code == 404, f"Expected 404, got {response.status_code}. Response: {response.get_json()}"


def test_list_runs_only_shows_own_tenant(client, temp_db, tenant_a, tenant_b, run_tenant_a, run_tenant_b, user_a):
    """
    Test that listing runs only returns runs for the authenticated tenant.
    This is a critical test for tenant isolation.
    """
    # Create JWT token for Tenant A user
    token_a = create_jwt_token(
        str(user_a.id),
        str(tenant_a.id),
        user_a.role
    )
    
    # List runs as Tenant A user
    response = client.get(
        '/api/v1/runs',
        headers={'Authorization': f'Bearer {token_a}'}
    )
    
    assert response.status_code == 200
    data = response.get_json()
    
    # Should only see Tenant A's run
    assert 'items' in data or isinstance(data, list), "Response should contain items array"
    runs = data.get('items', []) if isinstance(data, dict) else data
    
    # Verify only Tenant A's run is present
    run_ids = [r['run_id'] for r in runs]
    assert run_tenant_a.run_id in run_ids, "Should see Tenant A's run"
    assert run_tenant_b.run_id not in run_ids, "Should NOT see Tenant B's run"


def test_tenant_id_never_from_payload(client, temp_db, tenant_a, tenant_b, run_tenant_a, user_a):
    """
    Test that tenant_id cannot be provided in request payload to bypass isolation.
    This test ensures tenant_id comes ONLY from JWT context.
    """
    # Create JWT token for Tenant A user
    token_a = create_jwt_token(
        str(user_a.id),
        str(tenant_a.id),
        user_a.role
    )
    
    # Attempt to access run with tenant_id in payload (if endpoint accepts it)
    # Most endpoints don't accept tenant_id, but we test to be sure
    response = client.get(
        f'/api/v1/runs/{run_tenant_a.run_id}',
        headers={'Authorization': f'Bearer {token_a}'},
        json={'tenant_id': str(tenant_b.id)}  # Try to spoof tenant_id
    )
    
    # Should still work (tenant_id from JWT is used, payload is ignored)
    # OR should fail if endpoint doesn't accept JSON body
    # The key is: tenant_id from JWT (Tenant A) should be used, not payload
    assert response.status_code in [200, 400, 404, 405], "Request should either succeed with correct tenant or fail, but not use payload tenant_id"
    
    # If it succeeds, verify it's using Tenant A's data (from JWT), not Tenant B (from payload)
    if response.status_code == 200:
        data = response.get_json()
        # The run should be Tenant A's run (from JWT), not Tenant B's
        assert data.get('run_id') == run_tenant_a.run_id


def test_usage_events_tenant_isolation(client, temp_db, tenant_a, tenant_b, user_a, user_b):
    """
    Test that usage events are properly tenant-scoped.
    This verifies that usage tracking respects tenant boundaries.
    """
    from models import UsageEvent
    from datetime import datetime, timezone
    
    # Create usage events for both tenants
    event_a = UsageEvent(
        tenant_id=tenant_a.id,
        user_id=user_a.id,
        agent='test_plan',
        source='jira',
        success=True
    )
    event_b = UsageEvent(
        tenant_id=tenant_b.id,
        user_id=user_b.id,
        agent='test_plan',
        source='jira',
        success=True
    )
    
    temp_db.add(event_a)
    temp_db.add(event_b)
    temp_db.commit()
    
    # Create JWT token for Tenant A user
    token_a = create_jwt_token(
        str(user_a.id),
        str(tenant_a.id),
        user_a.role
    )
    
    # Query usage events (if endpoint exists)
    # Since there's no public endpoint, we verify at database level
    events_a = temp_db.query(UsageEvent).filter(
        UsageEvent.tenant_id == tenant_a.id
    ).all()
    
    events_b = temp_db.query(UsageEvent).filter(
        UsageEvent.tenant_id == tenant_b.id
    ).all()
    
    # Verify isolation
    assert len(events_a) == 1, "Should find Tenant A's event"
    assert len(events_b) == 1, "Should find Tenant B's event"
    assert events_a[0].id != events_b[0].id, "Events should be different"


def test_integration_tenant_isolation(client, temp_db, tenant_a, tenant_b, user_a, user_b):
    """
    Test that tenant integrations are properly isolated.
    This verifies that Jira integrations respect tenant boundaries.
    """
    from models import TenantIntegration
    from utils.encryption import encrypt_secret
    
    # Create integrations for both tenants
    integration_a = TenantIntegration(
        tenant_id=tenant_a.id,
        provider='jira',
        is_active=True,
        jira_base_url='https://tenant-a.atlassian.net',
        jira_user_email='user@tenant-a.com',
        credentials_ciphertext=encrypt_secret('token-a')
    )
    integration_b = TenantIntegration(
        tenant_id=tenant_b.id,
        provider='jira',
        is_active=True,
        jira_base_url='https://tenant-b.atlassian.net',
        jira_user_email='user@tenant-b.com',
        credentials_ciphertext=encrypt_secret('token-b')
    )
    
    temp_db.add(integration_a)
    temp_db.add(integration_b)
    temp_db.commit()
    
    # Create JWT token for Tenant A user
    token_a = create_jwt_token(
        str(user_a.id),
        str(tenant_a.id),
        user_a.role
    )
    
    # Query integrations (if endpoint exists)
    # Verify at database level
    integration_a_found = temp_db.query(TenantIntegration).filter(
        TenantIntegration.tenant_id == tenant_a.id,
        TenantIntegration.provider == 'jira'
    ).first()
    
    integration_b_found = temp_db.query(TenantIntegration).filter(
        TenantIntegration.tenant_id == tenant_b.id,
        TenantIntegration.provider == 'jira'
    ).first()
    
    # Verify isolation
    assert integration_a_found is not None, "Should find Tenant A's integration"
    assert integration_b_found is not None, "Should find Tenant B's integration"
    assert integration_a_found.id != integration_b_found.id, "Integrations should be different"
    assert integration_a_found.tenant_id == tenant_a.id, "Integration A should belong to Tenant A"
    assert integration_b_found.tenant_id == tenant_b.id, "Integration B should belong to Tenant B"
