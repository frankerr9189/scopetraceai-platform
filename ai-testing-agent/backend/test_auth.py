"""
Unit tests for JWT authentication middleware and login endpoint.
"""
import os
import pytest
import bcrypt
from flask import Flask
from app import app
from db import SessionLocal, engine, Base
from models import Tenant, TenantUser
import uuid
from datetime import datetime, timezone


@pytest.fixture
def client():
    """Create Flask test client."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def test_db():
    """Create test database session and clean up."""
    # Create tables
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        # Clean up tables
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def test_user(test_db, monkeypatch):
    """Create a test tenant and user for authentication tests."""
    # Set JWT_SECRET for tests
    monkeypatch.setenv('JWT_SECRET', 'test-secret-key-for-jwt-tests')
    
    # Reload auth module to pick up JWT_SECRET
    import importlib
    import auth.jwt as jwt_module
    importlib.reload(jwt_module)
    
    # Create test tenant
    tenant = Tenant(
        name="Test Tenant",
        slug="test-tenant",
        is_active=True
    )
    test_db.add(tenant)
    test_db.commit()
    test_db.refresh(tenant)
    
    # Create test user with known password
    password = "testpassword123"
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    user = TenantUser(
        tenant_id=tenant.id,
        email="test@example.com",
        password_hash=password_hash,
        role="owner",
        is_active=True
    )
    test_db.add(user)
    test_db.commit()
    test_db.refresh(user)
    
    return {
        "tenant": tenant,
        "user": user,
        "password": password
    }


def test_login_email_only_single_tenant_success(client, test_user):
    """Test successful login with email+password only (single tenant)."""
    response = client.post(
        '/auth/login',
        json={
            "email": "test@example.com",
            "password": test_user["password"]
        }
    )
    
    assert response.status_code == 200
    data = response.get_json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert "user" in data
    assert data["user"]["email"] == "test@example.com"
    assert data["user"]["role"] == "owner"
    assert data["user"]["id"] == str(test_user["user"].id)
    assert data["user"]["tenant_id"] == str(test_user["tenant"].id)


def test_login_success_with_tenant_slug(client, test_user):
    """Test successful login with tenant_slug (backward compatibility)."""
    response = client.post(
        '/auth/login',
        json={
            "tenant_slug": "test-tenant",
            "email": "test@example.com",
            "password": test_user["password"]
        }
    )
    
    assert response.status_code == 200
    data = response.get_json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert "user" in data
    assert data["user"]["email"] == "test@example.com"


def test_login_email_only_wrong_password_401(client, test_user):
    """Test login with wrong password returns 401."""
    response = client.post(
        '/auth/login',
        json={
            "email": "test@example.com",
            "password": "wrongpassword"
        }
    )
    
    assert response.status_code == 401
    data = response.get_json()
    assert "Invalid" in data["detail"] or "credentials" in data["detail"].lower()


def test_login_email_only_invalid_email_401(client, test_user):
    """Test login with invalid email returns 401."""
    response = client.post(
        '/auth/login',
        json={
            "email": "wrong@example.com",
            "password": test_user["password"]
        }
    )
    
    assert response.status_code == 401
    data = response.get_json()
    assert "Invalid" in data["detail"] or "credentials" in data["detail"].lower()


def test_login_email_only_multiple_tenants_returns_409(client, test_db, test_user, monkeypatch):
    """Test login with email that exists in multiple tenants returns 409 after password verification."""
    monkeypatch.setenv('JWT_SECRET', 'test-secret-key-for-jwt-tests')
    
    # Create a second tenant with the same user email
    tenant2 = Tenant(
        name="Test Tenant 2",
        slug="test-tenant-2",
        is_active=True
    )
    test_db.add(tenant2)
    test_db.commit()
    test_db.refresh(tenant2)
    
    # Create user with same email in second tenant
    password = test_user["password"]
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    user2 = TenantUser(
        tenant_id=tenant2.id,
        email="test@example.com",  # Same email
        password_hash=password_hash,
        role="owner",
        is_active=True
    )
    test_db.add(user2)
    test_db.commit()
    
    # Try to login - should get 409 with tenant list
    response = client.post(
        '/auth/login',
        json={
            "email": "test@example.com",
            "password": password
        }
    )
    
    assert response.status_code == 409
    data = response.get_json()
    assert data["code"] == "TENANT_SELECTION_REQUIRED"
    assert "Multiple workspaces" in data["detail"]
    assert "tenants" in data
    assert len(data["tenants"]) == 2
    tenant_ids = [t["tenant_id"] for t in data["tenants"]]
    assert str(test_user["tenant"].id) in tenant_ids
    assert str(tenant2.id) in tenant_ids


def test_login_tenant_second_step_success(client, test_db, test_user, monkeypatch):
    """Test second-step login with tenant_id selection."""
    monkeypatch.setenv('JWT_SECRET', 'test-secret-key-for-jwt-tests')
    
    # Create a second tenant with the same user email
    tenant2 = Tenant(
        name="Test Tenant 2",
        slug="test-tenant-2",
        is_active=True
    )
    test_db.add(tenant2)
    test_db.commit()
    test_db.refresh(tenant2)
    
    password = test_user["password"]
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    user2 = TenantUser(
        tenant_id=tenant2.id,
        email="test@example.com",
        password_hash=password_hash,
        role="owner",
        is_active=True
    )
    test_db.add(user2)
    test_db.commit()
    
    # First step: get 409 with tenant list
    response1 = client.post(
        '/auth/login',
        json={
            "email": "test@example.com",
            "password": password
        }
    )
    assert response1.status_code == 409
    data1 = response1.get_json()
    tenant_list = data1["tenants"]
    
    # Second step: select a tenant
    selected_tenant = tenant_list[0]  # Pick first tenant
    response2 = client.post(
        '/auth/login/tenant',
        json={
            "tenant_id": selected_tenant["tenant_id"],
            "email": "test@example.com",
            "password": password
        }
    )
    
    assert response2.status_code == 200
    data2 = response2.get_json()
    assert "access_token" in data2
    assert data2["user"]["tenant_id"] == selected_tenant["tenant_id"]


def test_login_inactive_user(client, test_db, test_user, monkeypatch):
    """Test login with inactive user returns 403 with code USER_INACTIVE."""
    monkeypatch.setenv('JWT_SECRET', 'test-secret-key-for-jwt-tests')
    
    # Deactivate user
    test_user["user"].is_active = False
    test_db.commit()
    
    response = client.post(
        '/auth/login',
        json={
            "email": "test@example.com",
            "password": test_user["password"]
        }
    )
    
    assert response.status_code == 403
    data = response.get_json()
    assert data["code"] == "USER_INACTIVE"
    assert "inactive" in data["detail"].lower()
    assert "hello@scopetraceai.com" in data["detail"]


def test_login_missing_fields(client):
    """Test login with missing fields returns 400."""
    response = client.post(
        '/auth/login',
        json={}
    )
    
    assert response.status_code == 400
    data = response.get_json()
    assert "required" in data["detail"].lower()


def test_auth_middleware_missing_header_returns_401(client, monkeypatch):
    """Test that protected routes require Authorization header."""
    monkeypatch.setenv('JWT_SECRET', 'test-secret-key-for-jwt-tests')
    
    # Reload auth module
    import importlib
    import auth.jwt as jwt_module
    importlib.reload(jwt_module)
    
    # Make request without Authorization header
    response = client.get('/api/v1/runs')
    assert response.status_code == 401
    data = response.get_json()
    assert data == {"detail": "Unauthorized"}


def test_auth_middleware_invalid_token_returns_401(client, monkeypatch):
    """Test that invalid JWT token returns 401."""
    monkeypatch.setenv('JWT_SECRET', 'test-secret-key-for-jwt-tests')
    
    # Reload auth module
    import importlib
    import auth.jwt as jwt_module
    importlib.reload(jwt_module)
    
    # Make request with invalid token
    response = client.get(
        '/api/v1/runs',
        headers={'Authorization': 'Bearer invalid-token'}
    )
    assert response.status_code == 401
    data = response.get_json()
    assert data == {"detail": "Unauthorized"}


def test_auth_middleware_valid_token_allows_request(client, test_user, monkeypatch):
    """Test that valid JWT token allows access to protected routes."""
    monkeypatch.setenv('JWT_SECRET', 'test-secret-key-for-jwt-tests')
    
    # Reload auth module
    import importlib
    import auth.jwt as jwt_module
    importlib.reload(jwt_module)
    
    # Login to get token
    login_response = client.post(
        '/auth/login',
        json={
            "email": "test@example.com",
            "password": test_user["password"]
        }
    )
    assert login_response.status_code == 200
    token = login_response.get_json()["access_token"]
    
    # Make request with valid token
    response = client.get(
        '/api/v1/runs',
        headers={'Authorization': f'Bearer {token}'}
    )
    # Should succeed (200 or 404, but not 401)
    assert response.status_code != 401


def test_login_inactive_tenant_blocks_login(client, test_db, test_user, monkeypatch):
    """Test login with inactive tenant returns 403 with code TENANT_INACTIVE."""
    monkeypatch.setenv('JWT_SECRET', 'test-secret-key-for-jwt-tests')
    
    # Deactivate tenant
    test_user["tenant"].is_active = False
    test_db.commit()
    
    response = client.post(
        '/auth/login',
        json={
            "email": "test@example.com",
            "password": test_user["password"]
        }
    )
    
    assert response.status_code == 403
    data = response.get_json()
    assert data["code"] == "TENANT_INACTIVE"
    assert "inactive" in data["detail"].lower()
    assert "hello@scopetraceai.com" in data["detail"]


def test_middleware_inactive_tenant_blocks_request(client, test_user, test_db, monkeypatch):
    """Test that middleware blocks requests with valid token but inactive tenant."""
    monkeypatch.setenv('JWT_SECRET', 'test-secret-key-for-jwt-tests')
    
    # Reload auth module
    import importlib
    import auth.jwt as jwt_module
    importlib.reload(jwt_module)
    
    # Login to get token
    login_response = client.post(
        '/auth/login',
        json={
            "email": "test@example.com",
            "password": test_user["password"]
        }
    )
    assert login_response.status_code == 200
    token = login_response.get_json()["access_token"]
    
    # Deactivate tenant after login (simulating tenant being deactivated while user has valid token)
    test_user["tenant"].is_active = False
    test_db.commit()
    
    # Make request with valid token but inactive tenant
    response = client.get(
        '/api/v1/runs',
        headers={'Authorization': f'Bearer {token}'}
    )
    
    assert response.status_code == 403
    data = response.get_json()
    assert data["code"] == "TENANT_INACTIVE"
    assert "inactive" in data["detail"].lower()
    assert "hello@scopetraceai.com" in data["detail"]


def test_middleware_inactive_user_blocks_request(client, test_user, test_db, monkeypatch):
    """Test that middleware blocks requests with valid token but inactive user."""
    monkeypatch.setenv('JWT_SECRET', 'test-secret-key-for-jwt-tests')
    
    # Reload auth module
    import importlib
    import auth.jwt as jwt_module
    importlib.reload(jwt_module)
    
    # Login to get token
    login_response = client.post(
        '/auth/login',
        json={
            "email": "test@example.com",
            "password": test_user["password"]
        }
    )
    assert login_response.status_code == 200
    token = login_response.get_json()["access_token"]
    
    # Deactivate user after login (simulating user being deactivated while having valid token)
    test_user["user"].is_active = False
    test_db.commit()
    
    # Make request with valid token but inactive user
    response = client.get(
        '/api/v1/runs',
        headers={'Authorization': f'Bearer {token}'}
    )
    
    assert response.status_code == 403
    data = response.get_json()
    assert data["code"] == "USER_INACTIVE"
    assert "inactive" in data["detail"].lower()
    assert "hello@scopetraceai.com" in data["detail"]


def test_middleware_db_failure_returns_503(client, test_user, monkeypatch):
    """Test that middleware returns 503 AUTH_UNAVAILABLE when DB checks fail."""
    monkeypatch.setenv('JWT_SECRET', 'test-secret-key-for-jwt-tests')
    
    # Reload auth module
    import importlib
    import auth.jwt as jwt_module
    importlib.reload(jwt_module)
    
    # Login to get token
    login_response = client.post(
        '/auth/login',
        json={
            "email": "test@example.com",
            "password": test_user["password"]
        }
    )
    assert login_response.status_code == 200
    token = login_response.get_json()["access_token"]
    
    # Mock get_db to raise an exception (simulating DB failure)
    # Since get_db is imported inside the middleware function, we patch it at the db module level
    from unittest.mock import patch
    
    def failing_get_db():
        raise Exception("Database connection failed")
    
    # Patch get_db in the db module
    with patch('db.get_db', side_effect=failing_get_db):
        # Make request with valid token
        response = client.get(
            '/api/v1/runs',
            headers={'Authorization': f'Bearer {token}'}
        )
        
        assert response.status_code == 503
        data = response.get_json()
        assert data["code"] == "AUTH_UNAVAILABLE"
        assert "temporarily unavailable" in data["detail"].lower()


def test_auth_middleware_skips_non_api_v1_routes(client, monkeypatch):
    """Test that auth middleware does not protect non-/api/v1/* routes."""
    monkeypatch.setenv('JWT_SECRET', 'test-secret-key-for-jwt-tests')
    
    # Reload auth module
    import importlib
    import auth.jwt as jwt_module
    importlib.reload(jwt_module)
    
    # Make request to non-protected route
    response = client.get('/')
    # Should not return 401 (might return 200 or other, but not 401)
    assert response.status_code != 401


def test_auth_middleware_skips_health_endpoints(client, monkeypatch):
    """Test that auth middleware does not protect health check endpoints."""
    monkeypatch.setenv('JWT_SECRET', 'test-secret-key-for-jwt-tests')
    
    # Reload auth module
    import importlib
    import auth.jwt as jwt_module
    importlib.reload(jwt_module)
    
    # Make request to health endpoint
    response = client.get('/health/db')
    # Should not return 401
    assert response.status_code != 401


def test_register_creates_exactly_one_user_row(client, test_db, monkeypatch):
    """Test that registration creates exactly one tenant_users row per email."""
    monkeypatch.setenv('JWT_SECRET', 'test-secret-key-for-jwt-tests')
    
    # Reload auth module
    import importlib
    import auth.jwt as jwt_module
    importlib.reload(jwt_module)
    
    email = "newuser@example.com"
    password = "password123"
    
    # Register user
    response = client.post(
        '/auth/register',
        json={
            "email": email,
            "password": password
        }
    )
    
    assert response.status_code == 201
    data = response.get_json()
    assert "access_token" in data
    user_id = data["user"]["id"]
    
    # Verify exactly one row exists for this email
    user_rows = test_db.query(TenantUser).filter(TenantUser.email == email).all()
    assert len(user_rows) == 1, f"Expected 1 row, found {len(user_rows)}"
    assert str(user_rows[0].id) == user_id
    assert user_rows[0].tenant_id is None  # Onboarding incomplete


def test_onboarding_company_updates_existing_row_not_creates_new(client, test_db, monkeypatch):
    """Test that creating company updates existing row, doesn't create duplicate."""
    monkeypatch.setenv('JWT_SECRET', 'test-secret-key-for-jwt-tests')
    
    # Reload auth module
    import importlib
    import auth.jwt as jwt_module
    importlib.reload(jwt_module)
    
    email = "onboarding@example.com"
    password = "password123"
    
    # Step 1: Register user
    register_response = client.post(
        '/auth/register',
        json={
            "email": email,
            "password": password
        }
    )
    assert register_response.status_code == 201
    token = register_response.get_json()["access_token"]
    user_id = register_response.get_json()["user"]["id"]
    
    # Verify one row exists with tenant_id NULL
    user_before = test_db.query(TenantUser).filter(TenantUser.email == email).first()
    assert user_before is not None
    assert str(user_before.id) == user_id
    assert user_before.tenant_id is None
    
    # Step 2: Create company
    company_response = client.post(
        '/api/v1/onboarding/company',
        headers={'Authorization': f'Bearer {token}'},
        json={"company_name": "Test Company"}
    )
    assert company_response.status_code == 201
    company_data = company_response.get_json()
    tenant_id = company_data["tenant_id"]
    
    # Step 3: Verify still exactly one row exists, now with tenant_id set
    user_after = test_db.query(TenantUser).filter(TenantUser.email == email).first()
    assert user_after is not None
    assert str(user_after.id) == user_id  # Same user ID
    assert str(user_after.tenant_id) == tenant_id  # tenant_id now set
    
    # Verify no duplicate rows
    all_rows = test_db.query(TenantUser).filter(TenantUser.email == email).all()
    assert len(all_rows) == 1, f"Expected 1 row after company creation, found {len(all_rows)}"


def test_onboarding_company_prevents_duplicate_returns_409(client, test_db, monkeypatch):
    """Test that calling onboarding/company twice returns 409 and doesn't create duplicate rows."""
    monkeypatch.setenv('JWT_SECRET', 'test-secret-key-for-jwt-tests')
    
    # Reload auth module
    import importlib
    import auth.jwt as jwt_module
    importlib.reload(jwt_module)
    
    email = "duplicate@example.com"
    password = "password123"
    
    # Step 1: Register user
    register_response = client.post(
        '/auth/register',
        json={
            "email": email,
            "password": password
        }
    )
    assert register_response.status_code == 201
    token = register_response.get_json()["access_token"]
    
    # Step 2: Create company (first time - should succeed)
    company_response1 = client.post(
        '/api/v1/onboarding/company',
        headers={'Authorization': f'Bearer {token}'},
        json={"company_name": "First Company"}
    )
    assert company_response1.status_code == 201
    tenant_id_1 = company_response1.get_json()["tenant_id"]
    
    # Step 3: Try to create company again (should return 409)
    company_response2 = client.post(
        '/api/v1/onboarding/company',
        headers={'Authorization': f'Bearer {token}'},
        json={"company_name": "Second Company"}
    )
    assert company_response2.status_code == 409
    assert "already created" in company_response2.get_json()["detail"].lower()
    
    # Step 4: Verify still exactly one row exists
    all_rows = test_db.query(TenantUser).filter(TenantUser.email == email).all()
    assert len(all_rows) == 1, f"Expected 1 row, found {len(all_rows)}"
    
    # Verify tenant_id is still from first creation
    user = all_rows[0]
    assert str(user.tenant_id) == tenant_id_1
