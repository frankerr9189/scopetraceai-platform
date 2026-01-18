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


def test_login_success(client, test_user):
    """Test successful login returns JWT token."""
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


def test_login_invalid_email(client, test_user):
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
    assert data["detail"] == "Invalid email or password"


def test_login_invalid_password(client, test_user):
    """Test login with invalid password returns 401."""
    response = client.post(
        '/auth/login',
        json={
            "email": "test@example.com",
            "password": "wrongpassword"
        }
    )
    
    assert response.status_code == 401
    data = response.get_json()
    assert data["detail"] == "Invalid email or password"


def test_login_inactive_user(client, test_db, test_user, monkeypatch):
    """Test login with inactive user returns 401."""
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
    
    assert response.status_code == 401
    data = response.get_json()
    assert data["detail"] == "Account is inactive"


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
