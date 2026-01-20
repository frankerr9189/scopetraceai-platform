"""
Unit tests for Phase 2.1: User Profile + Password Update + Forgot Password flow.
"""
import os
import pytest
import bcrypt
from flask import Flask
from app import app
from db import SessionLocal, engine, Base
from models import Tenant, TenantUser, PasswordResetToken
from services.auth import (
    hash_password, verify_password, validate_password_strength,
    generate_reset_token, hash_token, create_reset_token, consume_reset_token
)
import uuid
from datetime import datetime, timedelta, timezone
from auth.jwt import create_access_token


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
    monkeypatch.setenv('APP_PUBLIC_BASE_URL', 'http://localhost:5173')
    
    # Reload auth module to pick up JWT_SECRET
    import importlib
    import auth.jwt as jwt_module
    import services.auth as auth_module
    importlib.reload(jwt_module)
    importlib.reload(auth_module)
    
    # Create test tenant
    tenant = Tenant(
        name="Test Tenant",
        slug="test-tenant",
        is_active=True,
        subscription_status="trial"
    )
    test_db.add(tenant)
    test_db.commit()
    test_db.refresh(tenant)
    
    # Create test user with known password
    password = "testpassword123"
    password_hash = hash_password(password)
    
    user = TenantUser(
        tenant_id=tenant.id,
        email="test@example.com",
        password_hash=password_hash,
        role="user",
        is_active=True,
        first_name="Test",
        last_name="User"
    )
    test_db.add(user)
    test_db.commit()
    test_db.refresh(user)
    
    return {
        "tenant": tenant,
        "user": user,
        "password": password,
        "db": test_db
    }


def get_auth_headers(user_id, tenant_id, role="user"):
    """Helper to create auth headers with JWT token."""
    token = create_access_token(str(user_id), str(tenant_id), role)
    return {"Authorization": f"Bearer {token}"}


def test_get_user_profile_success(client, test_user):
    """Test GET /api/v1/users/me returns user profile."""
    headers = get_auth_headers(test_user["user"].id, test_user["tenant"].id)
    
    response = client.get('/api/v1/users/me', headers=headers)
    
    assert response.status_code == 200
    data = response.get_json()
    assert data["id"] == str(test_user["user"].id)
    assert data["email"] == "test@example.com"
    assert data["role"] == "user"
    assert data["first_name"] == "Test"
    assert data["last_name"] == "User"
    assert data["tenant_id"] == str(test_user["tenant"].id)


def test_update_user_profile_success(client, test_user):
    """Test PATCH /api/v1/users/me updates profile fields."""
    headers = get_auth_headers(test_user["user"].id, test_user["tenant"].id)
    
    response = client.patch(
        '/api/v1/users/me',
        headers=headers,
        json={
            "first_name": "Updated",
            "last_name": "Name",
            "address_1": "123 Main St",
            "city": "San Francisco",
            "state": "CA",
            "zip": "94102",
            "phone": "555-1234"
        }
    )
    
    assert response.status_code == 200
    data = response.get_json()
    assert data["first_name"] == "Updated"
    assert data["last_name"] == "Name"
    assert data["address_1"] == "123 Main St"
    assert data["city"] == "San Francisco"
    assert data["state"] == "CA"
    assert data["zip"] == "94102"
    assert data["phone"] == "555-1234"
    
    # Verify in database
    test_user["db"].refresh(test_user["user"])
    assert test_user["user"].first_name == "Updated"
    assert test_user["user"].last_name == "Name"


def test_update_user_profile_rejects_forbidden_fields(client, test_user):
    """Test PATCH /api/v1/users/me rejects email, tenant_id, role changes."""
    headers = get_auth_headers(test_user["user"].id, test_user["tenant"].id)
    
    # Try to change email
    response = client.patch(
        '/api/v1/users/me',
        headers=headers,
        json={"email": "newemail@example.com"}
    )
    assert response.status_code == 400
    assert "email" in response.get_json()["detail"].lower()
    
    # Try to change tenant_id
    response = client.patch(
        '/api/v1/users/me',
        headers=headers,
        json={"tenant_id": str(uuid.uuid4())}
    )
    assert response.status_code == 400
    assert "tenant_id" in response.get_json()["detail"].lower()
    
    # Try to change role
    response = client.patch(
        '/api/v1/users/me',
        headers=headers,
        json={"role": "admin"}
    )
    assert response.status_code == 400
    assert "role" in response.get_json()["detail"].lower()


def test_change_password_success(client, test_user):
    """Test POST /api/v1/users/me/change-password with correct current password."""
    headers = get_auth_headers(test_user["user"].id, test_user["tenant"].id)
    
    response = client.post(
        '/api/v1/users/me/change-password',
        headers=headers,
        json={
            "current_password": test_user["password"],
            "new_password": "newpassword123456"
        }
    )
    
    assert response.status_code == 204
    
    # Verify password was changed
    test_user["db"].refresh(test_user["user"])
    assert verify_password("newpassword123456", test_user["user"].password_hash)
    assert not verify_password(test_user["password"], test_user["user"].password_hash)


def test_change_password_rejects_wrong_current_password(client, test_user):
    """Test POST /api/v1/users/me/change-password rejects wrong current password."""
    headers = get_auth_headers(test_user["user"].id, test_user["tenant"].id)
    
    response = client.post(
        '/api/v1/users/me/change-password',
        headers=headers,
        json={
            "current_password": "wrongpassword",
            "new_password": "newpassword123456"
        }
    )
    
    assert response.status_code == 400
    assert "current password" in response.get_json()["detail"].lower()


def test_change_password_enforces_min_length(client, test_user):
    """Test POST /api/v1/users/me/change-password enforces 12 character minimum."""
    headers = get_auth_headers(test_user["user"].id, test_user["tenant"].id)
    
    response = client.post(
        '/api/v1/users/me/change-password',
        headers=headers,
        json={
            "current_password": test_user["password"],
            "new_password": "short"
        }
    )
    
    assert response.status_code == 400
    assert "12" in response.get_json()["detail"]


def test_forgot_password_always_returns_200(client, test_user):
    """Test POST /api/v1/auth/forgot-password always returns 200 (no email enumeration)."""
    # Test with existing email
    response = client.post(
        '/api/v1/auth/forgot-password',
        json={"email": "test@example.com"}
    )
    assert response.status_code == 200
    assert response.get_json()["ok"] is True
    
    # Test with non-existent email (should still return 200)
    response = client.post(
        '/api/v1/auth/forgot-password',
        json={"email": "nonexistent@example.com"}
    )
    assert response.status_code == 200
    assert response.get_json()["ok"] is True


def test_forgot_password_creates_token_for_active_user(client, test_user):
    """Test forgot-password creates reset token for active user."""
    response = client.post(
        '/api/v1/auth/forgot-password',
        json={"email": "test@example.com"}
    )
    assert response.status_code == 200
    
    # Check token was created
    tokens = test_user["db"].query(PasswordResetToken).filter(
        PasswordResetToken.user_id == test_user["user"].id
    ).all()
    assert len(tokens) > 0
    assert tokens[0].used_at is None
    assert tokens[0].expires_at > datetime.now(timezone.utc)


def test_reset_password_success(client, test_user):
    """Test POST /api/v1/auth/reset-password with valid token."""
    # Create reset token
    raw_token, token_model = create_reset_token(test_user["db"], str(test_user["user"].id))
    test_user["db"].commit()
    
    response = client.post(
        '/api/v1/auth/reset-password',
        json={
            "token": raw_token,
            "new_password": "newpassword123456"
        }
    )
    
    assert response.status_code == 204
    
    # Verify password was changed
    test_user["db"].refresh(test_user["user"])
    assert verify_password("newpassword123456", test_user["user"].password_hash)
    
    # Verify token was marked as used
    test_user["db"].refresh(token_model)
    assert token_model.used_at is not None


def test_reset_password_rejects_invalid_token(client, test_user):
    """Test POST /api/v1/auth/reset-password rejects invalid token."""
    response = client.post(
        '/api/v1/auth/reset-password',
        json={
            "token": "invalid-token",
            "new_password": "newpassword123456"
        }
    )
    
    assert response.status_code == 400
    assert "invalid" in response.get_json()["detail"].lower() or "expired" in response.get_json()["detail"].lower()


def test_reset_token_one_time_use(client, test_user):
    """Test reset token can only be used once."""
    # Create reset token
    raw_token, token_model = create_reset_token(test_user["db"], str(test_user["user"].id))
    test_user["db"].commit()
    
    # Use token first time
    response = client.post(
        '/api/v1/auth/reset-password',
        json={
            "token": raw_token,
            "new_password": "newpassword123456"
        }
    )
    assert response.status_code == 204
    
    # Try to use same token again
    response = client.post(
        '/api/v1/auth/reset-password',
        json={
            "token": raw_token,
            "new_password": "anotherpassword123456"
        }
    )
    assert response.status_code == 400


def test_reset_token_expiry(client, test_user):
    """Test reset token expires after 30 minutes."""
    # Create token and manually set expiry to past
    raw_token, token_model = create_reset_token(test_user["db"], str(test_user["user"].id))
    token_model.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    test_user["db"].commit()
    
    response = client.post(
        '/api/v1/auth/reset-password',
        json={
            "token": raw_token,
            "new_password": "newpassword123456"
        }
    )
    
    assert response.status_code == 400
    assert "invalid" in response.get_json()["detail"].lower() or "expired" in response.get_json()["detail"].lower()


def test_reset_password_enforces_min_length(client, test_user):
    """Test POST /api/v1/auth/reset-password enforces 12 character minimum."""
    raw_token, _ = create_reset_token(test_user["db"], str(test_user["user"].id))
    test_user["db"].commit()
    
    response = client.post(
        '/api/v1/auth/reset-password',
        json={
            "token": raw_token,
            "new_password": "short"
        }
    )
    
    assert response.status_code == 400
    assert "12" in response.get_json()["detail"]
