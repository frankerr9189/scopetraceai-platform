"""
Unit tests for strict email validation function and endpoint integration.

Tests validate_email_strict() function and ensures all three endpoints
(tenant admin creation, user invitation, lead submission) properly reject
invalid emails with correct HTTP error responses.
"""
import pytest
from flask import Flask
from app import app, validate_email_strict
from db import SessionLocal, engine, Base
from models import Tenant, TenantUser
import uuid
from datetime import datetime, timezone
import bcrypt


@pytest.fixture
def client():
    """Create Flask test client."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def test_db():
    """Create test database session and clean up."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def test_tenant(test_db):
    """Create a test tenant for endpoint tests."""
    tenant = Tenant(
        id=uuid.uuid4(),
        name="Test Company",
        slug="test-company",
        created_at=datetime.now(timezone.utc)
    )
    test_db.add(tenant)
    test_db.commit()
    return tenant


@pytest.fixture
def test_admin_user(test_db, test_tenant, monkeypatch):
    """Create a test admin user for authenticated endpoint tests."""
    monkeypatch.setenv('JWT_SECRET', 'test-secret-key-for-jwt-tests')
    
    # Reload auth module
    import importlib
    import auth.jwt as jwt_module
    importlib.reload(jwt_module)
    
    password_hash = bcrypt.hashpw(b"testpass123", bcrypt.gensalt()).decode('utf-8')
    user = TenantUser(
        id=uuid.uuid4(),
        tenant_id=test_tenant.id,
        email="admin@test.com",
        password_hash=password_hash,
        role="admin",
        is_active=True,
        created_at=datetime.now(timezone.utc)
    )
    test_db.add(user)
    test_db.commit()
    return user


class TestValidateEmailStrict:
    """Test cases for validate_email_strict() function."""
    
    # ========== VALID EMAIL CASES ==========
    
    def test_valid_standard_email(self):
        """Standard email format."""
        is_valid, error = validate_email_strict("user@example.com")
        assert is_valid is True
        assert error == ""
    
    def test_valid_plus_addressing(self):
        """Plus addressing (Gmail-style)."""
        is_valid, error = validate_email_strict("user+tag@example.com")
        assert is_valid is True
        assert error == ""
    
    def test_valid_dot_in_local_part(self):
        """Dot in local-part."""
        is_valid, error = validate_email_strict("first.last@example.com")
        assert is_valid is True
        assert error == ""
    
    def test_valid_multiple_dots_in_local_part(self):
        """Multiple dots in local-part."""
        is_valid, error = validate_email_strict("first.middle.last@example.com")
        assert is_valid is True
        assert error == ""
    
    def test_valid_hyphenated_domain(self):
        """Hyphenated domain name."""
        is_valid, error = validate_email_strict("user@example-domain.com")
        assert is_valid is True
        assert error == ""
    
    def test_valid_subdomain(self):
        """Subdomain."""
        is_valid, error = validate_email_strict("user@mail.example.com")
        assert is_valid is True
        assert error == ""
    
    def test_valid_multiple_subdomains(self):
        """Multiple subdomains."""
        is_valid, error = validate_email_strict("user@sub1.sub2.example.com")
        assert is_valid is True
        assert error == ""
    
    def test_valid_long_tld(self):
        """Long TLD (e.g., .technology)."""
        is_valid, error = validate_email_strict("user@example.technology")
        assert is_valid is True
        assert error == ""
    
    def test_valid_short_tld(self):
        """Short TLD (e.g., .io, .co)."""
        is_valid, error = validate_email_strict("user@example.io")
        assert is_valid is True
        assert error == ""
    
    def test_valid_country_code_tld(self):
        """Country code TLD."""
        is_valid, error = validate_email_strict("user@example.co.uk")
        assert is_valid is True
        assert error == ""
    
    def test_valid_numbers_in_local_part(self):
        """Numbers in local-part."""
        is_valid, error = validate_email_strict("user123@example.com")
        assert is_valid is True
        assert error == ""
    
    def test_valid_underscore_in_local_part(self):
        """Underscore in local-part."""
        is_valid, error = validate_email_strict("user_name@example.com")
        assert is_valid is True
        assert error == ""
    
    def test_valid_percent_in_local_part(self):
        """Percent sign in local-part."""
        is_valid, error = validate_email_strict("user%tag@example.com")
        assert is_valid is True
        assert error == ""
    
    def test_valid_hyphen_in_local_part(self):
        """Hyphen in local-part."""
        is_valid, error = validate_email_strict("user-name@example.com")
        assert is_valid is True
        assert error == ""
    
    def test_valid_max_length_local_part(self):
        """Local-part at max length (64 chars)."""
        local_part = "a" * 64
        is_valid, error = validate_email_strict(f"{local_part}@example.com")
        assert is_valid is True
        assert error == ""
    
    def test_valid_long_domain(self):
        """Long domain name."""
        is_valid, error = validate_email_strict("user@verylongdomainname.com")
        assert is_valid is True
        assert error == ""
    
    # ========== INVALID EMAIL CASES ==========
    
    def test_invalid_quoted_local_part(self):
        """Quoted local-part (bot prevention)."""
        is_valid, error = validate_email_strict('"text"@test.com')
        assert is_valid is False
        assert "quoted" in error.lower() or "not allowed" in error.lower()
    
    def test_invalid_quoted_local_part_single_quote(self):
        """Single-quoted local-part."""
        is_valid, error = validate_email_strict("'text'@test.com")
        assert is_valid is False
        assert "invalid characters" in error.lower()
    
    def test_invalid_consecutive_dots_local_part(self):
        """Consecutive dots in local-part."""
        is_valid, error = validate_email_strict("user..name@example.com")
        assert is_valid is False
        assert "consecutive" in error.lower()
    
    def test_invalid_dot_start_local_part(self):
        """Local-part starting with dot."""
        is_valid, error = validate_email_strict(".user@example.com")
        assert is_valid is False
        assert "start" in error.lower() or "end" in error.lower()
    
    def test_invalid_dot_end_local_part(self):
        """Local-part ending with dot."""
        is_valid, error = validate_email_strict("user.@example.com")
        assert is_valid is False
        assert "start" in error.lower() or "end" in error.lower()
    
    def test_invalid_space_in_local_part(self):
        """Space in local-part."""
        is_valid, error = validate_email_strict("user name@example.com")
        assert is_valid is False
        assert "space" in error.lower()
    
    def test_invalid_no_at_symbol(self):
        """Missing @ symbol."""
        is_valid, error = validate_email_strict("userexample.com")
        assert is_valid is False
        assert "@" in error.lower() or "symbol" in error.lower()
    
    def test_invalid_multiple_at_symbols(self):
        """Multiple @ symbols."""
        is_valid, error = validate_email_strict("user@example@com")
        assert is_valid is False
        assert "exactly one" in error.lower() or "one @" in error.lower()
    
    def test_invalid_empty_local_part(self):
        """Empty local-part."""
        is_valid, error = validate_email_strict("@example.com")
        assert is_valid is False
        assert "empty" in error.lower() or "cannot be empty" in error.lower()
    
    def test_invalid_empty_domain(self):
        """Empty domain."""
        is_valid, error = validate_email_strict("user@")
        assert is_valid is False
        assert "empty" in error.lower() or "cannot be empty" in error.lower()
    
    def test_invalid_domain_too_short(self):
        """Domain too short (a@b.c)."""
        is_valid, error = validate_email_strict("a@b.c")
        assert is_valid is False
        assert "too short" in error.lower()
    
    def test_invalid_no_tld(self):
        """No TLD (test@com)."""
        is_valid, error = validate_email_strict("test@com")
        assert is_valid is False
        assert "too short" in error.lower() or "top-level" in error.lower()
    
    def test_invalid_single_char_tld(self):
        """Single character TLD."""
        is_valid, error = validate_email_strict("user@example.c")
        assert is_valid is False
        assert "at least 2" in error.lower() or "too short" in error.lower()
    
    def test_invalid_tld_with_numbers(self):
        """TLD with numbers."""
        is_valid, error = validate_email_strict("user@example.123")
        assert is_valid is False
        assert "letters" in error.lower() or "only letters" in error.lower()
    
    def test_invalid_tld_with_hyphen(self):
        """TLD with hyphen."""
        is_valid, error = validate_email_strict("user@example.co-uk")
        assert is_valid is False
        assert "letters" in error.lower() or "only letters" in error.lower()
    
    def test_invalid_empty_domain_part(self):
        """Empty domain part (user@.com)."""
        is_valid, error = validate_email_strict("user@.com")
        assert is_valid is False
        assert "empty" in error.lower() or "cannot have empty" in error.lower()
    
    def test_invalid_consecutive_dots_domain(self):
        """Consecutive dots in domain."""
        is_valid, error = validate_email_strict("user@example..com")
        assert is_valid is False
        assert "empty" in error.lower() or "cannot have empty" in error.lower()
    
    def test_invalid_hyphen_start_domain_part(self):
        """Domain part starting with hyphen."""
        is_valid, error = validate_email_strict("user@-example.com")
        assert is_valid is False
        assert "hyphen" in error.lower() and ("start" in error.lower() or "end" in error.lower())
    
    def test_invalid_hyphen_end_domain_part(self):
        """Domain part ending with hyphen."""
        is_valid, error = validate_email_strict("user@example-.com")
        assert is_valid is False
        assert "hyphen" in error.lower() and ("start" in error.lower() or "end" in error.lower())
    
    def test_invalid_over_length_local_part(self):
        """Local-part over 64 characters."""
        local_part = "a" * 65
        is_valid, error = validate_email_strict(f"{local_part}@example.com")
        assert is_valid is False
        assert "too long" in error.lower() and "64" in error
    
    def test_invalid_over_length_total(self):
        """Total email over 254 characters."""
        long_email = "a" * 250 + "@example.com"
        is_valid, error = validate_email_strict(long_email)
        assert is_valid is False
        assert "too long" in error.lower() and "254" in error
    
    def test_invalid_over_length_domain(self):
        """Domain over 253 characters."""
        long_domain = "a" * 250 + ".com"
        is_valid, error = validate_email_strict(f"user@{long_domain}")
        assert is_valid is False
        assert "too long" in error.lower() and "253" in error
    
    def test_invalid_too_short_total(self):
        """Email too short (a@b)."""
        is_valid, error = validate_email_strict("a@b")
        assert is_valid is False
        assert "too short" in error.lower()
    
    def test_invalid_special_chars_local_part(self):
        """Invalid special characters in local-part."""
        is_valid, error = validate_email_strict("user#tag@example.com")
        assert is_valid is False
        assert "invalid characters" in error.lower()
    
    def test_invalid_special_chars_domain(self):
        """Invalid special characters in domain."""
        is_valid, error = validate_email_strict("user@example_com.com")
        assert is_valid is False
        assert "invalid characters" in error.lower()
    
    def test_invalid_none_input(self):
        """None input."""
        is_valid, error = validate_email_strict(None)
        assert is_valid is False
        assert "required" in error.lower()
    
    def test_invalid_empty_string(self):
        """Empty string."""
        is_valid, error = validate_email_strict("")
        assert is_valid is False
        assert "required" in error.lower() or "too short" in error.lower()
    
    def test_invalid_whitespace_only(self):
        """Whitespace only."""
        is_valid, error = validate_email_strict("   ")
        assert is_valid is False
        assert "required" in error.lower() or "too short" in error.lower()
    
    def test_invalid_non_string_input(self):
        """Non-string input."""
        is_valid, error = validate_email_strict(12345)
        assert is_valid is False
        assert "required" in error.lower()


class TestEmailValidationEndpoints:
    """Test that endpoints properly reject invalid emails."""
    
    def test_tenant_admin_creation_rejects_invalid_email(self, client, test_tenant):
        """POST /api/v1/onboarding/tenant/<tenant_id>/admin rejects invalid email."""
        invalid_emails = [
            '"text"@test.com',  # Quoted local-part
            'test@com',  # No TLD
            'a@b.c',  # Domain too short
            'user@.com',  # Empty domain part
            'user@example..com',  # Consecutive dots
        ]
        
        for invalid_email in invalid_emails:
            response = client.post(
                f"/api/v1/onboarding/tenant/{test_tenant.id}/admin",
                json={
                    "email": invalid_email,
                    "password": "testpass123",
                    "role": "admin"
                },
                content_type="application/json"
            )
            assert response.status_code == 400
            data = response.get_json()
            assert "detail" in data or "error" in data
            error_msg = data.get("detail") or data.get("error") or ""
            assert "email" in error_msg.lower() or "invalid" in error_msg.lower()
    
    def test_tenant_admin_creation_accepts_valid_email(self, client, test_tenant):
        """POST /api/v1/onboarding/tenant/<tenant_id>/admin accepts valid email."""
        response = client.post(
            f"/api/v1/onboarding/tenant/{test_tenant.id}/admin",
            json={
                "email": "admin@example.com",
                "password": "testpass123",
                "role": "admin"
            },
            content_type="application/json"
        )
        # Should not fail due to email validation (may fail for other reasons like tenant already has user)
        assert response.status_code != 400 or "email" not in (response.get_json() or {}).get("detail", "").lower()
    
    def test_user_invite_rejects_invalid_email(self, client, test_db, test_tenant, test_admin_user, monkeypatch):
        """POST /api/v1/tenant/users/invite rejects invalid email."""
        monkeypatch.setenv('JWT_SECRET', 'test-secret-key-for-jwt-tests')
        
        # Get JWT token for admin user
        from auth.jwt import create_access_token
        token = create_access_token(
            user_id=str(test_admin_user.id),
            tenant_id=str(test_tenant.id),
            role="admin"
        )
        
        invalid_emails = [
            '"text"@test.com',  # Quoted local-part
            'test@com',  # No TLD
            'a@b.c',  # Domain too short
            'user@.com',  # Empty domain part
            'user@example..com',  # Consecutive dots
        ]
        
        for invalid_email in invalid_emails:
            response = client.post(
                "/api/v1/tenant/users/invite",
                json={
                    "email": invalid_email,
                    "role": "user"
                },
                headers={"Authorization": f"Bearer {token}"},
                content_type="application/json"
            )
            assert response.status_code == 400
            data = response.get_json()
            assert data.get("ok") is False
            assert "INVALID_REQUEST" in data.get("error", "")
            error_msg = data.get("message", "")
            assert "email" in error_msg.lower() or "invalid" in error_msg.lower()
    
    def test_user_invite_accepts_valid_email(self, client, test_db, test_tenant, test_admin_user, monkeypatch):
        """POST /api/v1/tenant/users/invite accepts valid email."""
        monkeypatch.setenv('JWT_SECRET', 'test-secret-key-for-jwt-tests')
        
        from auth.jwt import create_access_token
        token = create_access_token(
            user_id=str(test_admin_user.id),
            tenant_id=str(test_tenant.id),
            role="admin"
        )
        
        response = client.post(
            "/api/v1/tenant/users/invite",
            json={
                "email": "newuser@example.com",
                "role": "user"
            },
            headers={"Authorization": f"Bearer {token}"},
            content_type="application/json"
        )
        # Should not fail due to email validation (may fail for other reasons like seat cap)
        assert response.status_code != 400 or "email" not in (response.get_json() or {}).get("message", "").lower()
    
    def test_leads_endpoint_rejects_invalid_email(self, client):
        """POST /api/v1/leads rejects invalid email."""
        invalid_emails = [
            '"text"@test.com',  # Quoted local-part
            'test@com',  # No TLD
            'a@b.c',  # Domain too short
            'user@.com',  # Empty domain part
            'user@example..com',  # Consecutive dots
        ]
        
        for invalid_email in invalid_emails:
            response = client.post(
                "/api/v1/leads",
                json={
                    "email": invalid_email,
                    "name": "Test User"
                },
                content_type="application/json"
            )
            assert response.status_code == 400
            data = response.get_json()
            assert "error" in data
            error_msg = data.get("error", "")
            assert "email" in error_msg.lower() or "invalid" in error_msg.lower()
    
    def test_leads_endpoint_accepts_valid_email(self, client, test_db):
        """POST /api/v1/leads accepts valid email."""
        response = client.post(
            "/api/v1/leads",
            json={
                "email": "lead@example.com",
                "name": "Test User"
            },
            content_type="application/json"
        )
        # Should succeed (200 or 201)
        assert response.status_code in [200, 201]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
