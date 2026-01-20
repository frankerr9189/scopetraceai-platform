"""
Tests for Ops Safety controls (ultra-strict: owner + kerr-ai-studio only).
"""
import pytest
import json
import uuid
from datetime import datetime, timezone
from app import app
from db import get_db, Base, engine
from models import Tenant, TenantUser, AdminAuditLog, UsageEvent, Run


@pytest.fixture
def client():
    """Create a test client."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def db_session():
    """Create a database session for testing."""
    Base.metadata.create_all(bind=engine)
    db = next(get_db())
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def kerr_tenant(db_session):
    """Create kerr-ai-studio tenant."""
    tenant = Tenant(
        id=uuid.uuid4(),
        name="Kerr AI Studio",
        slug="kerr-ai-studio",
        is_active=True,
        subscription_status="active"
    )
    db_session.add(tenant)
    db_session.commit()
    return tenant


@pytest.fixture
def other_tenant(db_session):
    """Create another tenant."""
    tenant = Tenant(
        id=uuid.uuid4(),
        name="Other Tenant",
        slug="other-tenant",
        is_active=True,
        subscription_status="trial"
    )
    db_session.add(tenant)
    db_session.commit()
    return tenant


@pytest.fixture
def kerr_owner(db_session, kerr_tenant):
    """Create owner user in kerr-ai-studio."""
    import bcrypt
    user = TenantUser(
        id=uuid.uuid4(),
        tenant_id=kerr_tenant.id,
        email="owner@kerr-ai-studio.com",
        password_hash=bcrypt.hashpw("password123".encode(), bcrypt.gensalt()).decode(),
        role="owner",
        is_active=True
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def kerr_user(db_session, kerr_tenant):
    """Create regular user in kerr-ai-studio."""
    import bcrypt
    user = TenantUser(
        id=uuid.uuid4(),
        tenant_id=kerr_tenant.id,
        email="user@kerr-ai-studio.com",
        password_hash=bcrypt.hashpw("password123".encode(), bcrypt.gensalt()).decode(),
        role="user",
        is_active=True
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def other_owner(db_session, other_tenant):
    """Create owner user in other tenant."""
    import bcrypt
    user = TenantUser(
        id=uuid.uuid4(),
        tenant_id=other_tenant.id,
        email="owner@other.com",
        password_hash=bcrypt.hashpw("password123".encode(), bcrypt.gensalt()).decode(),
        role="owner",
        is_active=True
    )
    db_session.add(user)
    db_session.commit()
    return user


def get_auth_token(client, email, password):
    """Helper to get auth token."""
    response = client.post('/api/v1/auth/login', json={
        'email': email,
        'password': password
    })
    if response.status_code == 200:
        data = json.loads(response.data)
        return data.get('access_token')
    return None


class TestOpsSafetyGuards:
    """Test ultra-strict guard: owner + kerr-ai-studio only."""

    def test_non_owner_gets_403(self, client, db_session, kerr_user):
        """Test that non-owner role gets 403."""
        token = get_auth_token(client, kerr_user.email, "password123")
        assert token is not None

        response = client.get(
            '/api/v1/admin/users',
            headers={'Authorization': f'Bearer {token}'}
        )
        assert response.status_code == 403
        data = json.loads(response.data)
        assert data['detail'] == 'Forbidden'

    def test_owner_other_tenant_gets_403(self, client, db_session, other_owner):
        """Test that owner from other tenant gets 403."""
        token = get_auth_token(client, other_owner.email, "password123")
        assert token is not None

        response = client.get(
            '/api/v1/admin/users',
            headers={'Authorization': f'Bearer {token}'}
        )
        assert response.status_code == 403
        data = json.loads(response.data)
        assert data['detail'] == 'Forbidden'

    def test_owner_kerr_tenant_gets_200(self, client, db_session, kerr_owner):
        """Test that owner from kerr-ai-studio gets access."""
        token = get_auth_token(client, kerr_owner.email, "password123")
        assert token is not None

        response = client.get(
            '/api/v1/admin/users',
            headers={'Authorization': f'Bearer {token}'}
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, list)


class TestUserDeactivateReactivate:
    """Test user deactivate/reactivate endpoints."""

    def test_deactivate_user(self, client, db_session, kerr_owner, kerr_tenant):
        """Test deactivating a user."""
        # Create a target user
        import bcrypt
        target_user = TenantUser(
            id=uuid.uuid4(),
            tenant_id=kerr_tenant.id,
            email="target@kerr-ai-studio.com",
            password_hash=bcrypt.hashpw("password123".encode(), bcrypt.gensalt()).decode(),
            role="user",
            is_active=True
        )
        db_session.add(target_user)
        db_session.commit()

        token = get_auth_token(client, kerr_owner.email, "password123")
        assert token is not None

        # Deactivate
        response = client.post(
            f'/api/v1/admin/users/{target_user.id}/deactivate',
            headers={'Authorization': f'Bearer {token}'}
        )
        assert response.status_code == 204

        # Verify user is deactivated
        db_session.refresh(target_user)
        assert target_user.is_active == False

        # Verify audit log
        audit_log = db_session.query(AdminAuditLog).filter(
            AdminAuditLog.action == 'ops.user.deactivate',
            AdminAuditLog.target_id == target_user.id
        ).first()
        assert audit_log is not None
        assert audit_log.user_id == kerr_owner.id
        assert audit_log.tenant_id == kerr_tenant.id

    def test_cannot_deactivate_self(self, client, db_session, kerr_owner):
        """Test that owner cannot deactivate themselves."""
        token = get_auth_token(client, kerr_owner.email, "password123")
        assert token is not None

        response = client.post(
            f'/api/v1/admin/users/{kerr_owner.id}/deactivate',
            headers={'Authorization': f'Bearer {token}'}
        )
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Cannot deactivate yourself' in data['detail']

    def test_reactivate_user(self, client, db_session, kerr_owner, kerr_tenant):
        """Test reactivating a user."""
        # Create a deactivated user
        import bcrypt
        target_user = TenantUser(
            id=uuid.uuid4(),
            tenant_id=kerr_tenant.id,
            email="target@kerr-ai-studio.com",
            password_hash=bcrypt.hashpw("password123".encode(), bcrypt.gensalt()).decode(),
            role="user",
            is_active=False
        )
        db_session.add(target_user)
        db_session.commit()

        token = get_auth_token(client, kerr_owner.email, "password123")
        assert token is not None

        # Reactivate
        response = client.post(
            f'/api/v1/admin/users/{target_user.id}/reactivate',
            headers={'Authorization': f'Bearer {token}'}
        )
        assert response.status_code == 204

        # Verify user is reactivated
        db_session.refresh(target_user)
        assert target_user.is_active == True

        # Verify audit log
        audit_log = db_session.query(AdminAuditLog).filter(
            AdminAuditLog.action == 'ops.user.reactivate',
            AdminAuditLog.target_id == target_user.id
        ).first()
        assert audit_log is not None


class TestTenantSuspendReactivate:
    """Test tenant suspend/reactivate endpoints."""

    def test_suspend_tenant(self, client, db_session, kerr_owner, kerr_tenant):
        """Test suspending tenant."""
        token = get_auth_token(client, kerr_owner.email, "password123")
        assert token is not None

        # Suspend
        response = client.post(
            '/api/v1/admin/tenant/suspend',
            headers={'Authorization': f'Bearer {token}'}
        )
        assert response.status_code == 204

        # Verify tenant is suspended
        db_session.refresh(kerr_tenant)
        assert kerr_tenant.is_active == False
        assert kerr_tenant.subscription_status == 'suspended'

        # Verify audit log
        audit_log = db_session.query(AdminAuditLog).filter(
            AdminAuditLog.action == 'ops.tenant.suspend',
            AdminAuditLog.target_id == kerr_tenant.id
        ).first()
        assert audit_log is not None

    def test_suspended_tenant_blocks_access(self, client, db_session, kerr_owner, kerr_tenant):
        """Test that suspended tenant blocks protected endpoints."""
        # Suspend tenant
        kerr_tenant.is_active = False
        kerr_tenant.subscription_status = 'suspended'
        db_session.commit()

        token = get_auth_token(client, kerr_owner.email, "password123")
        assert token is not None

        # Try to access a protected endpoint (e.g., runs)
        response = client.get(
            '/api/v1/runs',
            headers={'Authorization': f'Bearer {token}'}
        )
        assert response.status_code == 403
        data = json.loads(response.data)
        assert data['code'] == 'TENANT_SUSPENDED'

    def test_reactivate_tenant(self, client, db_session, kerr_owner, kerr_tenant):
        """Test reactivating tenant."""
        # Suspend first
        kerr_tenant.is_active = False
        kerr_tenant.subscription_status = 'suspended'
        db_session.commit()

        token = get_auth_token(client, kerr_owner.email, "password123")
        assert token is not None

        # Reactivate
        response = client.post(
            '/api/v1/admin/tenant/reactivate',
            headers={'Authorization': f'Bearer {token}'}
        )
        assert response.status_code == 204

        # Verify tenant is reactivated
        db_session.refresh(kerr_tenant)
        assert kerr_tenant.is_active == True
        assert kerr_tenant.subscription_status == 'active'

        # Verify audit log
        audit_log = db_session.query(AdminAuditLog).filter(
            AdminAuditLog.action == 'ops.tenant.reactivate',
            AdminAuditLog.target_id == kerr_tenant.id
        ).first()
        assert audit_log is not None


class TestUsageSummary:
    """Test usage summary endpoint."""

    def test_usage_summary(self, client, db_session, kerr_owner, kerr_tenant):
        """Test getting usage summary."""
        # Create some usage events
        for i in range(5):
            event = UsageEvent(
                tenant_id=kerr_tenant.id,
                agent="testing-agent",
                source="jira",
                jira_ticket_count=10,
                input_char_count=1000,
                success=True
            )
            db_session.add(event)
        db_session.commit()

        token = get_auth_token(client, kerr_owner.email, "password123")
        assert token is not None

        response = client.get(
            '/api/v1/admin/usage/summary?days=30',
            headers={'Authorization': f'Bearer {token}'}
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['days'] == 30
        assert data['totals']['events'] == 5
        assert data['totals']['success'] == 5
        assert len(data['by_agent']) > 0


class TestRecentRuns:
    """Test recent runs endpoint."""

    def test_recent_runs(self, client, db_session, kerr_owner, kerr_tenant):
        """Test getting recent runs."""
        # Create some runs
        for i in range(3):
            run = Run(
                run_id=str(uuid.uuid4()),
                tenant_id=kerr_tenant.id,
                created_at=datetime.now(timezone.utc),
                source_type="jira",
                status="success",
                review_status="generated",
                agent="testing-agent"
            )
            db_session.add(run)
        db_session.commit()

        token = get_auth_token(client, kerr_owner.email, "password123")
        assert token is not None

        response = client.get(
            '/api/v1/admin/runs/recent?limit=25',
            headers={'Authorization': f'Bearer {token}'}
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, list)
        assert len(data) == 3


class TestAuditLog:
    """Test audit log endpoint."""

    def test_audit_log_returns_newest_first(self, client, db_session, kerr_owner, kerr_tenant):
        """Test that audit log returns newest first."""
        # Create some audit log entries
        for i in range(3):
            log = AdminAuditLog(
                tenant_id=kerr_tenant.id,
                user_id=kerr_owner.id,
                action="ops.test.action",
                target_type="test",
                created_at=datetime.now(timezone.utc)
            )
            db_session.add(log)
        db_session.commit()

        token = get_auth_token(client, kerr_owner.email, "password123")
        assert token is not None

        response = client.get(
            '/api/v1/admin/audit?limit=50',
            headers={'Authorization': f'Bearer {token}'}
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, list)
        assert len(data) >= 3

        # Verify ordering (newest first)
        if len(data) > 1:
            for i in range(len(data) - 1):
                date1 = datetime.fromisoformat(data[i]['created_at'].replace('Z', '+00:00'))
                date2 = datetime.fromisoformat(data[i + 1]['created_at'].replace('Z', '+00:00'))
                assert date1 >= date2
