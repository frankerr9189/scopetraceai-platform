"""
Minimal tests for usage tracking functionality.
"""
import pytest
import uuid
from datetime import datetime, timezone
from db import get_db, init_db
from models import UsageEvent, Tenant, TenantUser
from services.usage import record_usage_event


@pytest.fixture
def db_session():
    """Get database session for testing."""
    db = next(get_db())
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def test_tenant(db_session):
    """Create a test tenant."""
    tenant = Tenant(
        name="Test Tenant",
        slug="test-tenant",
        is_active=True
    )
    db_session.add(tenant)
    db_session.commit()
    db_session.refresh(tenant)
    return tenant


@pytest.fixture
def test_user(db_session, test_tenant):
    """Create a test user."""
    user = TenantUser(
        tenant_id=test_tenant.id,
        email="test@example.com",
        password_hash="hashed_password",
        role="user",
        is_active=True
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def test_record_usage_event_success(db_session, test_tenant, test_user):
    """Test that usage event is created successfully."""
    usage_event = record_usage_event(
        db=db_session,
        tenant_id=str(test_tenant.id),
        user_id=str(test_user.id),
        agent="requirements_ba",
        source="jira",
        jira_ticket_count=2,
        input_char_count=1000,
        success=True,
        duration_ms=1500
    )
    
    assert usage_event.id is not None
    assert usage_event.tenant_id == test_tenant.id
    assert usage_event.user_id == test_user.id
    assert usage_event.agent == "requirements_ba"
    assert usage_event.source == "jira"
    assert usage_event.jira_ticket_count == 2
    assert usage_event.input_char_count == 1000
    assert usage_event.success is True
    assert usage_event.duration_ms == 1500
    assert usage_event.error_code is None
    assert usage_event.created_at is not None


def test_record_usage_event_tenant_id_required(db_session):
    """Test that tenant_id is required."""
    with pytest.raises(ValueError, match="tenant_id is required"):
        record_usage_event(
            db=db_session,
            tenant_id=None,
            agent="requirements_ba",
            source="text",
            success=True
        )


def test_record_usage_event_failure_with_error_code(db_session, test_tenant):
    """Test that usage event records failure with error code."""
    usage_event = record_usage_event(
        db=db_session,
        tenant_id=str(test_tenant.id),
        agent="requirements_ba",
        source="text",
        input_char_count=500,
        success=False,
        error_code="analysis_error",
        duration_ms=2000
    )
    
    assert usage_event.success is False
    assert usage_event.error_code == "analysis_error"
    assert usage_event.tenant_id == test_tenant.id


def test_record_usage_event_stores_run_id(db_session, test_tenant, test_user):
    """Regression: BA Requirements runs must record usage_events.run_id for Run History."""
    run_id = "550e8400-e29b-41d4-a716-446655440000"
    usage_event = record_usage_event(
        db=db_session,
        tenant_id=str(test_tenant.id),
        user_id=str(test_user.id),
        agent="requirements_ba",
        source="text",
        success=True,
        run_id=run_id,
        duration_ms=100,
    )
    assert usage_event.run_id == run_id
    assert usage_event.agent == "requirements_ba"


def test_usage_event_tenant_isolation(db_session, test_tenant):
    """Test that usage events are tenant-isolated."""
    # Create second tenant
    tenant2 = Tenant(
        name="Test Tenant 2",
        slug="test-tenant-2",
        is_active=True
    )
    db_session.add(tenant2)
    db_session.commit()
    db_session.refresh(tenant2)
    
    # Create usage event for tenant 1
    event1 = record_usage_event(
        db=db_session,
        tenant_id=str(test_tenant.id),
        agent="requirements_ba",
        source="text",
        success=True
    )
    
    # Create usage event for tenant 2
    event2 = record_usage_event(
        db=db_session,
        tenant_id=str(tenant2.id),
        agent="requirements_ba",
        source="text",
        success=True
    )
    
    # Verify events belong to different tenants
    assert event1.tenant_id == test_tenant.id
    assert event2.tenant_id == tenant2.id
    assert event1.tenant_id != event2.tenant_id
    
    # Verify tenant isolation: query by tenant_id
    tenant1_events = db_session.query(UsageEvent).filter(
        UsageEvent.tenant_id == test_tenant.id
    ).all()
    tenant2_events = db_session.query(UsageEvent).filter(
        UsageEvent.tenant_id == tenant2.id
    ).all()
    
    assert len(tenant1_events) == 1
    assert len(tenant2_events) == 1
    assert tenant1_events[0].id == event1.id
    assert tenant2_events[0].id == event2.id
    
    # Cleanup
    db_session.delete(tenant2)
    db_session.commit()


def test_usage_event_user_id_optional(db_session, test_tenant):
    """Test that user_id is optional."""
    usage_event = record_usage_event(
        db=db_session,
        tenant_id=str(test_tenant.id),
        user_id=None,
        agent="requirements_ba",
        source="text",
        success=True
    )
    
    assert usage_event.tenant_id == test_tenant.id
    assert usage_event.user_id is None


def test_usage_event_defaults(db_session, test_tenant):
    """Test that default values are applied correctly."""
    usage_event = record_usage_event(
        db=db_session,
        tenant_id=str(test_tenant.id),
        agent="test_plan",
        source="text",
        success=True
    )
    
    assert usage_event.jira_ticket_count == 0
    assert usage_event.input_char_count == 0
    assert usage_event.run_id is None
    assert usage_event.duration_ms is None
