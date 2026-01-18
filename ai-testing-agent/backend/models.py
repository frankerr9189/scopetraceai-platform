"""
SQLAlchemy models for persistence.
"""
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Boolean, Index, UniqueConstraint, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
import uuid
from db import Base


class Run(Base):
    """
    Model for storing test plan generation runs.
    """
    __tablename__ = "runs"
    
    run_id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    source_type = Column(String, nullable=False)  # "jira" | "freeform" | "document"
    ticket_count = Column(Integer, nullable=True)
    scope_id = Column(String, nullable=True)
    scope_type = Column(String, nullable=True)
    status = Column(String, nullable=False)  # "success" | "error" | "generated"
    logic_version = Column(String, nullable=True)
    model_name = Column(String, nullable=True)
    created_by = Column(String, nullable=True)  # Actor/user who created the run
    environment = Column(String, nullable=True)  # Environment (e.g., "development", "production")
    
    # Review and approval lifecycle (Phase 2A)
    review_status = Column(String, nullable=False, default="generated")  # "generated" | "reviewed" | "approved"
    reviewed_by = Column(String, nullable=True)  # Actor who reviewed the run
    reviewed_at = Column(DateTime, nullable=True)  # Timestamp when reviewed
    approved_by = Column(String, nullable=True)  # Actor who approved the run
    approved_at = Column(DateTime, nullable=True)  # Timestamp when approved
    
    # Jira write-back metadata (Phase 3)
    jira_issue_key = Column(String, nullable=True)  # Jira issue key (e.g., "PROJ-123")
    jira_issue_url = Column(String, nullable=True)  # Full URL to Jira issue
    jira_created_by = Column(String, nullable=True)  # Actor who created the Jira issue
    jira_created_at = Column(DateTime, nullable=True)  # Timestamp when Jira issue was created
    jira_audit_comment_posted_at = Column(DateTime, nullable=True)  # Timestamp when audit comment was posted
    jira_audit_comment_posted_by = Column(String, nullable=True)  # Actor who posted the audit comment
    jira_audit_comment_id = Column(String, nullable=True)  # Jira comment ID (if available)
    
    # Agent and run type metadata (Phase 4)
    agent = Column(String, nullable=False, server_default='testing-agent')  # 'testing-agent' | 'ba-agent'
    run_kind = Column(String, nullable=False, server_default='test_plan')  # 'test_plan' | 'requirements'
    artifact_type = Column(String, nullable=True)  # 'test_plan' | 'requirement_package'
    artifact_id = Column(String, nullable=True)  # package_id for BA runs, run_id for test plan runs
    summary = Column(Text, nullable=True)  # Short display text for run list
    input_ticket_count = Column(Integer, nullable=True, server_default='0')  # Number of input tickets/items
    output_item_count = Column(Integer, nullable=True, server_default='0')  # Number of requirements/tests generated
    
    # Relationship to artifacts
    artifacts = relationship("Artifact", back_populates="run", cascade="all, delete-orphan")
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_runs_tenant_id', 'tenant_id'),
    )


class Artifact(Base):
    """
    Model for storing artifact metadata (JSON files stored on disk).
    """
    __tablename__ = "artifacts"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    run_id = Column(String, ForeignKey("runs.run_id", ondelete="CASCADE"), nullable=False)
    artifact_type = Column(String, nullable=False)  # "package" | "rtm" | "test_plan" | "execution_report_csv" etc.
    path = Column(String, nullable=False)  # Path to artifact file (relative or absolute)
    sha256 = Column(String, nullable=False)  # SHA-256 hash of artifact content
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationship to run
    run = relationship("Run", back_populates="artifacts")
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_artifacts_tenant_id', 'tenant_id'),
    )


class Tenant(Base):
    """
    Model for multi-tenant SaaS organization/company.
    Foundation schema for future SaaS onboarding.
    """
    __tablename__ = "tenants"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False)
    slug = Column(String, nullable=False, unique=True)
    is_active = Column(Boolean, nullable=False, default=True, server_default='true')
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, server_default=text('now()'))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False, server_default=text('now()'))
    
    # Subscription and trial (onboarding gating Step 1)
    # subscription_status: 'Trial' | 'Active' | 'Paywalled'
    subscription_status = Column(String, nullable=False, server_default=text("'Trial'"))
    trial_requirements_runs_remaining = Column(Integer, nullable=False, server_default=text("3"))
    trial_testplan_runs_remaining = Column(Integer, nullable=False, server_default=text("3"))
    trial_writeback_runs_remaining = Column(Integer, nullable=False, server_default=text("3"))
    
    # Relationship to tenant users
    users = relationship("TenantUser", back_populates="tenant", cascade="all, delete-orphan")


class TenantUser(Base):
    """
    Model for users within a tenant organization.
    Foundation schema for future SaaS onboarding.
    """
    __tablename__ = "tenant_users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    email = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False, default='user', server_default='user')
    is_active = Column(Boolean, nullable=False, default=True, server_default='true')
    
    # Optional fields
    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    address_1 = Column(String, nullable=True)
    address_2 = Column(String, nullable=True)
    city = Column(String, nullable=True)
    state = Column(String, nullable=True)
    zip = Column(String, nullable=True)
    phone = Column(String, nullable=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    
    # Required timestamp fields
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, server_default=text('now()'))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False, server_default=text('now()'))
    
    # Relationship to tenant
    tenant = relationship("Tenant", back_populates="users")
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_tenant_users_tenant_id', 'tenant_id'),
        Index('idx_tenant_users_email', 'email'),
        # Composite unique constraint: email must be unique per tenant
        UniqueConstraint('tenant_id', 'email', name='uq_tenant_users_tenant_email'),
    )


class TenantIntegration(Base):
    """
    Model for storing tenant-specific integration credentials (e.g., Jira).
    Credentials are stored encrypted using Fernet symmetric encryption.
    """
    __tablename__ = "tenant_integrations"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    provider = Column(String, nullable=False)  # e.g., 'jira'
    is_active = Column(Boolean, nullable=False, default=True, server_default='true')
    
    # Jira-specific fields (provider='jira')
    jira_base_url = Column(String, nullable=True)  # NULL if provider != 'jira'
    jira_user_email = Column(String, nullable=True)  # NULL if provider != 'jira'
    
    # Encrypted credentials
    credentials_ciphertext = Column(Text, nullable=False)  # Encrypted API token
    credentials_version = Column(Integer, nullable=False, default=1, server_default='1')
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, server_default=text('now()'))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False, server_default=text('now()'))
    
    # Relationship to tenant
    tenant = relationship("Tenant")
    
    # Indexes and constraints
    __table_args__ = (
        Index('idx_tenant_integrations_tenant_id', 'tenant_id'),
        # Unique constraint: one integration per provider per tenant
        UniqueConstraint('tenant_id', 'provider', name='uq_tenant_integrations_tenant_provider'),
    )


class UsageEvent(Base):
    """
    Model for tracking agent usage for billing and analytics.
    Tenant-scoped usage tracking without storing sensitive data.
    """
    __tablename__ = "usage_events"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("tenant_users.id", ondelete="SET NULL"), nullable=True)
    agent = Column(String, nullable=False)  # e.g., 'requirements_ba', 'test_plan', 'jira_writeback'
    source = Column(String, nullable=False)  # 'jira' | 'text'
    jira_ticket_count = Column(Integer, nullable=False, default=0, server_default='0')
    input_char_count = Column(Integer, nullable=False, default=0, server_default='0')
    success = Column(Boolean, nullable=False, default=False, server_default='false')
    error_code = Column(String, nullable=True)  # Short machine-readable code only
    run_id = Column(String, nullable=True)  # Reference to runs.run_id if applicable
    duration_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, server_default=text('now()'))
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_usage_events_tenant_id', 'tenant_id'),
        Index('idx_usage_events_agent', 'agent'),
        Index('idx_usage_events_created_at', 'created_at'),
    )
