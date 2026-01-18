"""
Status and type enums for the application.
"""
from enum import Enum


class RequirementStatus(str, Enum):
    """Status values for requirements."""
    
    DRAFT = "draft"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    IMPLEMENTED = "implemented"
    ARCHIVED = "archived"


class PriorityLevel(str, Enum):
    """Priority levels for requirements."""
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AnalysisStatus(str, Enum):
    """Status values for analysis operations."""
    
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class RiskLevel(str, Enum):
    """Risk level classifications."""
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class ConfidenceLevel(str, Enum):
    """Confidence levels for LLM analysis."""
    
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class TicketType(str, Enum):
    """Jira ticket types for requirements."""
    
    STORY = "story"
    SUB_TASK = "sub-task"

