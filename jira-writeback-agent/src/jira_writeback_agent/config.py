"""
Configuration for Jira Write-Back Agent.
"""
import os
from typing import Optional


class JiraWriteBackConfig:
    """Configuration settings for Jira write-back operations."""
    
    JIRA_BASE_URL: str
    JIRA_USERNAME: str
    JIRA_API_TOKEN: str
    JIRA_ACCEPTANCE_CRITERIA_FIELD_ID: Optional[str] = None
    
    @classmethod
    def from_env(cls) -> "JiraWriteBackConfig":
        """
        Create config from environment variables.
        
        Returns:
            JiraWriteBackConfig instance
            
        Raises:
            ValueError: If required environment variables are missing
        """
        base_url = os.getenv("JIRA_BASE_URL")
        # Support both JIRA_USERNAME and JIRA_EMAIL (common convention)
        username = os.getenv("JIRA_USERNAME") or os.getenv("JIRA_EMAIL")
        api_token = os.getenv("JIRA_API_TOKEN")
        acceptance_criteria_field_id = os.getenv("JIRA_ACCEPTANCE_CRITERIA_FIELD_ID")
        
        if not base_url:
            raise ValueError("JIRA_BASE_URL environment variable is required")
        if not username:
            raise ValueError("JIRA_USERNAME or JIRA_EMAIL environment variable is required")
        if not api_token:
            raise ValueError("JIRA_API_TOKEN environment variable is required")
        
        config = cls()
        config.JIRA_BASE_URL = base_url
        config.JIRA_USERNAME = username
        config.JIRA_API_TOKEN = api_token
        config.JIRA_ACCEPTANCE_CRITERIA_FIELD_ID = acceptance_criteria_field_id
        
        return config

