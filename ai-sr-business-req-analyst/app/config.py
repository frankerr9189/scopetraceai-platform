"""
Environment configuration and constants.
"""
from typing import Optional
from dotenv import load_dotenv
from pydantic_settings import BaseSettings
import os

# Load environment variables from .env file at module import time
# BUT: Preserve DATABASE_URL and JWT_SECRET if already set (they come from testing agent's .env)
saved_db_url = os.getenv("DATABASE_URL")
saved_jwt_secret = os.getenv("JWT_SECRET")

load_dotenv()

# Restore DATABASE_URL and JWT_SECRET if they were set before (must come from testing agent only)
if saved_db_url:
    os.environ["DATABASE_URL"] = saved_db_url
if saved_jwt_secret:
    os.environ["JWT_SECRET"] = saved_jwt_secret


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # API Configuration
    api_title: str = "AI Senior Business Requirement Analyst"
    api_version: str = "0.1.0"
    
    # OpenAI Configuration
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4o-mini"
    
    # Jira Configuration
    jira_base_url: Optional[str] = None
    jira_email: Optional[str] = None
    jira_api_token: Optional[str] = None
    
    # Application Configuration
    debug: bool = False
    log_level: str = "INFO"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"  # Ignore extra environment variables that aren't defined in the model


# Global settings instance
settings = Settings()

