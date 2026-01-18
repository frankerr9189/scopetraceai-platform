"""
Core orchestration for the Senior Business Requirement Analyst agent.

This module orchestrates the end-to-end flow from raw input to a validated RequirementPackage.
It coordinates the LLM client and analysis mapper without containing any business logic.
"""
from typing import Optional
from app.models.package import RequirementPackage
from app.services.llm_client import analyze_requirements as llm_analyze, LLMClientError
from app.services.analysis_mapper import map_llm_output_to_package, MappingError
from app.config import settings


class AnalysisError(Exception):
    """Raised when analysis orchestration fails."""
    pass


class BusinessRequirementAnalyst:
    """
    Core agent class for analyzing business requirements.
    
    This class only orchestrates the flow and does not contain business logic or policy.
    """
    
    def __init__(self):
        """Initialize the analyst agent."""
        pass
    
    async def analyze(
        self,
        input_text: str,
        source: Optional[str] = None,
        context: Optional[str] = None,
        attachment_context: Optional[str] = None
    ) -> RequirementPackage:
        """
        Analyze and normalize human-written requirements.
        
        Orchestrates the end-to-end flow:
        1. Calls LLM client to produce intermediate analysis output
        2. Passes intermediate output to analysis mapper
        3. Returns fully validated RequirementPackage
        
        Args:
            input_text: Human-written requirements (e.g., Jira ticket, plain text)
            source: Optional source identifier (e.g., "jira", "email")
            context: Optional additional context for analysis
            attachment_context: Optional extracted text from attachments (read-only context)
            
        Returns:
            RequirementPackage with structured, versioned requirements
            
        Raises:
            AnalysisError: If LLM analysis or mapping fails
        """
        try:
            llm_output = llm_analyze(
                input_text=input_text,
                source=source,
                context=context,
                attachment_context=attachment_context
            )
        except LLMClientError as e:
            raise AnalysisError(f"LLM analysis failed: {str(e)}") from e
        
        try:
            package = map_llm_output_to_package(
                llm_output=llm_output,
                original_input=input_text,
                source=source,
                agent_version=settings.api_version
            )
        except MappingError as e:
            raise AnalysisError(f"Mapping failed: {str(e)}") from e
        
        return package

