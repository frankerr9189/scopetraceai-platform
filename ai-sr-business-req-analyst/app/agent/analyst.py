"""
Core orchestration for the Senior Business Requirement Analyst agent.

This module orchestrates the end-to-end flow from raw input to a validated RequirementPackage.
It coordinates the LLM client and analysis mapper without containing any business logic.
"""
from typing import Optional, List, Tuple
from app.models.package import RequirementPackage
from app.models.requirement import BusinessRequirement
from app.services.llm_client import analyze_requirements as llm_analyze, LLMClientError
from app.services.analysis_mapper import map_llm_output_to_package, MappingError
from app.services.output_guardrails import apply_output_guardrails
from app.services.authoritative_br import extract_authoritative_brs
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
        # Authoritative BR Mode: if input has explicit BRs (e.g. Jira), extract and use when full parse
        authoritative_brs: List[Tuple[str, str]] = []
        extracted_list, marker_count, extracted_count = extract_authoritative_brs(input_text)
        if marker_count > 0 and extracted_count == marker_count:
            authoritative_brs = extracted_list

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

        # Client-facing output guardrails: UI filter, trust/reviewability, metadata
        apply_output_guardrails(package, input_text)

        # When we have authoritative BRs (full extraction), replace first requirement's BRs and preserve original IDs
        if authoritative_brs and package.requirements:
            package.requirements[0].business_requirements = [
                BusinessRequirement(id=br_id, statement=stmt, inferred=False)
                for br_id, stmt in authoritative_brs
            ]

        return package

