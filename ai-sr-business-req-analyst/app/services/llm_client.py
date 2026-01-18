"""
OpenAI LLM client for the AI Sr Business Requirement Analyst.

This module encapsulates all OpenAI API interaction and produces intermediate
analysis output that is advisory only. It does NOT assign IDs, statuses, versions,
or enforce any business logic or validation.
"""
import json
from typing import Optional
from openai import OpenAI, APIError
from pydantic import ValidationError
from app.config import settings
from app.agent.prompt import get_system_prompt, get_analysis_prompt
from app.models.intermediate import LLMAnalysisOutput


class LLMClientError(Exception):
    """Raised when LLM API call or response parsing fails."""
    pass


def analyze_requirements(
    input_text: str,
    source: Optional[str] = None,
    context: Optional[str] = None,
    attachment_context: Optional[str] = None
) -> LLMAnalysisOutput:
    """
    Analyze requirements using OpenAI LLM and return intermediate analysis output.
    
    This function:
    - Sends the input text to OpenAI with the system prompt
    - Requests structured JSON output matching LLMAnalysisOutput schema
    - Parses and validates the response
    - Returns advisory-only analysis output
    
    The output is advisory only and does NOT include:
    - Requirement IDs (assigned by mapper)
    - Statuses (enforced by mapper)
    - Versions (applied by mapper)
    - Final RequirementPackage objects
    
    Args:
        input_text: Raw human-written requirements text to analyze
        source: Optional source identifier (e.g., "jira", "email") for context
        context: Optional additional context to include in system prompt
        attachment_context: Optional extracted text from attachments (read-only context)
        
    Returns:
        LLMAnalysisOutput containing advisory analysis
        
    Raises:
        LLMClientError: If API call fails, response is malformed, or parsing fails
    """
    # Validate API key is configured
    if not settings.openai_api_key:
        raise LLMClientError("OpenAI API key not configured. Set OPENAI_API_KEY environment variable.")
    
    # Get system prompt
    system_prompt = get_system_prompt(context=context)
    
    # Build user message with analysis prompt (include attachment context if provided)
    user_message = get_analysis_prompt(input_text, attachment_context=attachment_context)
    
    # Add JSON schema instruction to ensure structured output
    json_schema_instruction = """

IMPORTANT: You must respond with valid JSON that matches the following structure exactly:
{
    "analysis_summary": {
        "original_intent": "<verbatim original input text>",
        "interpretation_notes": ["<observation 1>", "<observation 2>", ...],
        "requires_human_decision": <true/false>
    },
    "proposed_capabilities": [
        {
            "capability_title": "<title>",
            "description": "<description>",
            "inferred": <true/false>,
            "proposed_requirements": [
                {
                    "summary": "<requirement summary/title>",
                    "description": "<business intent description - what the system must provide, not how it is validated>",
                    "business_requirements": [
                        {
                            "statement": "The system shall <business capability or constraint>.",
                            "inferred": <true/false>
                        }
                    ],
                    "scope_boundaries": {
                        "in_scope": ["<item 1>", "<item 2>", ...],
                        "out_of_scope": ["<item 1>", "<item 2>", ...]
                    },
                    "constraints_policies": ["<constraint 1>", ...] or ["N/A"],
                    "open_questions": ["<question 1>", ...] or ["N/A"],
                    "metadata": {
                        "source_type": "brd | freeform | jira_existing",
                        "enhancement_mode": 0 | 1 | 2 | 3,
                        "enhancement_actions": ["<action 1>", ...],
                        "inferred_content": <true/false>
                    },
                    "gaps": ["<gap 1>", ...],
                    "risks": ["<risk 1>", ...]
                }
            ]
        }
    ],
    "global_gaps": ["<gap 1>", ...],
    "global_risks": [
        {
            "type": "<risk type>",
            "description": "<description>",
            "severity": "<low|medium|high|critical|none>"
        }
    ],
    "confidence": "<low|medium|high>"
}

Do NOT include requirement IDs, statuses, or versions in your response.
These will be assigned by the normalization layer.

SUB-TASK CREATION RULES (DEFAULT: DO NOT CREATE SUB-TASKS):
- Default behavior: Include ONLY ONE proposed_requirement per capability (creates a story ticket)
- Only include multiple proposed_requirements when decomposition is warranted:
  * 2+ distinct Business Requirements that warrant separate implementable units, OR
  * Input explicitly requests multiple tickets/sub-tasks, OR
  * Enhancement mode 3 AND scope is clearly multi-capability
- If a single BR exists, include only ONE proposed_requirement
- Never create a proposed_requirement that duplicates the parent capability's content

CRITICAL BUSINESS REQUIREMENTS RULES (PERMANENTLY LOCKED):
The "statement" field in business_requirements MUST be a declarative business requirement.

1. Declarative Scope Only:
- REQUIRED format: "The system shall <business capability or constraint>."
- Requirements must describe what exists, not how it is validated
- No workflows, no step sequences
- No conditional logic
- No success/failure language
- Each requirement must be atomic (exactly ONE obligation per BR)
- If a statement could be directly turned into a test case, it is NOT allowed

2. ATOMICITY ENFORCEMENT (HARD RULE):
- Each BR must represent exactly ONE obligation ("The system shall <single capability>")
- Do NOT combine multiple obligations into a single BR
- If a BR statement includes "and", "or", commas joining behaviors, or multiple verbs, it MUST be split into separate BRs
- If in_scope contains N distinct obligations, create N separate BRs (one per obligation)
- Example: If in_scope = ["Publishing test plans", "Associating with Jira tickets"], create:
  * BR-001: "The system shall publish test plans to Jira."
  * BR-002: "The system shall associate test plans with Jira tickets."
- Never create one BR that implicitly covers multiple obligations

3. INPUT-BASED ATOMICITY (HARD REQUIREMENT - OVERRIDES ALL ENHANCEMENT MODES):
- If the INPUT TEXT explicitly references multiple system obligations, those obligations
  MUST be represented as separate Business Requirements (BRs), regardless of enhancement_mode (0-3)
- This applies even when enhancement_mode = 1 (Clarify Language) - do NOT collapse obligations
- Examples of explicit multiple obligations:
  * "publish X to Y and associate it with Z" → 2 BRs (publish, associate)
  * "store data and link it to a record" → 2 BRs (store, link)
  * "create a report and attach it to the request" → 2 BRs (create, attach)
  * "generate artifacts and make them visible in Jira" → 2 BRs (generate, make visible)
- This is NOT invention: if the obligation is explicitly stated or clearly implied in the input,
  it must be surfaced as its own BR
- If you cannot confidently separate obligations:
  * Emit separate BRs marked inferred=false, OR
  * Defer with an Open Question explaining the ambiguity (do NOT guess)
- If input text references N obligations, BR count MUST be ≥ N

2. What Business Requirements Are NOT:
- Workflows or user journeys
- Validations or error handling
- Negative scenarios
- UI elements
- Acceptance criteria
- Tests or evidence expectations

3. Scope Boundaries:
- In Scope: Explicitly state what is included
- Out of Scope: Explicitly state what is excluded (capability exclusions only, NOT test/verification terminology)
- Be specific and clear
- FORBIDDEN in out_of_scope: "validation of", "testability", "verification of", "testing of",
  "negative scenarios", "pass/fail", "evidence of", "test execution" (as testing activity),
  "test cases" (in testing context), "Given/When/Then", "test steps"
- ALLOWED: "test plans" as a business artifact (e.g., "Editing test plans", "Publishing test plans")
- ALLOWED: "test execution tracking" (as a business capability)
- CORRECT: "Editing test plans within Jira", "Approval workflows", "Test execution tracking"
- WRONG: "Validation of test plans", "Testability requirements", "Negative test scenarios", "Test execution" (standalone)

4. Enhancement Mode:
- Level 0: Normalize Only (structural formatting only)
- Level 1: Clarify Language (rewrite vague wording, split compound statements)
- Level 2: Surface Implied Scope (add obvious boundaries, implied actors/objects)
- Level 3: Aggressive Enhancement (add defensive exclusions, decompose bundled intent)

5. Golden Rule:
- If unsure whether something is scope or validation, exclude it
- Surface ambiguity as an Open Question

Examples:
- CORRECT: "The system shall authenticate users with valid credentials."
- WRONG: "Given a user provides credentials, when they submit, then they are authenticated."
- WRONG: "The system shall validate user input and display error messages." (contains validation logic)
"""
    
    user_message = user_message + json_schema_instruction
    
    try:
        # Initialize OpenAI client
        client = OpenAI(api_key=settings.openai_api_key)
        
        # Make API call with JSON response mode
        response = client.chat.completions.create(
            model=settings.openai_model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ],
            response_format={"type": "json_object"},
            temperature=0.3  # Lower temperature for more deterministic output
        )
        
        # Extract content from response
        if not response.choices or len(response.choices) == 0:
            raise LLMClientError("OpenAI API returned empty response")
        
        content = response.choices[0].message.content
        if not content:
            raise LLMClientError("OpenAI API returned empty content")
        
        # Parse JSON
        try:
            json_data = json.loads(content)
        except json.JSONDecodeError as e:
            raise LLMClientError(f"Failed to parse JSON response: {str(e)}")
        
        # Parse into LLMAnalysisOutput model (this validates structure)
        try:
            llm_output = LLMAnalysisOutput(**json_data)
        except ValidationError as e:
            raise LLMClientError(
                f"Response does not match LLMAnalysisOutput schema: {str(e)}"
            )
        
        return llm_output
        
    except APIError as e:
        raise LLMClientError(f"OpenAI API error: {str(e)}")
    except Exception as e:
        if isinstance(e, LLMClientError):
            raise
        raise LLMClientError(f"Unexpected error during LLM analysis: {str(e)}")

