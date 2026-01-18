"""
Mapping layer that converts LLM intermediate analysis output into final RequirementPackage artifacts.

This module is responsible for:
- Converting ProposedCapability objects into parent Requirement objects
- Converting ProposedRequirement objects into child Requirement objects
- Assigning deterministic hierarchical requirement IDs
- Enforcing status = IN_REVIEW for all requirements
- Preserving original intent verbatim
- Mapping business requirements and scope boundaries
- Preserving inferred flags
- Mapping requirement-level and global gaps and risks
- Attaching audit metadata
- Validating invariants before returning
"""
from typing import List, Dict, Any, Optional
from datetime import datetime
import re
from app.models.intermediate import (
    LLMAnalysisOutput,
    ProposedCapability,
    ProposedRequirement,
    BusinessRequirementIntermediate,
    ScopeBoundariesIntermediate,
    RequirementMetadataIntermediate,
    GlobalRisk,
)
from app.models.requirement import (
    Requirement,
    BusinessRequirement,
    ScopeBoundaries,
    RequirementMetadata,
)
from app.models.package import RequirementPackage, GapAnalysis, RiskAnalysis
from app.models.enums import RequirementStatus, TicketType
from app.services.numbering import generate_requirement_id, generate_package_id
from app.services.quality_scoring import calculate_quality_scores
from app.validators.invariants import InvariantValidator


class MappingError(Exception):
    """Raised when mapping fails due to validation or invariant violations."""
    pass


def _generate_hierarchical_requirement_id(
    parent_index: int,
    child_index: Optional[int] = None,
    seed: Optional[str] = None
) -> str:
    """
    Generate a deterministic hierarchical requirement ID.
    
    Args:
        parent_index: Zero-based index of the parent requirement
        child_index: Optional zero-based index of the child requirement
        seed: Optional seed for deterministic generation
        
    Returns:
        Hierarchical requirement ID (e.g., "REQ-001" or "REQ-001.1")
    """
    parent_num = str(parent_index + 1).zfill(3)
    parent_id = f"REQ-{parent_num}"
    
    if child_index is not None:
        child_num = str(child_index + 1)
        return f"{parent_id}.{child_num}"
    
    return parent_id


def _generate_br_id(requirement_id: str, index: int) -> str:
    """
    Generate deterministic business requirement ID.
    
    Format: BR-{N} (numbering resets per ticket)
    Examples: BR-001, BR-002, BR-003 (for REQ-001), then BR-001, BR-002 (for REQ-001.1)
    
    Args:
        requirement_id: Parent requirement ID (e.g., REQ-001, REQ-001.1) - not used in ID
        index: Zero-based index of the business requirement (resets per requirement)
        
    Returns:
        Business requirement ID (e.g., BR-001, BR-002)
    """
    br_number = index + 1
    return f"BR-{br_number:03d}"


def _is_ui_orchestration_ticket(
    proposed_req: ProposedRequirement,
    capability: Optional[ProposedCapability] = None
) -> bool:
    """
    Detect if a ticket is a UI orchestration ticket.
    
    A UI orchestration ticket is one whose primary intent is to provide user interface
    inputs, triggers, navigation, or presentation of generated artifacts.
    
    Set ui_orchestration = true when:
    - Primary intent involves UI elements (buttons, tabs, fields, viewers, panels)
    - Displaying generated artifacts (test plans, RTMs, requirements)
    - Triggering actions (e.g., "Generate", "Load", "View") without implementing underlying logic
    - Ticket explicitly excludes backend logic, integrations, validation, or domain rules
    - Obligations are UI triggers or presentation-only concerns
    
    Do NOT set ui_orchestration = true when:
    - Ticket defines business rules, validation, authorization, persistence, or workflows
    - Ticket implements backend behavior or domain logic
    
    Args:
        proposed_req: Proposed requirement to check
        capability: Optional parent capability for context
        
    Returns:
        True if ticket is UI orchestration, False otherwise
    """
    # Collect all text for analysis
    text_parts = [proposed_req.summary.lower(), proposed_req.description.lower()]
    if capability:
        text_parts.append(capability.capability_title.lower())
        text_parts.append(capability.description.lower() if capability.description else "")
    
    combined_text = " ".join(text_parts)
    
    # Criterion 1: Primary intent involves UI elements or displaying generated artifacts
    # More inclusive UI keywords - match common UI orchestration patterns
    ui_keywords = [
        r'\b(?:button|buttons?)\b',
        r'\b(?:tab|tabs?)\b',
        r'\b(?:field|fields?|input|inputs?|text\s+field|url\s+field|raw\s+input)\b',
        r'\b(?:viewer|viewers?|view|views?)\b',
        r'\b(?:display|displays?|show|shows?|render|renders?|present|presents?)\b',
        r'\b(?:layout|control|controls?|panel|panels?|container)\b',
        r'\b(?:ui|user\s+interface|interface|frontend)\b',
        r'\b(?:load|fetch|retrieve|get)\s+(?:from|data|information)\b',
        r'\b(?:generate|generating|trigger|triggering|view|viewing)\s+(?:button|action|control|trigger)\b',
        r'\b(?:test\s+plan|rtm|requirement|requirement|artifact|output)\s+(?:display|view|presentation|viewer|show)\b',
        r'\b(?:json|table|format|raw)\s+(?:view|display|viewer|presentation|format)\b',
        r'\b(?:orchestrat|orchestrating|orchestration)\b',
        r'\b(?:navigate|navigation|group|organize|arrange)\s+(?:output|result|artifact)\b',
    ]
    
    has_ui_keywords = any(re.search(pattern, combined_text) for pattern in ui_keywords)
    if not has_ui_keywords:
        return False
    
    # Criterion 2: Ticket does NOT describe backend logic, business rules, validation, etc.
    # More comprehensive backend exclusion patterns - but exclude UI trigger patterns
    backend_keywords = [
        # Data persistence (exclude UI "load from" which is just a trigger)
        r'\b(?:persist|store|save|delete|update|create|modify)\s+(?:data|record|entity|database|information)\s+(?:to|in|into)\b',
        r'\b(?:business\s+rule|rule\s+enforcement|enforce|enforcement)\s+(?:logic|policy|validation)\b',
        r'\b(?:validate|validates|validation|validated)\s+(?:data|input|rule|business|content)\s+(?:against|using|with)\b',
        r'\b(?:authorize|authorizes|authorization|authorized)\s+(?:user|access|action|request)\s+(?:based|using|against)\b',
        r'\b(?:authenticate|authentication|authenticated)\s+(?:user|request|session)\b',
        r'\b(?:workflow|process|state\s+machine|approval\s+workflow|business\s+process)\s+(?:engine|logic|implementation)\b',
        r'\b(?:api|endpoint|service|backend|server)\s+(?:call|invoke|integrate|implementation|logic)\b',
        r'\b(?:audit|log|logging|compliance|security)\s+(?:enforcement|rule|policy|validation|logic)\b',
        r'\b(?:domain\s+logic|business\s+logic|application\s+logic)\b',
        r'\b(?:implement|implements|implementation)\s+(?:logic|rule|validation|authorization|business)\b',
    ]
    
    # Check scope boundaries for explicit exclusions of backend behavior
    scope_excludes_backend = False
    if proposed_req.scope_boundaries and proposed_req.scope_boundaries.out_of_scope:
        out_of_scope_text = " ".join(proposed_req.scope_boundaries.out_of_scope).lower()
        backend_exclusion_keywords = [
            r'\b(?:integration|integrations?)\b',
            r'\b(?:validation|validating)\b',
            r'\b(?:domain\s+behavior|backend\s+logic|business\s+logic)\b',
        ]
        scope_excludes_backend = any(re.search(pattern, out_of_scope_text) for pattern in backend_exclusion_keywords)
    
    has_backend_keywords = any(re.search(pattern, combined_text) for pattern in backend_keywords)
    if has_backend_keywords and not scope_excludes_backend:
        # If backend keywords found AND scope doesn't explicitly exclude backend, it's not UI-only
        return False
    
    # Criterion 3: Obligations are UI triggers or presentation-only concerns
    # Check BR statements for UI orchestration patterns (more comprehensive)
    if not proposed_req.business_requirements:
        # If no BRs, check if summary/description strongly indicates UI-only
        # Look for explicit UI-only language or UI orchestration patterns
        ui_only_indicators = [
            r'\b(?:only|solely|exclusively)\s+(?:ui|interface|presentation|display)\b',
            r'\b(?:ui\s+only|interface\s+only|presentation\s+only)\b',
            r'\b(?:no\s+backend|no\s+server|no\s+logic|no\s+validation|no\s+integration)\b',
            r'\b(?:orchestrat|orchestrating|orchestration)\s+(?:ui|interface|presentation)\b',
        ]
        if any(re.search(pattern, combined_text) for pattern in ui_only_indicators):
            return True
        # If we have strong UI keywords and scope excludes backend, classify as UI orchestration
        if has_ui_keywords and scope_excludes_backend:
            return True
        return False
    
    # Expanded UI orchestration patterns for BR statements - more inclusive
    ui_orchestration_patterns = [
        r'\b(?:button|tab|field|input|viewer|view|panel|control)\s+(?:to|for|that)\s+',
        r'\b(?:display|show|render|present|view|exhibit)\s+',
        r'\b(?:load|fetch|retrieve|get)\s+(?:from|data|information)\b',
        r'\b(?:navigate|navigation|group|organize|arrange)\s+',
        r'\b(?:provide|provides|enable|enables|allow|allows)\s+(?:user\s+)?(?:interface|ui|control|button|input|field|viewer)\b',
        r'\b(?:generate|trigger|initiate|start|view)\s+(?:button|action|control|trigger)\b',
        r'\b(?:shall|must|will)\s+(?:display|show|present|render|view|provide|enable|allow)\s+(?:.*?)(?:button|field|input|tab|viewer|view|display)\b',
        r'\b(?:test\s+plan|rtm|requirement|requirement|artifact|output)\s+(?:display|view|presentation|viewer|show)\b',
        r'\b(?:orchestrat|orchestrating)\s+(?:output|result|artifact|display)\b',
    ]
    
    ui_orchestration_count = 0
    non_ui_count = 0
    
    for br in proposed_req.business_requirements:
        statement_lower = br.statement.lower()
        
        # Check if BR matches UI orchestration patterns
        if any(re.search(pattern, statement_lower) for pattern in ui_orchestration_patterns):
            ui_orchestration_count += 1
        # Check if BR describes backend logic (exclude from UI orchestration)
        # Use stricter backend patterns for BRs to avoid false positives
        elif any(re.search(pattern, statement_lower) for pattern in [
            r'\b(?:persist|store|save|delete|update|create|modify)\s+(?:data|record|entity|database)\s+(?:to|in|into)\b',
            r'\b(?:validate|validates|validation)\s+(?:data|input|rule|business)\s+(?:against|using|with)\b',
            r'\b(?:authorize|authorizes|authorization)\s+(?:user|access|action)\s+(?:based|using|against)\b',
            r'\b(?:authenticate|authentication)\s+(?:user|request|session)\b',
            r'\b(?:implement|implements|implementation)\s+(?:logic|rule|validation|authorization|business)\b',
        ]):
            non_ui_count += 1
    
    # If we have backend logic BRs, it's not UI orchestration
    if non_ui_count > 0:
        return False
    
    # More permissive classification: If we have UI keywords in summary/description,
    # scope excludes backend OR no backend keywords, and BRs are UI-focused
    if has_ui_keywords and (scope_excludes_backend or not has_backend_keywords):
        # If at least one BR is UI orchestration-oriented, classify as UI orchestration
        if ui_orchestration_count > 0:
            return True
        # If all BRs are UI-focused (even if pattern doesn't match exactly), classify as UI orchestration
        if ui_orchestration_count == 0 and len(proposed_req.business_requirements) > 0:
            # Check if BRs contain UI-related keywords
            ui_keyword_in_brs = any(
                any(keyword in br.statement.lower() for keyword in ['button', 'tab', 'field', 'input', 'display', 'show', 'view', 'viewer', 'load', 'generate', 'trigger'])
                for br in proposed_req.business_requirements
            )
            if ui_keyword_in_brs:
                return True
    
    # If at least 50% of BRs are UI orchestration-oriented, classify as UI orchestration ticket
    if ui_orchestration_count >= len(proposed_req.business_requirements) * 0.5:
        return True
    
    return False


def _consolidate_ui_orchestration_brs(
    intermediate_brs: List[BusinessRequirementIntermediate]
) -> List[BusinessRequirementIntermediate]:
    """
    UI ORCHESTRATION GUARDRAIL: Consolidate fine-grained UI elements into higher-level BRs.
    
    Prevents over-decomposition of UI-only or presentation-oriented tickets into one BR per control
    (buttons, tabs, fields) while preserving BR atomicity at the consolidated level.
    
    Consolidation rules:
    - Group into at most 2-3 higher-level Business Requirements:
      a) Inputs & Triggers (fields, buttons, load actions)
      b) Artifact Presentation & Navigation (tabs, views, grouping)
      c) Optional: Usability / Readability (scrolling, long strings, typography)
    
    Each consolidated BR must still describe a single cohesive business obligation.
    
    Args:
        intermediate_brs: List of intermediate business requirements to consolidate
        
    Returns:
        Consolidated list of intermediate business requirements
    """
    if len(intermediate_brs) < 3:
        # Need at least 3 BRs to consider consolidation
        return intermediate_brs
    
    # Categorize BRs by theme
    inputs_triggers = []
    presentation_navigation = []
    usability_readability = []
    other_brs = []
    
    for br in intermediate_brs:
        statement_lower = br.statement.lower()
        
        # Inputs & Triggers theme
        if any(keyword in statement_lower for keyword in [
            'button', 'field', 'input', 'load from', 'load data', 'fetch from',
            'trigger', 'action', 'submit', 'generate', 'create', 'select'
        ]):
            inputs_triggers.append(br)
        # Presentation & Navigation theme
        elif any(keyword in statement_lower for keyword in [
            'display', 'show', 'render', 'present', 'view', 'viewer',
            'tab', 'tabs', 'navigate', 'navigation', 'group', 'organize', 'layout'
        ]):
            presentation_navigation.append(br)
        # Usability & Readability theme
        elif any(keyword in statement_lower for keyword in [
            'scrollable', 'scroll', 'readable', 'readability', 'typography',
            'long string', 'lengthy', 'large', 'performance'
        ]):
            usability_readability.append(br)
        else:
            other_brs.append(br)
    
    # If we don't have enough UI BRs to consolidate, return original
    ui_br_count = len(inputs_triggers) + len(presentation_navigation) + len(usability_readability)
    if ui_br_count < 3:
        return intermediate_brs
    
    # If we have non-UI BRs, preserve them and only consolidate UI BRs
    consolidated_brs = []
    
    # Consolidate Inputs & Triggers
    if inputs_triggers:
        # Extract common patterns
        actions = []
        for br in inputs_triggers:
            statement_lower = br.statement.lower()
            if 'button' in statement_lower or 'trigger' in statement_lower:
                # Extract action from statement
                action_match = re.search(r'shall\s+(?:provide|enable|support|allow).*?(?:to|for)\s+(\w+)', statement_lower)
                if action_match:
                    actions.append(action_match.group(1))
        
        if len(inputs_triggers) >= 2:
            # Consolidate into single BR
            consolidated_inputs = BusinessRequirementIntermediate(
                statement="The system shall provide user interface inputs and triggers for artifact generation and data loading.",
                inferred=any(br.inferred for br in inputs_triggers)
            )
            consolidated_brs.append(consolidated_inputs)
        else:
            # Keep original if only one
            consolidated_brs.extend(inputs_triggers)
    else:
        # No inputs/triggers to consolidate
        pass
    
    # Consolidate Presentation & Navigation
    if presentation_navigation:
        if len(presentation_navigation) >= 2:
            # Consolidate into single BR
            consolidated_presentation = BusinessRequirementIntermediate(
                statement="The system shall present generated artifacts in organized views with navigation controls.",
                inferred=any(br.inferred for br in presentation_navigation)
            )
            consolidated_brs.append(consolidated_presentation)
        else:
            # Keep original if only one
            consolidated_brs.extend(presentation_navigation)
    
    # Consolidate Usability & Readability (optional - merge with presentation if both exist)
    if usability_readability:
        if len(usability_readability) >= 2:
            # Consolidate into single BR
            consolidated_usability = BusinessRequirementIntermediate(
                statement="The system shall ensure artifact presentation remains usable and readable for large datasets.",
                inferred=any(br.inferred for br in usability_readability)
            )
            consolidated_brs.append(consolidated_usability)
        elif presentation_navigation and len(consolidated_brs) > 0:
            # Merge with presentation if only one usability BR
            # Update the last consolidated BR (presentation) to include usability
            consolidated_brs[-1].statement = "The system shall present generated artifacts in organized views with navigation controls and ensure usability for large datasets."
            consolidated_brs[-1].inferred = consolidated_brs[-1].inferred or any(br.inferred for br in usability_readability)
        else:
            # Keep original if only one and no presentation to merge with
            consolidated_brs.extend(usability_readability)
    
    # Preserve non-UI BRs unchanged
    consolidated_brs.extend(other_brs)
    
    # Safety check: Ensure we have at least 1 BR after consolidation
    if len(consolidated_brs) == 0:
        return intermediate_brs
    
    # Return consolidated BRs (should be 2-3 instead of many)
    return consolidated_brs


def _map_business_requirements(
    intermediate_requirements: List[BusinessRequirementIntermediate],
    requirement_id: str,
    proposed_req: Optional[ProposedRequirement] = None,
    capability: Optional[ProposedCapability] = None
) -> List[BusinessRequirement]:
    """
    Map intermediate business requirements to final business requirements with IDs.
    
    UI ORCHESTRATION GUARDRAIL: If this is a UI orchestration ticket, consolidate
    fine-grained UI elements before mapping to final BRs.
    
    Args:
        intermediate_requirements: List of intermediate business requirements
        requirement_id: Parent requirement ID for generating BR IDs
        proposed_req: Optional proposed requirement for UI orchestration detection
        capability: Optional parent capability for UI orchestration detection
        
    Returns:
        List of final business requirements with deterministic IDs
    """
    # UI ORCHESTRATION GUARDRAIL: Consolidate UI orchestration BRs before mapping
    # This prevents over-decomposition of UI controls into separate BRs
    # Only applies to UI orchestration tickets (UI controls, no backend mutation, presentation-oriented)
    if proposed_req and _is_ui_orchestration_ticket(proposed_req, capability):
        # Consolidate fine-grained UI elements into 2-3 higher-level BRs
        # This preserves BR atomicity at the consolidated level while preventing
        # one BR per UI control (button, tab, field) fragmentation
        # UI ORCHESTRATION GUARDRAIL APPLIED: Consolidating UI orchestration BRs
        # to prevent over-decomposition of UI controls into separate BRs
        intermediate_requirements = _consolidate_ui_orchestration_brs(intermediate_requirements)
    
    return [
        BusinessRequirement(
            id=_generate_br_id(requirement_id, idx),
            statement=req.statement,
            inferred=req.inferred
        )
        for idx, req in enumerate(intermediate_requirements)
    ]


def _collect_inferred_logic(
    capability: ProposedCapability,
    requirement: ProposedRequirement
) -> List[str]:
    """
    Collect all inferred logic from a requirement.
    
    Args:
        capability: Parent capability
        requirement: The requirement
        
    Returns:
        List of inferred logic descriptions
    """
    inferred_items = []
    
    # Check if capability is inferred
    if capability.inferred:
        inferred_items.append(f"Capability '{capability.capability_title}' was inferred")
    
    # Check business requirements for inferred logic
    for br in requirement.business_requirements:
        if br.inferred:
            inferred_items.append(f"Business requirement '{br.statement}' was inferred")
    
    # Check metadata
    if requirement.metadata.inferred_content:
        inferred_items.append("Some content was inferred during enhancement")
    
    return inferred_items


def _map_requirement_risks(risks: List[str]) -> List[str]:
    """
    Map requirement risks to string format.
    
    Args:
        risks: List of risk descriptions
        
    Returns:
        List of risk descriptions
    """
    return risks.copy()


def _map_global_risks(risks: List[GlobalRisk]) -> List[str]:
    """
    Map global risks to string format.
    
    Args:
        risks: List of global risks
        
    Returns:
        List of risk descriptions
    """
    return [
        f"[{risk.type}] {risk.description} (Severity: {risk.severity.value})"
        for risk in risks
    ]


def _should_lock_pattern_a(
    capability: ProposedCapability,
    original_input: str = ""
) -> bool:
    """
    Determine if Pattern A MUST be enforced (hard lock rule).
    
    Pattern A MUST be enforced when ALL of the following are true:
    1. All obligations operate on the same domain object
       (e.g., records, data, access, documents, accounts)
    2. At least one obligation is an enforcement action
       (e.g., restrict, authorize, validate, scan, block)
    3. At least one obligation is a supporting or secondary action
       (e.g., logging, auditing, monitoring, retention)
    4. The input does NOT explicitly request independent delivery
       (no language like "separately", "independently deployable", etc.)
    
    WHEN THESE CONDITIONS ARE MET:
    - Create exactly ONE parent requirement (story)
    - Package all obligations as sub-tasks under that parent
    - Pattern B MUST NOT be used
    - No fallback to flat story generation is allowed
    
    This is a pattern selection gate that overrides all other pattern selection logic.
    
    Args:
        capability: Proposed capability to evaluate
        original_input: Original input text for context
        
    Returns:
        True if Pattern A must be locked/enforced, False otherwise
    """
    # Get proposed requirements from capability
    proposed_reqs = capability.proposed_requirements if capability.proposed_requirements else []
    
    # Need at least 2 proposed requirements to have enforcement + support pattern
    if len(proposed_reqs) < 2:
        return False
    
    # Condition 4: Check if input explicitly requests independent delivery
    # If so, do NOT lock Pattern A
    # Explicit override rule: Only allow additional parent stories if input explicitly states:
    # - "separately"
    # - "independently"
    # - "as a distinct capability"
    # - "as its own deliverable"
    # - "as a separate ticket/story/issue"
    # Absent explicit language, default to sub-tasks only (Pattern A)
    if original_input:
        input_lower = original_input.lower()
        independent_delivery_keywords = [
            r'separately\s+',
            r'independently\s+(?:deployable|deliverable|delivered)',
            r'as\s+a\s+separate\s+',
            r'in\s+a\s+separate\s+',
            r'standalone\s+',
            r'independent\s+delivery',
            r'as\s+a\s+distinct\s+capability',
            r'as\s+its\s+own\s+deliverable',
            r'as\s+its\s+own\s+(?:ticket|story|issue)',
        ]
        if any(re.search(pattern, input_lower) for pattern in independent_delivery_keywords):
            return False
    
    # Collect all text from proposed requirements
    all_text = []
    for req in proposed_reqs:
        req_text = f"{req.summary} {req.description}".lower()
        if req.business_requirements:
            for br in req.business_requirements:
                all_text.append(br.statement.lower())
        all_text.append(req_text)
    
    combined_text = " ".join(all_text)
    
    # Condition 1: Check if all obligations operate on the same domain object
    # Group related domain concepts together
    domain_groups = [
        # Data/Content domain
        ['record', 'records', 'data', 'document', 'documents', 'file', 'files', 'content', 'information'],
        # Access/Identity domain
        ['access', 'account', 'accounts', 'user', 'users', 'identity', 'permission', 'permissions', 'authorization'],
        # Resource domain
        ['resource', 'resources', 'item', 'items', 'entity', 'entities', 'object', 'objects'],
        # Transaction/Request domain
        ['transaction', 'transactions', 'request', 'requests', 'operation', 'operations'],
    ]
    
    # Find which domain group(s) are mentioned
    domains_mentioned = set()
    for group in domain_groups:
        for domain in group:
            if re.search(rf'\b{domain}s?\b', combined_text):
                # Use group index as identifier to group related concepts
                domains_mentioned.add(tuple(group))
                break
    
    # If multiple different domain groups, likely not same domain - don't lock Pattern A
    if len(domains_mentioned) > 1:
        return False
    
    # If no domain object detected, don't lock Pattern A
    if len(domains_mentioned) == 0:
        return False
    
    # Condition 2: Check for enforcement actions
    enforcement_actions = [
        'restrict', 'restricts', 'restriction', 'restricted',
        'authorize', 'authorizes', 'authorization', 'authorized',
        'validate', 'validates', 'validation', 'validated',
        'scan', 'scans', 'scanning', 'scanned',
        'block', 'blocks', 'blocking', 'blocked',
        'deny', 'denies', 'denial', 'denied',
        'enforce', 'enforces', 'enforcement', 'enforced',
        'control', 'controls', 'controlling', 'controlled',
        'limit', 'limits', 'limiting', 'limited',
        'prevent', 'prevents', 'prevention', 'prevented'
    ]
    
    has_enforcement = False
    for action in enforcement_actions:
        if re.search(rf'\b{action}\b', combined_text):
            has_enforcement = True
            break
    
    if not has_enforcement:
        return False
    
    # Condition 3: Check for supporting/secondary actions
    supporting_actions = [
        'log', 'logs', 'logging', 'logged',
        'audit', 'audits', 'auditing', 'audited',
        'monitor', 'monitors', 'monitoring', 'monitored',
        'retain', 'retains', 'retention', 'retained',
        'track', 'tracks', 'tracking', 'tracked',
        'record', 'records', 'recording', 'recorded',
        'store', 'stores', 'storing', 'stored',
        'archive', 'archives', 'archiving', 'archived',
        'notify', 'notifies', 'notification', 'notified',
        'report', 'reports', 'reporting', 'reported'
    ]
    
    has_supporting = False
    for action in supporting_actions:
        if re.search(rf'\b{action}\b', combined_text):
            has_supporting = True
            break
    
    if not has_supporting:
        return False
    
    # ALL conditions met: Lock Pattern A
    return True


def _should_split_into_multiple_stories(
    capability: ProposedCapability,
    original_input: str = ""
) -> bool:
    """
    Determine if a capability should be split into multiple Jira stories.
    
    PATTERN A FINAL AUTHORITY: This function is the ONLY gate for story splitting.
    Multiple obligations/BRs MUST NOT automatically result in multiple stories.
    
    TICKET PACKAGING POLICY (Human Sr BA Behavior):
    
    DEFAULT: ONE story per business capability with MULTIPLE BRs.
    - Multiple obligations → Multiple BRs (atomicity rules)
    - Multiple BRs → Usually ONE story (Pattern A default)
    - Sub-tasks are optional and implementation-driven
    
    SPLIT into MULTIPLE stories ONLY when ALL of the following are true:
    1. Obligations are independently deliverable business capabilities (not just different actions)
    2. Obligations belong to different subsystems or domains (e.g., API vs UI, Auth vs Reporting)
    3. Input explicitly requests separate tickets (e.g., "separately", "as a separate ticket")
    4. Enhancement mode = 3 AND capabilities are clearly distinct (not just multiple actions)
    
    DO NOT split based solely on:
    - Number of obligations detected
    - Number of BRs
    - Number of proposed_requirements
    - Input-based atomicity detection
    
    Args:
        capability: Proposed capability to evaluate
        original_input: Original input text for context
        
    Returns:
        True if should split into multiple stories, False to keep in one story (DEFAULT)
    """
    # Get proposed requirements from capability
    proposed_reqs = capability.proposed_requirements if capability.proposed_requirements else []
    
    # DEFAULT: Keep in one story (Pattern A default behavior)
    # If only one proposed requirement, definitely keep in one story
    if len(proposed_reqs) <= 1:
        return False
    
    # PATTERN A: Multiple proposed_reqs or multiple BRs do NOT automatically mean multiple stories
    # Only split if STRONG criteria are met
    
    # Criterion 1: Input explicitly requests separation
    # This is the strongest signal - user explicitly wants separate tickets
    if original_input:
        input_lower = original_input.lower()
        explicit_separation_keywords = [
            r'separately\s+',
            r'as\s+a\s+separate\s+(?:ticket|story|issue)',
            r'in\s+a\s+separate\s+(?:ticket|story|issue)',
            r'create\s+.*\s+and\s+.*\s+as\s+separate',
            r'separate\s+(?:ticket|story|issue)',
        ]
        if any(re.search(pattern, input_lower) for pattern in explicit_separation_keywords):
            return True
    
    # Criterion 2: Different subsystems or domains (strong technical separation)
    # Check if proposed requirements represent different technical capabilities or subsystems
    summaries = [req.summary.lower().strip() for req in proposed_reqs]
    descriptions = [req.description.lower().strip() for req in proposed_reqs]
    
    # Technical domain keywords that indicate different subsystems
    technical_domains = {
        'api': ['api', 'endpoint', 'service', 'rest', 'graphql'],
        'database': ['database', 'storage', 'persist', 'data layer', 'repository'],
        'ui': ['ui', 'interface', 'frontend', 'user interface', 'display', 'view'],
        'backend': ['backend', 'server', 'service layer', 'business logic'],
        'auth': ['authentication', 'authorization', 'login', 'session', 'security'],
        'reporting': ['report', 'analytics', 'dashboard', 'metrics', 'statistics'],
        'notification': ['notification', 'alert', 'email', 'message', 'push'],
        'workflow': ['workflow', 'process', 'approval', 'state machine'],
    }
    
    # Count distinct technical domains mentioned across all proposed_reqs
    domains_mentioned = set()
    for desc in descriptions:
        for domain, keywords in technical_domains.items():
            if any(keyword in desc for keyword in keywords):
                domains_mentioned.add(domain)
                break
    
    # If 2+ distinct technical domains, likely different subsystems - split
    if len(domains_mentioned) >= 2:
        return True
    
    # Criterion 3: Enhancement mode 3 with clearly distinct capabilities
    # Get enhancement mode from first proposed requirement's metadata
    if proposed_reqs and proposed_reqs[0].metadata:
        enhancement_mode = proposed_reqs[0].metadata.enhancement_mode
        if enhancement_mode == 3:
            # Check if proposed requirements represent clearly distinct business capabilities
            # (not just different actions within the same capability)
            # Look for distinct capability keywords in summaries
            capability_keywords = [
                'authentication', 'authorization', 'reporting', 'notification',
                'upload', 'download', 'storage', 'retrieval', 'search', 'filter'
            ]
            
            capabilities_mentioned = set()
            for summary in summaries:
                for keyword in capability_keywords:
                    if keyword in summary:
                        capabilities_mentioned.add(keyword)
                        break
            
            # If 2+ distinct capabilities AND summaries are very different, likely should split
            unique_summaries_count = len(set(summaries))
            if len(capabilities_mentioned) >= 2 and unique_summaries_count == len(proposed_reqs):
                # Additional check: summaries should be semantically different
                # Simple heuristic: if summaries share < 30% common words, likely different capabilities
                if len(proposed_reqs) >= 2:
                    words1 = set(summaries[0].split())
                    words2 = set(summaries[1].split())
                    common_words = words1 & words2
                    similarity = len(common_words) / max(len(words1), len(words2)) if words1 or words2 else 0
                    if similarity < 0.3:  # Very different summaries
                        return True
    
    # Criterion 4: Independently deliverable (strong business separation)
    # Look for keywords that suggest independent delivery as business capabilities
    independent_delivery_keywords = [
        'standalone', 'independent', 'reusable', 'modular',
        'optional feature', 'can be used without', 'does not require'
    ]
    
    for req in proposed_reqs:
        req_text = f"{req.summary} {req.description}".lower()
        if any(keyword in req_text for keyword in independent_delivery_keywords):
            return True
    
    # DEFAULT: Keep in one story (Pattern A default - obligations are closely related)
    # Multiple obligations → Multiple BRs in ONE story
    # This is the human Sr BA behavior: default to grouping unless strong split criteria
    return False


def _should_group_proposed_requirements(
    req1: ProposedRequirement,
    req2: ProposedRequirement
) -> bool:
    """
    Determine if two proposed requirements should be grouped into a single sub-task.
    
    Pattern A refinement: Prefer ONE sub-task with MULTIPLE BRs when obligations are
    mutually dependent and part of the SAME primary capability.
    
    Group when:
    - One obligation cannot be delivered meaningfully without the others
    - Obligations share the same primary capability (e.g., virus scanning)
    - Obligations are part of the same lifecycle and risk boundary
    
    Split when:
    - Obligations are independently deliverable
    - Obligations belong to different technical capabilities or subsystems
    - Input explicitly requests independent behavior
    
    Args:
        req1: First proposed requirement
        req2: Second proposed requirement
        
    Returns:
        True if should group, False if should split
    """
    # Default to grouping unless strong split criteria are met
    should_split = False
    
    # Extract text for analysis
    text1 = f"{req1.summary} {req1.description}".lower()
    text2 = f"{req2.summary} {req2.description}".lower()
    combined_text = f"{text1} {text2}"
    
    # Check for explicit dependency patterns (group indicators)
    dependency_patterns = [
        # Action-result dependencies
        (r'\b(scan|scanning)\b', r'\b(quarantine|quarantining|isolate|isolating)\b'),
        (r'\b(validate|validation)\b', r'\b(reject|rejection|accept|acceptance)\b'),
        (r'\b(upload|uploading)\b', r'\b(store|storing|save|saving)\b'),
        (r'\b(create|creating)\b', r'\b(associate|associating|link|linking)\b'),
        (r'\b(authenticate|authentication)\b', r'\b(authorize|authorization)\b'),
        (r'\b(retrieve|retrieving)\b', r'\b(display|displaying|show|showing)\b'),
    ]
    
    has_dependency = False
    for pattern1, pattern2 in dependency_patterns:
        if (re.search(pattern1, text1) and re.search(pattern2, text2)) or \
           (re.search(pattern1, text2) and re.search(pattern2, text1)):
            has_dependency = True
            break
    
    # Check for shared primary capability keywords
    capability_keywords = [
        'virus', 'malware', 'security', 'scan', 'quarantine',
        'authentication', 'authorization', 'login', 'session',
        'upload', 'download', 'file', 'document',
        'validation', 'verification', 'approval',
        'notification', 'alert', 'email',
    ]
    
    shared_capability = False
    for keyword in capability_keywords:
        if keyword in text1 and keyword in text2:
            shared_capability = True
            break
    
    # Check for split indicators (strong criteria to split)
    split_indicators = [
        # Different technical subsystems
        (r'\b(api|backend|service)\b', r'\b(ui|frontend|interface|display)\b'),
        (r'\b(database|storage|persist)\b', r'\b(api|service|endpoint)\b'),
        (r'\b(authentication|auth)\b', r'\b(reporting|analytics|dashboard)\b'),
        # Independent delivery keywords
        r'\b(standalone|independent|separate|independently)\b',
        r'\b(can be used without|does not require|optional)\b',
    ]
    
    for indicator in split_indicators:
        if isinstance(indicator, tuple):
            pattern1, pattern2 = indicator
            if (re.search(pattern1, text1) and re.search(pattern2, text2)) or \
               (re.search(pattern1, text2) and re.search(pattern2, text1)):
                should_split = True
                break
        else:
            if re.search(indicator, combined_text):
                should_split = True
                break
    
    # Check if summaries/descriptions are very different (different capabilities)
    summary1_words = set(text1.split())
    summary2_words = set(text2.split())
    # Remove common stop words
    stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'shall', 'must', 'should', 'will', 'can', 'may'}
    summary1_words -= stop_words
    summary2_words -= stop_words
    
    # If summaries share very few words, likely different capabilities
    common_words = summary1_words & summary2_words
    if len(summary1_words) > 0 and len(summary2_words) > 0:
        similarity = len(common_words) / max(len(summary1_words), len(summary2_words))
        if similarity < 0.1:  # Very different
            should_split = True
    
    # Decision: Group if dependency exists or shared capability, unless strong split criteria
    if should_split:
        return False  # Split
    elif has_dependency or shared_capability:
        return True  # Group
    else:
        # Default to grouping (conservative approach)
        return True


def _group_proposed_requirements(
    proposed_requirements: List[ProposedRequirement]
) -> List[List[ProposedRequirement]]:
    """
    Group proposed requirements into sub-task clusters based on capability cohesion.
    
    Pattern A refinement: Groups related obligations into single sub-tasks with multiple BRs.
    Defaults to grouping unless strong split criteria are met.
    
    Args:
        proposed_requirements: List of proposed requirements to group
        
    Returns:
        List of groups, where each group contains proposed_reqs that should be in one sub-task
    """
    if not proposed_requirements or len(proposed_requirements) <= 1:
        return [[req] for req in proposed_requirements] if proposed_requirements else []
    
    groups = []
    remaining = proposed_requirements.copy()
    
    while remaining:
        # Start a new group with the first remaining requirement
        current_group = [remaining.pop(0)]
        
        # Try to add other requirements to this group
        i = 0
        while i < len(remaining):
            req = remaining[i]
            # Check if this req should be grouped with any req in current_group
            should_group = any(
                _should_group_proposed_requirements(group_req, req)
                for group_req in current_group
            )
            
            if should_group:
                current_group.append(remaining.pop(i))
                # Don't increment i since we removed an element
            else:
                i += 1
        
        groups.append(current_group)
    
    return groups


def _meets_decomposition_criteria(
    parent_req: Requirement,
    proposed_requirements: List[ProposedRequirement],
    enhancement_mode: int,
    parent_created_from_first: bool = False
) -> bool:
    """
    Determine if decomposition into sub-tasks is warranted.
    
    Default behavior: Do NOT create sub-tasks unless criteria are met.
    
    Decomposition criteria (any one triggers sub-tasks):
    1) The requirement contains 2+ distinct Business Requirements (BR-###) that cannot reasonably live in a single ticket, OR
    2) The input explicitly requests multiple tickets/sub-tasks (indicated by 2+ proposed_requirements with distinct content), OR
    3) The agent is operating in enhancement_mode 3 AND the scope is clearly multi-capability (not just "and" in a sentence).
    
    Args:
        parent_req: The parent requirement
        proposed_requirements: List of proposed child requirements from LLM
        enhancement_mode: Enhancement mode (0-3)
        parent_created_from_first: Whether parent was created from first proposed_requirement
        
    Returns:
        True if decomposition is warranted, False otherwise
    """
    # If only one proposed_requirement exists and it was used for parent, no decomposition
    if len(proposed_requirements) <= 1:
        return False
    
    # If parent was created from first proposed_requirement, we need 2+ remaining distinct requirements
    remaining_requirements = proposed_requirements[1:] if parent_created_from_first else proposed_requirements
    
    # Need at least 2 distinct proposed_requirements to warrant decomposition
    if len(remaining_requirements) < 1:
        return False
    
    # Criterion 1: Check if parent has 2+ distinct Business Requirements
    if len(parent_req.business_requirements) >= 2:
        # Check if BRs are truly distinct (not just variations)
        br_statements = [br.statement.lower().strip() for br in parent_req.business_requirements]
        # If we have 2+ unique statements, decomposition may be warranted
        if len(set(br_statements)) >= 2:
            return True
    
    # Criterion 2: Check if remaining proposed_requirements have distinct content
    if len(remaining_requirements) >= 1:
        # Check if they have distinct summaries/descriptions from parent and each other
        remaining_summaries = [req.summary.lower().strip() for req in remaining_requirements]
        remaining_descriptions = [req.description.lower().strip() for req in remaining_requirements]
        parent_summary = parent_req.summary.lower().strip()
        parent_description = parent_req.description.lower().strip()
        
        # Check if any remaining requirement is distinct from parent
        distinct_from_parent = any(
            s != parent_summary and d != parent_description 
            for s, d in zip(remaining_summaries, remaining_descriptions)
        )
        
        # Check if remaining requirements are distinct from each other
        distinct_from_each_other = len(set(remaining_summaries)) > 1 or len(set(remaining_descriptions)) > 1
        
        if distinct_from_parent or distinct_from_each_other:
            return True
    
    # Criterion 3: Enhancement mode 3 with multi-capability scope
    if enhancement_mode == 3:
        # Check if scope boundaries indicate multiple capabilities
        if parent_req.scope_boundaries:
            in_scope_items = len(parent_req.scope_boundaries.in_scope)
            # If multiple distinct in-scope items, may warrant decomposition
            if in_scope_items >= 2:
                return True
    
    return False


def _parent_represents_core_obligation(
    parent_req: Requirement
) -> bool:
    """
    Determine if a parent requirement represents a core obligation (not just a structural container).
    
    GUARDRAIL: Prevents parent requirements from losing all BRs when they represent a core obligation
    (e.g., "integrate with vendor API - see attached API specification").
    
    A parent is NOT purely structural if it has:
    - A core obligation in its description or summary (not just container language)
    - Scope boundaries, gaps, risks, or ambiguities that apply to the parent
    - Referenced attachments that support (but do not define) the obligation
    
    Args:
        parent_req: Parent requirement to check
        
    Returns:
        True if parent represents a core obligation, False if it's purely structural
    """
    # Check 1: Core obligation in description or summary
    # Look for action verbs and capability language, not just container/structural language
    description_lower = parent_req.description.lower()
    summary_lower = parent_req.summary.lower()
    combined_text = f"{summary_lower} {description_lower}"
    
    # Structural/container language patterns (indicates pure container)
    structural_patterns = [
        r'\b(?:container|wrapper|grouping|organizing|managing)\s+(?:of|for)',
        r'\b(?:collection|set|group)\s+(?:of|for)',
        r'\b(?:parent|parent\s+story|parent\s+requirement)\s+(?:for|of)',
        r'\b(?:capability|feature)\s+(?:container|wrapper)',
    ]
    
    # Core obligation language patterns (indicates actual obligation)
    obligation_patterns = [
        r'\b(?:shall|must|will|should)\s+(?:provide|enable|support|allow|integrate|implement|deliver)',
        r'\b(?:integrate|implement|deliver|provide|enable|support|allow|create|build)',
        r'\b(?:see|refer|reference|attached|attachment|specification|document|api\s+spec)',
        r'\b(?:api|service|system|platform)\s+(?:integration|implementation|delivery)',
    ]
    
    # Check if text contains obligation language (not just structural)
    has_obligation_language = any(re.search(pattern, combined_text) for pattern in obligation_patterns)
    has_only_structural_language = any(re.search(pattern, combined_text) for pattern in structural_patterns) and not has_obligation_language
    
    if has_obligation_language and not has_only_structural_language:
        return True
    
    # Check 2: Scope boundaries, gaps, risks, or ambiguities that apply to the parent
    # If parent has non-empty scope, gaps, risks, or ambiguities, it likely represents a core obligation
    has_scope = (
        parent_req.scope_boundaries and
        (parent_req.scope_boundaries.in_scope or parent_req.scope_boundaries.out_of_scope)
    )
    has_gaps = parent_req.gaps and len(parent_req.gaps) > 0
    has_risks = parent_req.risks and len(parent_req.risks) > 0
    has_ambiguities = parent_req.ambiguities and len(parent_req.ambiguities) > 0
    
    if has_scope or has_gaps or has_risks or has_ambiguities:
        return True
    
    # Check 3: Referenced attachments (attachments are read-only context, but their presence
    # may indicate the parent has a core obligation that references supporting materials)
    # Check if description/summary references attachments (e.g., "see attached API specification")
    attachment_reference_patterns = [
        r'\b(?:see|refer|reference)\s+(?:attached|attachment|specification|document|api\s+spec)',
        r'\b(?:see\s+attached|see\s+attachment|see\s+specification|see\s+document)',
        r'\b(?:attached|attachment)\s+(?:specification|document|api|spec)',
    ]
    if any(re.search(pattern, combined_text) for pattern in attachment_reference_patterns):
        # Parent references attachments - this suggests it has a core obligation
        # (attachments are supporting materials, not the obligation itself)
        return True
    
    # Default: If none of the above, parent is purely structural
    return False


def _child_duplicates_parent(
    parent_req: Requirement,
    child_req: Requirement
) -> bool:
    """
    Check if a child requirement duplicates parent content.
    
    Hard rule: Never create a child requirement that duplicates parent 
    summary/description/BRs/scope/open_questions.
    
    Args:
        parent_req: Parent requirement
        child_req: Child requirement to check
        
    Returns:
        True if child duplicates parent, False otherwise
    """
    # Check summary
    if parent_req.summary.lower().strip() == child_req.summary.lower().strip():
        return True
    
    # Check description (allow for minor variations)
    parent_desc = parent_req.description.lower().strip()
    child_desc = child_req.description.lower().strip()
    if parent_desc == child_desc or (len(parent_desc) > 20 and child_desc.startswith(parent_desc[:20])):
        return True
    
    # Check business requirements
    parent_brs = {br.statement.lower().strip() for br in parent_req.business_requirements}
    child_brs = {br.statement.lower().strip() for br in child_req.business_requirements}
    if parent_brs == child_brs:
        return True
    
    # Check scope boundaries
    if parent_req.scope_boundaries and child_req.scope_boundaries:
        parent_in_scope = set(s.lower().strip() for s in parent_req.scope_boundaries.in_scope)
        child_in_scope = set(s.lower().strip() for s in child_req.scope_boundaries.in_scope)
        if parent_in_scope == child_in_scope:
            # Also check out_of_scope
            parent_out_scope = set(s.lower().strip() for s in parent_req.scope_boundaries.out_of_scope)
            child_out_scope = set(s.lower().strip() for s in child_req.scope_boundaries.out_of_scope)
            if parent_out_scope == child_out_scope:
                return True
    
    # Check open questions
    parent_questions = set(q.lower().strip() for q in parent_req.open_questions if q != "N/A")
    child_questions = set(q.lower().strip() for q in child_req.open_questions if q != "N/A")
    if parent_questions == child_questions and len(parent_questions) > 0:
        return True
    
    return False


def _sanitize_out_of_scope(requirements: List[Requirement]) -> None:
    """
    Sanitize out_of_scope items to remove test/verification terminology.
    
    Replaces test-oriented phrasing with capability exclusions.
    Example: "Validation of test plans" -> "Editing test plans within Jira"
    
    Args:
        requirements: List of requirements to sanitize
    """
    # Banned test-oriented terms (case-insensitive)
    # NOTE: "test plans" as a business artifact is ALLOWED (e.g., "publish test plans", "test plan editing")
    # Only ban test-oriented phrases in testing/verification contexts
    banned_terms = [
        r'\bvalidation\s+of\s+(?:test\s+)?(?:plans?|cases?|execution)',
        r'\bverification\s+of\s+(?:test\s+)?(?:plans?|cases?|execution)',
        r'\btesting\s+of\s+(?:test\s+)?(?:plans?|cases?|execution)',
        r'\btestability\b',
        r'\btest\s+execution\s+(?:tracking|monitoring|validation|verification)',
        r'\btest\s+cases?\s+(?:execution|validation|verification|testing)',
        r'\bnegative\s+scenarios?\b',
        r'\bpass/fail\b',
        r'\bevidence\s+(?:of|for|that)',
        r'\bRTM\s+(?:generation|creation|validation|verification)',
        r'\bGiven/When/Then\b',
        r'\btest\s+steps?\b',
        # Ban "test execution" when standalone (testing activity)
        r'^\s*test\s+execution\s*$',
        r'\btest\s+execution\s+(?:is|are|must|should|will|can)\s+(?:not\s+)?(?:in|out\s+of)\s+scope',
    ]
    
    # Replacement patterns (map test language to capability exclusions)
    # Only match test-oriented phrases, not legitimate business capabilities
    replacement_map = {
        r'\bvalidation\s+of\s+(.+?)(?:\s+within|\s+in|\s+for|$)': r'Editing \1 within Jira',
        r'\bverification\s+of\s+(.+?)(?:\s+within|\s+in|\s+for|$)': r'Editing \1 within Jira',
        r'\btesting\s+of\s+(.+?)(?:\s+within|\s+in|\s+for|$)': r'Editing \1 within Jira',
        r'\btestability\s+(?:requirements?|criteria)': 'Approval workflows',
        r'\bnegative\s+scenarios?\b': 'Error handling workflows',
    }
    
    # Legitimate business capabilities that should NOT be sanitized
    legitimate_capabilities = [
        r'test\s+plan\s+(?:edit|publish|manage|create|delete|view|display|show|generation|creation)',
        r'test\s+execution\s+tracking',
        r'test\s+execution\s+monitoring',
        r'test\s+case\s+management',
        r'rtm\s+generation',
        r'rtm\s+creation',
        r'publish\s+test\s+plans?',
        r'associate\s+test\s+plans?',
        r'link\s+test\s+plans?',
        r'generate\s+test\s+plans?',
        r'create\s+test\s+plans?',
        r'test\s+plans?\s+(?:to|in|for|with)',
    ]
    
    for req in requirements:
        if not req.scope_boundaries or not req.scope_boundaries.out_of_scope:
            continue
        
        sanitized_items = []
        for item in req.scope_boundaries.out_of_scope:
            if item == "N/A":
                sanitized_items.append(item)
                continue
            
            item_lower = item.lower()
            
            # Check if this is a legitimate business capability (don't sanitize)
            is_legitimate = any(re.search(pattern, item_lower) for pattern in legitimate_capabilities)
            if is_legitimate:
                sanitized_items.append(item)
                continue
            
            # Also check if item already looks sanitized (has "Editing" prefix) - don't double-process
            if item_lower.startswith('editing ') and ('test plan' in item_lower or 'test case' in item_lower):
                # If it already says "Editing X" and X contains test plan/case, it's likely already sanitized
                # But check if it's malformed like "Editing Test plan editing"
                if len(item_lower) > 8 and 'editing' in item_lower[8:]:  # Check after "editing "
                    # Malformed - fix it
                    # Extract what comes after "Editing " and before any second "editing"
                    match = re.search(r'editing\s+(.+?)(?:\s+editing|$)', item_lower)
                    if match:
                        subject = match.group(1).strip()
                        sanitized_item = f"Editing {subject} within Jira"
                    else:
                        sanitized_item = item  # Keep as-is if we can't fix it
                else:
                    sanitized_item = item  # Already properly sanitized
                sanitized_items.append(sanitized_item)
                continue
            
            # Check for banned test-oriented terms
            has_banned_term = any(re.search(pattern, item_lower) for pattern in banned_terms)
            
            if has_banned_term:
                # Try to replace with capability exclusion
                sanitized_item = item
                replaced = False
                
                for pattern, replacement in replacement_map.items():
                    if re.search(pattern, item_lower):
                        sanitized_item = re.sub(pattern, replacement, item, flags=re.IGNORECASE)
                        replaced = True
                        break
                
                # If no replacement found, try to infer capability exclusion
                if not replaced:
                    if 'validation' in item_lower or 'verification' in item_lower:
                        # Try to extract what is being validated
                        match = re.search(r'(?:validation|verification)\s+of\s+(.+?)(?:\s+within|\s+in|\s+for|$)', item_lower)
                        if match:
                            subject = match.group(1).strip()
                            sanitized_item = f"Editing {subject} within Jira"
                        else:
                            sanitized_item = "Approval workflows"
                    elif 'testability' in item_lower:
                        sanitized_item = "Approval workflows"
                    elif 'negative scenario' in item_lower:
                        sanitized_item = "Error handling workflows"
                    elif item_lower.strip() == 'test execution':
                        # Standalone "test execution" is a testing activity, convert to capability
                        sanitized_item = "Test execution tracking"
                    else:
                        # Generic fallback: convert to capability exclusion
                        sanitized_item = "Approval workflows"
                
                sanitized_items.append(sanitized_item)
            else:
                # No banned terms found, keep as-is
                sanitized_items.append(item)
        
        req.scope_boundaries.out_of_scope = sanitized_items


def _is_ui_presentation_br(br: BusinessRequirement) -> bool:
    """
    Determine if a Business Requirement describes UI/presentation qualities only.
    
    UI/presentation BRs include:
    - Display format (JSON, table, tabs)
    - Scrollability
    - Handling long strings
    - Typography
    - Readability
    - Library choices (react-json-view)
    - Performance/readability with large outputs
    
    Args:
        br: BusinessRequirement to check
        
    Returns:
        True if BR describes UI/presentation qualities only, False otherwise
    """
    statement_lower = br.statement.lower()
    
    # UI/presentation keywords (non-exhaustive)
    ui_presentation_keywords = [
        r'\bdisplay\s+(?:format|as|in)\b',
        r'\b(?:json|table|tabs?|view|format)\b',
        r'\bscrollable\b',
        r'\bscroll\b',
        r'\b(?:long|lengthy)\s+strings?\b',
        r'\btypography\b',
        r'\breadable\b',
        r'\breadability\b',
        r'\breact-json-view\b',
        r'\blibrary\s+(?:choice|selection)\b',
        r'\b(?:large|big|huge)\s+outputs?\b',
        r'\b(?:performance|readability)\s+with\s+large\b',
        r'\bpresent\s+(?:in|as|with)\b',
        r'\bshow\s+(?:in|as|with)\b',
        r'\brender\s+(?:in|as|with)\b',
        r'\bformat\s+(?:as|in|with)\b',
    ]
    
    # Check if statement contains UI/presentation keywords
    has_ui_keywords = any(re.search(pattern, statement_lower) for pattern in ui_presentation_keywords)
    
    # Exclude if it contains non-UI system obligations
    non_ui_keywords = [
        r'\b(?:authenticate|authorize|validate|persist|store|save|delete|create|update)\b',
        r'\b(?:security|audit|log|compliance|authorization)\b',
        r'\b(?:integrate|api|service|endpoint)\b',
        r'\b(?:data|record|entity)\s+(?:persist|store|save|delete)\b',
    ]
    
    has_non_ui_keywords = any(re.search(pattern, statement_lower) for pattern in non_ui_keywords)
    
    # If it has UI keywords but no non-UI keywords, it's a UI/presentation BR
    return has_ui_keywords and not has_non_ui_keywords


def _collapse_ui_presentation_brs(requirement: Requirement, all_requirements: List[Requirement]) -> None:
    """
    HUMANIZATION GUARDRAIL: Consolidate UI/presentation-only Business Requirements.
    
    This guardrail reduces BR over-fragmentation for UI/presentation-heavy tickets
    so output reads like a Sr Business Analyst wrote it.
    
    APPLIES ONLY WHEN:
    - The ticket is a SINGLE capability (Pattern B - no sub-tasks)
    - AND BRs describe UI/presentation qualities of the SAME capability
    - AND no BR represents an independently deliverable system capability
    
    RULES:
    1. Preserve atomicity of TRUE system obligations
    2. Prefer 2-3 consolidated BRs over many UI micro-BRs
    3. Consolidation MUST preserve meaning, avoid inventing behavior, avoid removing intent
    4. Excess UI details moved to constraints_policies or quality_notes
    5. NEVER collapse: Security, Data persistence, Authorization, Audit logging, Cross-system integrations
    
    Args:
        requirement: Requirement to process (modified in-place)
        all_requirements: All requirements in package (for context)
    """
    # Only apply to Pattern B (single capability, no sub-tasks)
    if requirement.parent_id is not None:
        # This is a sub-task - skip (Pattern A)
        return
    
    # Check if requirement has sub-tasks (Pattern A)
    has_children = any(child.parent_id == requirement.id for child in all_requirements)
    if has_children:
        # Pattern A - skip consolidation
        return
    
    # Only apply if requirement has multiple BRs
    if not requirement.business_requirements or len(requirement.business_requirements) < 3:
        # Need at least 3 BRs to consider consolidation
        return
    
    # Identify UI/presentation BRs
    ui_brs = []
    non_ui_brs = []
    
    for br in requirement.business_requirements:
        if _is_ui_presentation_br(br):
            ui_brs.append(br)
        else:
            non_ui_brs.append(br)
    
    # Only consolidate if:
    # 1. At least 3 UI BRs exist
    # 2. All BRs are UI (no non-UI BRs) OR non-UI BRs are minimal (1-2)
    if len(ui_brs) < 3:
        # Not enough UI BRs to consolidate
        return
    
    if len(non_ui_brs) > 2:
        # Too many non-UI BRs - don't consolidate (preserve system obligations)
        return
    
    # Consolidate UI BRs into 2-3 higher-quality BRs
    # Group by theme: format/display, usability/readability, performance
    
    format_brs = []
    usability_brs = []
    performance_brs = []
    other_ui_brs = []
    
    for br in ui_brs:
        statement_lower = br.statement.lower()
        
        # Format/display theme
        if any(keyword in statement_lower for keyword in ['display', 'format', 'json', 'table', 'tabs', 'view', 'show', 'render', 'present']):
            format_brs.append(br)
        # Usability/readability theme
        elif any(keyword in statement_lower for keyword in ['readable', 'readability', 'scrollable', 'scroll', 'typography', 'long string', 'lengthy']):
            usability_brs.append(br)
        # Performance theme
        elif any(keyword in statement_lower for keyword in ['performance', 'large output', 'big output', 'huge output']):
            performance_brs.append(br)
        else:
            other_ui_brs.append(br)
    
    # Create consolidated BRs
    consolidated_brs = []
    ui_details_moved = []  # Track details moved to constraints/notes
    
    # Extract the core capability from requirement description/summary for context
    capability_context = f"{requirement.summary} {requirement.description}".lower()
    output_type = "output"
    if "test plan" in capability_context:
        output_type = "test plan"
    elif "requirement" in capability_context:
        output_type = "requirement"
    elif "data" in capability_context:
        output_type = "data"
    
    # Consolidate format/display BRs
    if format_brs:
        # Extract format details from original BRs
        formats_mentioned = []
        for br in format_brs:
            statement_lower = br.statement.lower()
            if 'json' in statement_lower:
                formats_mentioned.append('JSON')
            if 'table' in statement_lower:
                formats_mentioned.append('table')
            if 'tabs' in statement_lower or 'tab' in statement_lower:
                formats_mentioned.append('tabs')
        
        # Create consolidated BR preserving original intent
        if len(formats_mentioned) >= 2:
            formats_str = ' and '.join(formats_mentioned[:2])  # Limit to 2 formats
            consolidated_format = f"The system shall present the {output_type} in both {formats_str} formats."
        else:
            consolidated_format = f"The system shall present the {output_type} in both raw JSON and human-readable table formats."
        
        consolidated_brs.append(BusinessRequirement(
            id=_generate_br_id(requirement.id, len(consolidated_brs)),
            statement=consolidated_format,
            inferred=any(br.inferred for br in format_brs)
        ))
        # Track details moved
        for br in format_brs:
            if 'react-json-view' in br.statement.lower() or 'library' in br.statement.lower():
                ui_details_moved.append(f"Library choice: {br.statement}")
    
    # Consolidate usability/readability BRs
    if usability_brs:
        # Create consolidated BR
        consolidated_usability = f"The system shall ensure the {output_type} display remains usable and readable for large datasets."
        consolidated_brs.append(BusinessRequirement(
            id=_generate_br_id(requirement.id, len(consolidated_brs)),
            statement=consolidated_usability,
            inferred=any(br.inferred for br in usability_brs)
        ))
        # Track details moved
        for br in usability_brs:
            if 'scrollable' in br.statement.lower() or 'scroll' in br.statement.lower():
                ui_details_moved.append("Scrollable display")
            if 'typography' in br.statement.lower():
                ui_details_moved.append("Typography consistency")
            if 'long string' in br.statement.lower() or 'lengthy' in br.statement.lower():
                ui_details_moved.append("Long string handling")
    
    # Consolidate performance BRs (merge with usability if both exist)
    if performance_brs:
        if usability_brs:
            # Merge performance into usability BR
            consolidated_brs[-1].statement = f"The system shall ensure the {output_type} display remains usable, readable, and performs adequately for large datasets."
            consolidated_brs[-1].inferred = consolidated_brs[-1].inferred or any(br.inferred for br in performance_brs)
        else:
            # Create separate performance BR
            consolidated_performance = f"The system shall ensure the {output_type} display performs adequately with large datasets."
            consolidated_brs.append(BusinessRequirement(
                id=_generate_br_id(requirement.id, len(consolidated_brs)),
                statement=consolidated_performance,
                inferred=any(br.inferred for br in performance_brs)
            ))
        # Track details moved
        for br in performance_brs:
            ui_details_moved.append("Performance with large outputs")
    
    # Add any remaining UI BRs that don't fit themes (preserve them)
    consolidated_brs.extend(other_ui_brs)
    
    # SAFETY CHECK: Ensure we have at least 1 BR after consolidation
    if len(consolidated_brs) == 0:
        # Abort consolidation - keep original BRs
        return
    
    # Replace UI BRs with consolidated BRs
    # Keep non-UI BRs unchanged
    requirement.business_requirements = non_ui_brs + consolidated_brs
    
    # Renumber BRs to maintain sequential IDs
    for idx, br in enumerate(requirement.business_requirements):
        br.id = _generate_br_id(requirement.id, idx)
    
    # Move excess UI details to constraints_policies or quality_notes
    if ui_details_moved:
        # Prefer quality_notes (if available) over constraints_policies
        # For now, add to constraints_policies
        if requirement.constraints_policies == ["N/A"]:
            requirement.constraints_policies = []
        
        # Add UI details as constraints
        for detail in ui_details_moved:
            if detail not in requirement.constraints_policies:
                requirement.constraints_policies.append(detail)
    
    # Log consolidation action in metadata
    if requirement.metadata:
        if not requirement.metadata.enhancement_actions:
            requirement.metadata.enhancement_actions = []
        requirement.metadata.enhancement_actions.append(
            f"Consolidated {len(ui_brs)} UI/presentation BRs into {len(consolidated_brs)} higher-quality BRs"
        )


def _collapse_ui_presentation_brs_for_package(requirements: List[Requirement]) -> None:
    """
    Apply UI/presentation BR consolidation to all Pattern B requirements.
    
    Args:
        requirements: List of all requirements (modified in-place)
    """
    for req in requirements:
        _collapse_ui_presentation_brs(req, requirements)


def _detect_multiple_obligations_in_input(text: str) -> int:
    """
    Detect if input text explicitly references multiple system obligations.
    
    Looks for patterns like:
    - "X and Y" (where X and Y are actions)
    - "X, then Y" or "X, and Y"
    - Multiple action verbs in sequence
    
    Args:
        text: Input text to analyze
        
    Returns:
        Estimated number of distinct obligations (minimum 1)
    """
    if not text or len(text.strip()) < 10:
        return 1
    
    text_lower = text.lower()
    
    # Common patterns indicating multiple obligations
    # Pattern 1: "X and Y" where both are actions
    and_patterns = [
        r'\b(publish|create|generate|store|save|send|associate|link|attach|make|display|show)\s+[^,]+?\s+and\s+(?:it\s+)?(associate|link|attach|make|display|show|publish|create|generate|store|save|send)',
        r'\b(publish|create|generate|store|save|send|associate|link|attach|make|display|show)\s+[^,]+?,\s+(?:and\s+)?(?:it\s+)?(associate|link|attach|make|display|show|publish|create|generate|store|save|send)',
    ]
    
    obligation_count = 1  # Default to 1
    
    for pattern in and_patterns:
        matches = re.findall(pattern, text_lower)
        if matches:
            # Each match represents at least 2 obligations
            obligation_count = max(obligation_count, len(matches) * 2)
    
    # Pattern 2: Count distinct action verbs that suggest separate obligations
    action_verbs = [
        'publish', 'create', 'generate', 'store', 'save', 'send', 'associate',
        'link', 'attach', 'make', 'display', 'show', 'retrieve', 'fetch',
        'update', 'delete', 'validate', 'process', 'transform', 'export'
    ]
    
    verb_count = sum(1 for verb in action_verbs if re.search(rf'\b{verb}[s]?\b', text_lower))
    
    # If we find multiple distinct action verbs, likely multiple obligations
    if verb_count > 1:
        # Check if they're in a compound structure (and/or/comma)
        if re.search(r'\b(and|or|,)\s+', text_lower):
            obligation_count = max(obligation_count, verb_count)
    
    return obligation_count


def _check_br_atomicity(requirements: List[Requirement], original_input: str = "") -> None:
    """
    Check BR atomicity and add open questions if mismatch between obligations and BR count.
    
    IMPORTANT: This function ONLY adds open questions - it does NOT influence story packaging.
    Pattern A packaging decisions are made separately by _should_split_into_multiple_stories().
    Input-based atomicity detection MUST NOT override Pattern A packaging decisions.
    
    UI ORCHESTRATION SUPPRESSION: For UI orchestration tickets, scope-to-BR cardinality checks
    are suppressed because UI elements (buttons, tabs, inputs) are consolidated into fewer
    orchestration-level BRs. Multiple UI affordances do not represent atomic obligations.
    
    Checks both:
    1. Input text for explicit multiple obligations
    2. in_scope items vs BR count (suppressed for UI orchestration tickets)
    
    This is a lightweight post-check that flags potential atomicity issues without modifying BRs.
    If input text or in_scope indicates N obligations but BR count is < N, add an open question.
    
    Args:
        requirements: List of requirements to check
        original_input: Original input text (optional, for input-based atomicity check)
    """
    for req in requirements:
        if not req.scope_boundaries or not req.business_requirements:
            continue
        
        # UI ORCHESTRATION SUPPRESSION: Skip scope-to-BR cardinality checks for UI orchestration tickets
        # UI orchestration tickets consolidate many UI elements into fewer orchestration-level BRs
        # Multiple UI affordances (buttons, tabs, inputs) do not represent atomic obligations
        is_ui_orchestration = req.metadata and req.metadata.ui_orchestration if req.metadata else False
        
        in_scope_items = req.scope_boundaries.in_scope
        br_count = len(req.business_requirements)
        
        # Check 1: Input-based atomicity (HARD REQUIREMENT)
        # If original_input explicitly references multiple obligations, BR count must be >= N
        # This check still applies to UI orchestration tickets (input-based obligations are domain-level)
        if original_input:
            input_obligations = _detect_multiple_obligations_in_input(original_input)
            if input_obligations > 1 and br_count < input_obligations:
                # Add open question about input-based atomicity
                if req.open_questions == ["N/A"]:
                    req.open_questions = []
                input_atomicity_question = (
                    f"Input text appears to reference {input_obligations} distinct system obligations, "
                    f"but only {br_count} business requirement(s) exist. "
                    f"Each explicitly stated obligation in the input must have a corresponding atomic BR. "
                    f"Input text: '{original_input[:100]}{'...' if len(original_input) > 100 else ''}'"
                )
                if input_atomicity_question not in req.open_questions:
                    req.open_questions.append(input_atomicity_question)
        
        # Check 2: in_scope-based atomicity
        # UI ORCHESTRATION SUPPRESSION: Skip this check for UI orchestration tickets
        # UI orchestration tickets consolidate UI elements into fewer BRs - this is expected behavior
        if not is_ui_orchestration:
            # If in_scope has multiple items, check if BR count matches
            if len(in_scope_items) > 1 and br_count < len(in_scope_items):
                # Check if in_scope items are truly distinct
                in_scope_lower = [item.lower().strip() for item in in_scope_items]
                unique_items = len(set(in_scope_lower))
                
                # If we have fewer BRs than distinct in_scope items, flag it
                if unique_items > br_count:
                    # Check if any BR contains compound behaviors
                    has_compound_br = False
                    for br in req.business_requirements:
                        statement_lower = br.statement.lower()
                        # Check for compound patterns
                        compound_patterns = [
                            r'\band\s+(?:the\s+system\s+shall|it\s+shall)',
                            r',\s+(?:and\s+)?(?:the\s+system\s+shall|it\s+shall)',
                            r'\bor\s+(?:the\s+system\s+shall|it\s+shall)',
                        ]
                        if any(re.search(pattern, statement_lower) for pattern in compound_patterns):
                            has_compound_br = True
                            break
                    
                    if has_compound_br or unique_items > br_count:
                        # Add open question about atomicity
                        if req.open_questions == ["N/A"]:
                            req.open_questions = []
                        atomicity_question = (
                            f"Scope boundaries indicate {unique_items} distinct obligations "
                            f"({', '.join(in_scope_items[:3])}{'...' if len(in_scope_items) > 3 else ''}), "
                            f"but only {br_count} business requirement(s) exist. "
                            f"Verify that each distinct obligation has a corresponding atomic BR."
                        )
                        if atomicity_question not in req.open_questions:
                            req.open_questions.append(atomicity_question)
        
        # Also check individual BRs for compound behaviors
        for br in req.business_requirements:
            statement_lower = br.statement.lower()
            # Check for compound patterns that indicate multiple obligations
            compound_patterns = [
                r'\band\s+(?:the\s+system\s+shall|it\s+shall|it\s+must)',
                r',\s+(?:and\s+)?(?:the\s+system\s+shall|it\s+shall|it\s+must)',
            ]
            
            if any(re.search(pattern, statement_lower) for pattern in compound_patterns):
                # Add open question about splitting
                if req.open_questions == ["N/A"]:
                    req.open_questions = []
                split_question = (
                    f"Business requirement '{br.statement}' appears to contain multiple obligations. "
                    f"Consider splitting into separate atomic BRs."
                )
                if split_question not in req.open_questions:
                    req.open_questions.append(split_question)


def _humanize_summary(summary: str) -> str:
    """
    Humanize summary: short, action-oriented, no trailing punctuation.
    
    Examples:
    - "Enable publishing of test plans to Jira." → "Publish test plans to Jira"
    - "The system shall provide user authentication." → "User authentication"
    """
    if not summary or summary == "N/A":
        return summary
    
    # Remove trailing punctuation
    summary = summary.rstrip('.!?')
    
    # Remove robotic prefixes
    robotic_prefixes = [
        r'^enable\s+',
        r'^the\s+system\s+shall\s+',
        r'^the\s+solution\s+shall\s+',
        r'^provide\s+',
        r'^support\s+',
    ]
    
    for pattern in robotic_prefixes:
        summary = re.sub(pattern, '', summary, flags=re.IGNORECASE)
        summary = summary.strip()
    
    # Capitalize first letter
    if summary:
        summary = summary[0].upper() + summary[1:] if len(summary) > 1 else summary.upper()
    
    return summary


def _humanize_description(description: str) -> str:
    """
    Humanize description: 1-2 sentences, business intent first, natural phrasing.
    
    Examples:
    - "The system must provide capability to publish test plans." 
      → "Allow QA teams to publish generated test plans directly to Jira for visibility."
    """
    if not description or description == "N/A":
        return description
    
    # Remove robotic prefixes
    robotic_prefixes = [
        r'^the\s+system\s+(?:must|shall|will|should)\s+provide\s+',
        r'^this\s+requirement\s+(?:must|shall|will|should)\s+',
        r'^the\s+capability\s+(?:must|shall|will|should)\s+',
    ]
    
    for pattern in robotic_prefixes:
        description = re.sub(pattern, '', description, flags=re.IGNORECASE)
        description = description.strip()
    
    # If description is too long, try to condense to 1-2 sentences
    sentences = re.split(r'[.!?]+\s+', description)
    sentences = [s.strip() for s in sentences if s.strip()]
    
    if len(sentences) > 2:
        # Keep first two sentences if they're reasonable length
        description = '. '.join(sentences[:2])
        if not description.endswith('.'):
            description += '.'
    
    # Ensure it starts with business intent (actor/benefit)
    if not any(word in description.lower()[:20] for word in ['allow', 'enable', 'provide', 'support', 'permit']):
        # Try to make it more natural
        if description.lower().startswith('the system'):
            description = re.sub(r'^the\s+system\s+', 'This capability ', description, flags=re.IGNORECASE)
    
    return description


def _humanize_br_statement(statement: str, br_index: int) -> str:
    """
    Humanize business requirement statement: preserve declarative structure but vary phrasing.
    
    Allowed starters (mix naturally):
    - "The system shall…"
    - "The solution shall…"
    - "The platform shall…"
    - "This capability shall…"
    
    IMPORTANT: Must preserve declarative structure and "shall" - only vary the subject.
    
    Args:
        statement: Original BR statement
        br_index: Index of BR (0-based) for variation
    """
    if not statement or statement == "N/A":
        return statement
    
    # Ensure it starts with a declarative phrase
    statement_lower = statement.lower().strip()
    
    # Must preserve "shall" - only vary the subject
    # Variation based on index to avoid repetition (but keep "shall")
    if statement_lower.startswith("the system shall"):
        if br_index % 4 == 1:
            statement = re.sub(r'^the\s+system\s+shall', 'The solution shall', statement, flags=re.IGNORECASE)
        elif br_index % 4 == 2:
            statement = re.sub(r'^the\s+system\s+shall', 'The platform shall', statement, flags=re.IGNORECASE)
        elif br_index % 4 == 3:
            statement = re.sub(r'^the\s+system\s+shall', 'This capability shall', statement, flags=re.IGNORECASE)
    elif statement_lower.startswith("the solution shall"):
        if br_index % 4 == 0:
            statement = re.sub(r'^the\s+solution\s+shall', 'The system shall', statement, flags=re.IGNORECASE)
    elif statement_lower.startswith("the platform shall"):
        if br_index % 4 == 0:
            statement = re.sub(r'^the\s+platform\s+shall', 'The system shall', statement, flags=re.IGNORECASE)
    elif statement_lower.startswith("this capability shall"):
        if br_index % 4 == 0:
            statement = re.sub(r'^this\s+capability\s+shall', 'The system shall', statement, flags=re.IGNORECASE)
    # If it doesn't start with a declarative phrase, ensure it does
    elif not statement_lower.startswith(("the system shall", "the solution shall", "the platform shall", "this capability shall")):
        # Try to add "The system shall" if missing
        if not any(word in statement_lower[:20] for word in ['shall', 'must', 'will']):
            statement = f"The system shall {statement}"
    
    # Ensure proper capitalization
    if statement:
        statement = statement[0].upper() + statement[1:] if len(statement) > 1 else statement.upper()
    
    return statement


def _humanize_scope_item(item: str, is_out_of_scope: bool = False) -> str:
    """
    Humanize scope boundary item: selective, intentional, natural phrasing.
    
    Args:
        item: Original scope item
        is_out_of_scope: Whether this is an out-of-scope item
    """
    if not item or item == "N/A":
        return item
    
    # Remove robotic prefixes
    robotic_prefixes = [
        r'^the\s+system\s+(?:must|shall|will|should)\s+',
        r'^this\s+(?:requirement|capability)\s+(?:must|shall|will|should)\s+',
    ]
    
    for pattern in robotic_prefixes:
        item = re.sub(pattern, '', item, flags=re.IGNORECASE)
        item = item.strip()
    
    # For out-of-scope, ensure it reads as a capability exclusion
    if is_out_of_scope:
        # Remove trailing punctuation
        item = item.rstrip('.!?')
        # Ensure it's phrased as a capability, not an activity
        if item.lower().startswith('no '):
            item = re.sub(r'^no\s+', '', item, flags=re.IGNORECASE)
            item = item.strip()
    
    # Capitalize first letter
    if item:
        item = item[0].upper() + item[1:] if len(item) > 1 else item.upper()
    
    return item


def _humanize_open_question(question: str) -> str:
    """
    Humanize open question: conversational, as a Sr BA would ask stakeholders.
    
    Examples:
    - "What specific information from the test plans needs to be published to Jira?"
      → "What level of detail from the test plan should be posted to the Jira issue?"
    """
    if not question or question == "N/A":
        return question
    
    # Remove robotic/question-like prefixes
    robotic_prefixes = [
        r'^what\s+specific\s+',
        r'^please\s+clarify\s+',
        r'^it\s+is\s+unclear\s+',
    ]
    
    for pattern in robotic_prefixes:
        question = re.sub(pattern, '', question, flags=re.IGNORECASE)
        question = question.strip()
    
    # Ensure it's a question (ends with ?)
    question = question.rstrip('.!')
    if not question.endswith('?'):
        question += '?'
    
    # Make it more conversational
    # Replace formal language with natural phrasing
    replacements = [
        (r'needs?\s+to\s+be', 'should be'),
        (r'is\s+required\s+to', 'should'),
        (r'what\s+information', 'what level of detail'),
        (r'what\s+data', 'what information'),
    ]
    
    for pattern, replacement in replacements:
        question = re.sub(pattern, replacement, question, flags=re.IGNORECASE)
    
    # Capitalize first letter
    if question:
        question = question[0].upper() + question[1:] if len(question) > 1 else question.upper()
    
    return question


def _humanize_requirement(requirement: Requirement) -> None:
    """
    Apply humanization layer to a requirement: refine tone and phrasing while preserving meaning.
    
    This is a style refinement pass that:
    - Makes text read naturally as if authored by a Sr BA
    - Preserves all scope meaning, atomicity, and structure
    - Does NOT change logic, counts, or obligations
    
    Args:
        requirement: Requirement to humanize (modified in-place)
    """
    # Humanize summary
    requirement.summary = _humanize_summary(requirement.summary)
    
    # Humanize description
    requirement.description = _humanize_description(requirement.description)
    
    # Humanize business requirements (with variation)
    for idx, br in enumerate(requirement.business_requirements):
        br.statement = _humanize_br_statement(br.statement, idx)
    
    # Humanize scope boundaries
    if requirement.scope_boundaries:
        requirement.scope_boundaries.in_scope = [
            _humanize_scope_item(item, is_out_of_scope=False)
            for item in requirement.scope_boundaries.in_scope
        ]
        requirement.scope_boundaries.out_of_scope = [
            _humanize_scope_item(item, is_out_of_scope=True)
            for item in requirement.scope_boundaries.out_of_scope
        ]
    
    # Humanize open questions
    if requirement.open_questions:
        requirement.open_questions = [
            _humanize_open_question(q) if q != "N/A" else q
            for q in requirement.open_questions
        ]


def _humanize_requirements(requirements: List[Requirement]) -> None:
    """
    Apply humanization layer to all requirements.
    
    This is the final style refinement pass that makes outputs read naturally
    as if authored by a real Senior Business Analyst, while preserving all
    scope meaning, atomicity, and structure.
    
    Args:
        requirements: List of requirements to humanize (modified in-place)
    """
    for req in requirements:
        _humanize_requirement(req)


def _enforce_ticket_type(requirements: List[Requirement]) -> None:
    """
    Enforce deterministic ticket_type assignment for all requirements.
    
    Rules (NON-NEGOTIABLE):
    - If parent_id == None → ticket_type MUST be "story"
    - If parent_id != None → ticket_type MUST be "sub-task"
    
    This function guarantees correctness regardless of LLM output.
    It auto-corrects any missing or invalid ticket_type values.
    
    Args:
        requirements: List of requirements to enforce ticket_type on
    """
    for req in requirements:
        # Deterministic assignment based on parent_id
        if req.parent_id is None:
            # Parent requirement → must be "story"
            req.ticket_type = TicketType.STORY
        else:
            # Child requirement → must be "sub-task"
            req.ticket_type = TicketType.SUB_TASK


def _create_parent_requirement(
    capability: ProposedCapability,
    parent_id: str,
    original_intent: str,
    llm_output: LLMAnalysisOutput
) -> Requirement:
    """
    Create a parent requirement from a proposed capability.
    
    Args:
        capability: Proposed capability to convert
        parent_id: Assigned parent requirement ID
        original_intent: Original business intent
        llm_output: Full LLM output for context
        
    Returns:
        Parent Requirement object
    """
    # For parent requirements, we create a requirement from the capability
    # When keeping multiple BRs in one story (default), combine all BRs from all proposed_requirements
    if capability.proposed_requirements and len(capability.proposed_requirements) > 0:
        # Use the first proposed requirement as the base
        proposed_req = capability.proposed_requirements[0]
        summary = proposed_req.summary
        description = proposed_req.description
        
        # COMBINE all BRs from all proposed_requirements when keeping in one story
        all_brs = []
        for req in capability.proposed_requirements:
            all_brs.extend(req.business_requirements)
        
        # UI ORCHESTRATION GUARDRAIL: Check if first proposed_req is UI orchestration
        # (used as representative for the capability)
        first_proposed_req = capability.proposed_requirements[0] if capability.proposed_requirements else None
        business_requirements = _map_business_requirements(
            all_brs, 
            parent_id,
            proposed_req=first_proposed_req,
            capability=capability
        )
        
        # Combine scope boundaries (union of all in-scope, intersection of out-of-scope)
        all_in_scope = []
        all_out_of_scope = []
        for req in capability.proposed_requirements:
            if req.scope_boundaries:
                all_in_scope.extend(req.scope_boundaries.in_scope)
                all_out_of_scope.extend(req.scope_boundaries.out_of_scope)
        
        # Deduplicate
        all_in_scope = list(set(all_in_scope))
        all_out_of_scope = list(set(all_out_of_scope))
        
        scope_boundaries = ScopeBoundaries(
            in_scope=all_in_scope if all_in_scope else proposed_req.scope_boundaries.in_scope,
            out_of_scope=all_out_of_scope if all_out_of_scope else proposed_req.scope_boundaries.out_of_scope
        )
        
        # Combine constraints, open questions, gaps
        all_constraints = []
        all_questions = []
        all_gaps_list = []
        for req in capability.proposed_requirements:
            if req.constraints_policies and req.constraints_policies != ["N/A"]:
                all_constraints.extend(req.constraints_policies)
            if req.open_questions and req.open_questions != ["N/A"]:
                all_questions.extend(req.open_questions)
            all_gaps_list.extend(req.gaps)
        
        constraints_policies = all_constraints if all_constraints else (proposed_req.constraints_policies if proposed_req.constraints_policies else ["N/A"])
        open_questions = all_questions if all_questions else (proposed_req.open_questions if proposed_req.open_questions else ["N/A"])
        gaps = list(set(all_gaps_list)) if all_gaps_list else proposed_req.gaps
        
        # Combine risks
        all_risks = []
        for req in capability.proposed_requirements:
            all_risks.extend(req.risks)
        risks = _map_requirement_risks(all_risks) if all_risks else _map_requirement_risks(proposed_req.risks)
        
        # Use metadata from first proposed requirement
        # UI ORCHESTRATION CLASSIFICATION: Classify as UI orchestration if first proposed_req is UI orchestration
        # This flag identifies UI-only or UI-orchestration requirements (UI controls, presentation, no backend mutation)
        is_ui_orchestration = _is_ui_orchestration_ticket(proposed_req, capability) if proposed_req else False
        metadata = RequirementMetadata(
            source_type=proposed_req.metadata.source_type,
            enhancement_mode=proposed_req.metadata.enhancement_mode,
            enhancement_actions=proposed_req.metadata.enhancement_actions,
            inferred_content=any(req.metadata.inferred_content for req in capability.proposed_requirements),
            ui_orchestration=is_ui_orchestration  # UI orchestration: true = primary intent is UI controls/presentation/triggers, no backend logic/validation/persistence
        )
    else:
        # Create synthetic requirement from capability
        summary = capability.capability_title
        description = capability.description
        business_requirements = [
            BusinessRequirement(
                id=_generate_br_id(parent_id, 0),
                statement=capability.description,
                inferred=capability.inferred
            )
        ]
        scope_boundaries = ScopeBoundaries(
            in_scope=[capability.capability_title],
            out_of_scope=[]
        )
        constraints_policies = ["N/A"]
        open_questions = ["N/A"]
        # UI ORCHESTRATION CLASSIFICATION: Synthetic requirements default to false (ambiguous)
        metadata = RequirementMetadata(
            source_type="freeform",
            enhancement_mode=0,
            enhancement_actions=[],
            inferred_content=capability.inferred,
            ui_orchestration=False  # Default: not classified as UI orchestration (ambiguous for synthetic requirements)
        )
        gaps = []
        risks = []
    
    # Collect inferred logic
    inferred_logic = []
    if capability.inferred:
        inferred_logic.append(f"Capability '{capability.capability_title}' was inferred from context")
    
    # Determine ambiguities (open questions that need human confirmation)
    ambiguities = open_questions.copy() if open_questions != ["N/A"] else []
    
    req = Requirement(
        id=parent_id,
        parent_id=None,
        ticket_type=TicketType.STORY,
        summary=summary,
        description=description,
        business_requirements=business_requirements,
        scope_boundaries=scope_boundaries,
        constraints_policies=constraints_policies,
        open_questions=open_questions,
        metadata=metadata,
        inferred_logic=inferred_logic,
        status=RequirementStatus.IN_REVIEW,
        gaps=gaps,
        risks=risks,
        ambiguities=ambiguities,
        original_intent=original_intent,
        created_at=datetime.now()
    )
    
    # Quality scores will be added after all requirements are created
    return req


def _create_child_requirement_pattern_a(
    requirement: ProposedRequirement,
    parent_id: str,
    child_id: str,
    business_requirements: List[BusinessRequirement],
    capability: ProposedCapability,
    original_intent: str,
    llm_output: LLMAnalysisOutput,
    description_override: Optional[str] = None
) -> Requirement:
    """
    Create a child requirement using Pattern A (one or more BRs per sub-task).
    
    Pattern A: Sub-tasks contain atomic BRs, parent has no atomic BRs.
    A sub-task may contain MULTIPLE BRs if they belong to the SAME capability boundary.
    
    Args:
        requirement: Proposed requirement to convert
        parent_id: Parent requirement ID
        child_id: Assigned child requirement ID
        business_requirements: One or more BRs to assign to this sub-task (all from same proposed_req)
        capability: Parent capability for context
        original_intent: Original business intent
        llm_output: Full LLM output for context
        
    Returns:
        Child Requirement object with one or more BRs
    """
    # PATTERN A: Each sub-task must have at least ONE BR
    if len(business_requirements) < 1:
        raise MappingError(
            f"Pattern A requires at least one BR per sub-task, got {len(business_requirements)}"
        )
    
    # Collect inferred logic
    inferred_logic = _collect_inferred_logic(capability, requirement)
    
    # Map risks
    risks = _map_requirement_risks(requirement.risks)
    
    # Map scope boundaries (sub-task owns its atomic scope)
    scope_boundaries = ScopeBoundaries(
        in_scope=requirement.scope_boundaries.in_scope if requirement.scope_boundaries else [],
        out_of_scope=requirement.scope_boundaries.out_of_scope if requirement.scope_boundaries else []
    )
    
    # Map constraints and policies
    constraints_policies = requirement.constraints_policies if requirement.constraints_policies else ["N/A"]
    
    # Map open questions
    open_questions = requirement.open_questions if requirement.open_questions else ["N/A"]
    
    # Map metadata
    # UI ORCHESTRATION CLASSIFICATION: Classify as UI orchestration if requirement is UI orchestration
    # This flag identifies UI-only or UI-orchestration requirements (UI controls, presentation, no backend mutation)
    is_ui_orchestration = _is_ui_orchestration_ticket(requirement, capability) if requirement else False
    metadata = RequirementMetadata(
        source_type=requirement.metadata.source_type,
        enhancement_mode=requirement.metadata.enhancement_mode,
        enhancement_actions=requirement.metadata.enhancement_actions,
        inferred_content=requirement.metadata.inferred_content,
        ui_orchestration=is_ui_orchestration  # UI orchestration: true = primary intent is UI controls/presentation/triggers, no backend logic/validation/persistence
    )
    
    # Determine ambiguities (open questions that need human confirmation)
    ambiguities = open_questions.copy() if open_questions != ["N/A"] else []
    ambiguities.extend(requirement.gaps)
    
    # Use description override if provided (Pattern A: avoid duplicating parent description)
    child_description = description_override if description_override else requirement.description
    
    req = Requirement(
        id=child_id,
        parent_id=parent_id,
        ticket_type=TicketType.SUB_TASK,
        summary=requirement.summary,
        description=child_description,
        business_requirements=business_requirements,
        scope_boundaries=scope_boundaries,
        constraints_policies=constraints_policies,
        open_questions=open_questions,
        metadata=metadata,
        inferred_logic=inferred_logic,
        status=RequirementStatus.IN_REVIEW,
        gaps=requirement.gaps,
        risks=risks,
        ambiguities=ambiguities,
        original_intent=original_intent,
        created_at=datetime.now()
    )
    
    # Quality scores will be added after all requirements are created
    return req


def _create_child_requirement(
    requirement: ProposedRequirement,
    parent_id: str,
    child_id: str,
    capability: ProposedCapability,
    original_intent: str,
    llm_output: LLMAnalysisOutput
) -> Requirement:
    """
    Create a child requirement from a proposed requirement.
    
    Args:
        requirement: Proposed requirement to convert
        parent_id: Parent requirement ID
        child_id: Assigned child requirement ID
        capability: Parent capability for context
        original_intent: Original business intent
        llm_output: Full LLM output for context
        
    Returns:
        Child Requirement object
        
    Raises:
        MappingError: If requirement is missing business requirements
    """
    # Validate business requirements presence
    if not requirement.business_requirements or len(requirement.business_requirements) == 0:
        raise MappingError(
            f"Requirement '{requirement.summary}' is missing business requirements"
        )
    
    # Map business requirements with IDs
    # UI ORCHESTRATION GUARDRAIL: Pass proposed_req and capability for UI orchestration detection
    business_requirements = _map_business_requirements(
        requirement.business_requirements, 
        child_id,
        proposed_req=requirement,
        capability=capability
    )
    
    # Collect inferred logic
    inferred_logic = _collect_inferred_logic(capability, requirement)
    
    # Map risks
    risks = _map_requirement_risks(requirement.risks)
    
    # Map scope boundaries
    scope_boundaries = ScopeBoundaries(
        in_scope=requirement.scope_boundaries.in_scope,
        out_of_scope=requirement.scope_boundaries.out_of_scope
    )
    
    # Map constraints and policies
    constraints_policies = requirement.constraints_policies if requirement.constraints_policies else ["N/A"]
    
    # Map open questions
    open_questions = requirement.open_questions if requirement.open_questions else ["N/A"]
    
    # Map metadata
    # UI ORCHESTRATION CLASSIFICATION: Classify as UI orchestration if requirement is UI orchestration
    # This flag identifies UI-only or UI-orchestration requirements (UI controls, presentation, no backend mutation)
    is_ui_orchestration = _is_ui_orchestration_ticket(requirement, capability) if requirement else False
    metadata = RequirementMetadata(
        source_type=requirement.metadata.source_type,
        enhancement_mode=requirement.metadata.enhancement_mode,
        enhancement_actions=requirement.metadata.enhancement_actions,
        inferred_content=requirement.metadata.inferred_content,
        ui_orchestration=is_ui_orchestration  # UI orchestration: true = primary intent is UI controls/presentation/triggers, no backend logic/validation/persistence
    )
    
    # Determine ambiguities (open questions that need human confirmation)
    ambiguities = open_questions.copy() if open_questions != ["N/A"] else []
    ambiguities.extend(requirement.gaps)
    
    req = Requirement(
        id=child_id,
        parent_id=parent_id,
        ticket_type=TicketType.SUB_TASK,
        summary=requirement.summary,
        description=requirement.description,
        business_requirements=business_requirements,
        scope_boundaries=scope_boundaries,
        constraints_policies=constraints_policies,
        open_questions=open_questions,
        metadata=metadata,
        inferred_logic=inferred_logic,
        status=RequirementStatus.IN_REVIEW,
        gaps=requirement.gaps,
        risks=risks,
        ambiguities=ambiguities,
        original_intent=original_intent,
        created_at=datetime.now()
    )
    
    # Quality scores will be added after all requirements are created
    return req


def map_llm_output_to_package(
    llm_output: LLMAnalysisOutput,
    original_input: str,
    source: Optional[str] = None,
    agent_version: Optional[str] = None
) -> RequirementPackage:
    """
    Map LLM intermediate analysis output to a final RequirementPackage.
    
    This is the main entry point for the mapping layer. It converts the advisory
    LLM output into a structured, validated RequirementPackage ready for review.
    
    Args:
        llm_output: Intermediate LLM analysis output
        original_input: Original human-written requirements input
        source: Optional source identifier (e.g., "jira", "email")
        agent_version: Optional agent version for audit metadata
        
    Returns:
        Fully populated and validated RequirementPackage
        
    Raises:
        MappingError: If mapping fails due to validation errors or invariant violations
    """
    requirements: List[Requirement] = []
    original_intent = llm_output.analysis_summary.original_intent
    
    # Process each capability
    for cap_idx, capability in enumerate(llm_output.proposed_capabilities):
        # PATTERN A FINAL AUTHORITY: Packaging decisions occur AFTER BR atomicity is finalized.
        # Multiple obligations → Multiple BRs (atomicity rules determine BRs only)
        # Multiple BRs → Usually ONE story (Pattern A default)
        
        # HARD PATTERN A LOCK: Check if Pattern A must be enforced BEFORE any other pattern selection
        # This overrides all other pattern selection logic when conditions are met
        # 
        # STRUCTURAL GUARDRAIL: Pattern A is TERMINAL
        # Once Pattern A is selected (locked), it becomes the final and authoritative packaging decision.
        # After Pattern A is chosen, the system must not create additional top-level stories from the same input.
        # All decomposed obligations must be emitted only as sub-tasks under the Pattern A parent story,
        # unless the input explicitly requests separate deliverables.
        #
        # Pattern A represents a human Sr. Business Analyst packaging decision:
        # one capability, one story, decomposed into sub-tasks.
        # Once made, that decision must not be second-guessed by downstream logic.
        pattern_a_locked = _should_lock_pattern_a(
            capability=capability,
            original_input=original_input
        )
        
        if pattern_a_locked:
            # PATTERN A LOCKED: Create exactly ONE parent story with sub-tasks
            # Pattern B MUST NOT be used - no fallback to flat story generation
            # This is IRREVERSIBLE and TERMINAL - once Pattern A is locked, it is FINAL
            # No downstream logic may override this decision
            should_split_stories = False  # Force Pattern A (one story with sub-tasks)
        else:
            # PATTERN A NOT LOCKED: Use normal pattern selection logic
            # _should_split_into_multiple_stories() is the FINAL GATE before story creation.
            # DO NOT create multiple stories solely because multiple obligations were detected.
            should_split_stories = _should_split_into_multiple_stories(
                capability=capability,
                original_input=original_input
            )
        
        if should_split_stories:
            # STRUCTURAL GUARDRAIL: Pattern A is terminal - if Pattern A is locked, block story splitting
            # Once Pattern A is selected, it becomes the final and authoritative packaging decision.
            # No additional top-level stories may be created - all obligations must go to sub-tasks.
            if pattern_a_locked:
                # Pattern A is locked - this is a terminal decision
                # Block story splitting and route all obligations to sub-task creation instead
                # This guardrail ensures Pattern A cannot be overridden by downstream logic
                raise MappingError(
                    f"Pattern A is locked for capability '{capability.capability_title}', "
                    f"but story splitting was attempted. Pattern A is terminal - "
                    f"all obligations must be packaged as sub-tasks under a single parent story."
                )
            
            # SPLIT INTO MULTIPLE STORIES (Pattern B)
            # Create a separate story for each proposed requirement
            # This path is only taken when Pattern A is NOT locked
            proposed_reqs = capability.proposed_requirements if capability.proposed_requirements else []
            
            valid_stories_created = 0
            for req_idx, proposed_req in enumerate(proposed_reqs):
                # Validate that proposed requirement has business requirements
                if not proposed_req.business_requirements or len(proposed_req.business_requirements) == 0:
                    # Skip this proposed requirement if it has no BRs
                    continue
                
                # Validate scope boundaries exist
                if not proposed_req.scope_boundaries:
                    # Skip if scope boundaries are missing
                    continue
                
                story_id = _generate_hierarchical_requirement_id(
                    parent_index=cap_idx * 100 + req_idx,  # Offset to avoid ID conflicts
                    seed=f"{original_intent}_{capability.capability_title}_{proposed_req.summary}"
                )
                
                # Create a story from the proposed requirement
                # Use the proposed requirement's BRs directly
                # UI ORCHESTRATION GUARDRAIL: Pass proposed_req and capability for UI orchestration detection
                story_brs = _map_business_requirements(
                    proposed_req.business_requirements, 
                    story_id,
                    proposed_req=proposed_req,
                    capability=capability
                )
                
                # Collect inferred logic
                inferred_logic = _collect_inferred_logic(capability, proposed_req)
                
                # Map risks
                risks = _map_requirement_risks(proposed_req.risks)
                
                # Map scope boundaries
                scope_boundaries = ScopeBoundaries(
                    in_scope=proposed_req.scope_boundaries.in_scope if proposed_req.scope_boundaries.in_scope else [],
                    out_of_scope=proposed_req.scope_boundaries.out_of_scope if proposed_req.scope_boundaries.out_of_scope else []
                )
                
                # Map constraints and policies
                constraints_policies = proposed_req.constraints_policies if proposed_req.constraints_policies else ["N/A"]
                
                # Map open questions
                open_questions = proposed_req.open_questions if proposed_req.open_questions else ["N/A"]
                
                # Map metadata
                # UI ORCHESTRATION CLASSIFICATION: Classify as UI orchestration if proposed_req is UI orchestration
                # This flag identifies UI-only or UI-orchestration requirements (UI controls, presentation, no backend mutation)
                is_ui_orchestration = _is_ui_orchestration_ticket(proposed_req, capability) if proposed_req else False
                metadata = RequirementMetadata(
                    source_type=proposed_req.metadata.source_type,
                    enhancement_mode=proposed_req.metadata.enhancement_mode,
                    enhancement_actions=proposed_req.metadata.enhancement_actions,
                    inferred_content=proposed_req.metadata.inferred_content,
                    ui_orchestration=is_ui_orchestration  # UI orchestration: true = primary intent is UI controls/presentation/triggers, no backend logic/validation/persistence
                )
                
                # Determine ambiguities
                ambiguities = open_questions.copy() if open_questions != ["N/A"] else []
                ambiguities.extend(proposed_req.gaps)
                
                story = Requirement(
                    id=story_id,
                    parent_id=None,  # Stories have no parent
                    ticket_type=TicketType.STORY,
                    summary=proposed_req.summary,
                    description=proposed_req.description,
                    business_requirements=story_brs,
                    scope_boundaries=scope_boundaries,
                    constraints_policies=constraints_policies,
                    open_questions=open_questions,
                    metadata=metadata,
                    inferred_logic=inferred_logic,
                    status=RequirementStatus.IN_REVIEW,
                    gaps=proposed_req.gaps,
                    risks=risks,
                    ambiguities=ambiguities,
                    original_intent=original_intent,
                    created_at=datetime.now()
                )
                
                requirements.append(story)
                valid_stories_created += 1
            
            # If no valid stories were created from splitting, fall back to default behavior
            if valid_stories_created == 0:
                # Fall back to creating one story with all BRs combined
                parent_id = _generate_hierarchical_requirement_id(
                    parent_index=cap_idx,
                    seed=f"{original_intent}_{capability.capability_title}"
                )
                
                # Create parent requirement from capability (includes all BRs)
                parent_req = _create_parent_requirement(
                    capability=capability,
                    parent_id=parent_id,
                    original_intent=original_intent,
                    llm_output=llm_output
                )
                requirements.append(parent_req)
        else:
            # DEFAULT: KEEP IN ONE STORY WITH MULTIPLE BRs
            parent_id = _generate_hierarchical_requirement_id(
                parent_index=cap_idx,
                seed=f"{original_intent}_{capability.capability_title}"
            )
            
            # Create parent requirement from capability (includes all BRs)
            parent_req = _create_parent_requirement(
                capability=capability,
                parent_id=parent_id,
                original_intent=original_intent,
                llm_output=llm_output
            )
            requirements.append(parent_req)
            
            # Check if parent was created from first proposed_requirement
            parent_created_from_first = (
                capability.proposed_requirements 
                and len(capability.proposed_requirements) > 0
                and capability.proposed_requirements[0].summary == parent_req.summary
            )
            
            # Determine if decomposition into sub-tasks is warranted
            # PATTERN A LOCK: If Pattern A is locked, decomposition is REQUIRED
            if pattern_a_locked:
                # Pattern A locked: Force decomposition - create sub-tasks for all obligations
                should_decompose = True
            else:
                # Default: Do NOT create sub-tasks unless criteria are met
                should_decompose = _meets_decomposition_criteria(
                    parent_req=parent_req,
                    proposed_requirements=capability.proposed_requirements,
                    enhancement_mode=parent_req.metadata.enhancement_mode,
                    parent_created_from_first=parent_created_from_first
                )
            
            # Only create children if decomposition is required or criteria are met
            if should_decompose:
                # PATTERN A: Move atomic BRs from parent to sub-tasks
                # Collect all BRs from parent for distribution to sub-tasks
                parent_brs = parent_req.business_requirements.copy()
                
                # DEFENSIVE GUARD: Do NOT clear parent BRs until we confirm sub-tasks will be created
                # We'll clear them only after at least one sub-task is successfully created
                # This prevents silent BR loss if decomposition fails
                sub_tasks_created = 0
                
                # PATTERN A: Make parent scope high-level (non-atomic)
                # Parent scope should describe capability holistically, not implementation units
                if parent_req.scope_boundaries:
                    # Keep high-level scope, but ensure it's not atomic
                    # If in_scope contains atomic items that will be in sub-tasks, keep only high-level summary
                    # For now, keep scope as-is but it will be refined by ensuring sub-tasks own atomic scope
                    pass
                
                # PATTERN A: Ensure parent description is high-level and doesn't duplicate sub-task descriptions
                # The description should describe the capability holistically
                # Sub-tasks will have their own specific descriptions
                
                # PATTERN A refinement: Group related proposed_reqs into single sub-tasks
                # STRUCTURAL GUARDRAIL: When Pattern A is locked, ALL proposed_requirements must become sub-tasks
                # The parent story is a capability container - it does NOT represent any specific proposed_requirement
                # All obligations must be represented as sub-tasks under the parent
                if pattern_a_locked:
                    # Pattern A locked: ALL proposed_requirements must become sub-tasks
                    # Do NOT skip any - the parent is a capability container, not a specific requirement
                    remaining_proposed_reqs = capability.proposed_requirements if capability.proposed_requirements else []
                else:
                    # Pattern A not locked: Process remaining proposed requirements (skip the first one if it was used for parent)
                    start_idx = 1 if parent_created_from_first else 0
                    remaining_proposed_reqs = capability.proposed_requirements[start_idx:] if start_idx < len(capability.proposed_requirements) else []
                
                # Group proposed requirements by capability cohesion
                proposed_req_groups = _group_proposed_requirements(remaining_proposed_reqs)
                
                child_index = 0
                
                # Process each group as a single sub-task
                for group in proposed_req_groups:
                    if not group:
                        continue
                    
                    # Generate child ID for this sub-task group
                    child_id = _generate_hierarchical_requirement_id(
                        parent_index=cap_idx,
                        child_index=child_index,
                        seed=f"{original_intent}_{capability.capability_title}_{group[0].summary}"
                    )
                    
                    try:
                        # PATTERN A: Grouping is STRUCTURAL ONLY - collect ALL BRs from ALL proposed_reqs AS-IS
                        # DO NOT merge or rewrite BR statements
                        # DO NOT collapse BR identities
                        # Preserve BR atomicity - each BR remains distinct
                        all_group_brs = []
                        all_scope_in = []
                        all_scope_out = []
                        
                        # Use first proposed_req as canonical base (for description, summary, metadata)
                        # This ensures ONE canonical description describing PRIMARY capability only
                        base_req = group[0]
                        
                        # Collect ALL BRs from all proposed_reqs in group (preserve atomicity)
                        for proposed_req in group:
                            if proposed_req.business_requirements and len(proposed_req.business_requirements) > 0:
                                # Map BRs with proper IDs for this child requirement
                                # Each BR maintains its identity - renumbering happens but statements are unchanged
                                # UI ORCHESTRATION GUARDRAIL: Pass proposed_req and capability for UI orchestration detection
                                mapped_brs = _map_business_requirements(
                                    proposed_req.business_requirements, 
                                    child_id,
                                    proposed_req=proposed_req,
                                    capability=capability
                                )
                                all_group_brs.extend(mapped_brs)
                            
                            # Union scope boundaries (DO NOT rewrite scope text)
                            if proposed_req.scope_boundaries:
                                if proposed_req.scope_boundaries.in_scope:
                                    all_scope_in.extend(proposed_req.scope_boundaries.in_scope)
                                if proposed_req.scope_boundaries.out_of_scope:
                                    all_scope_out.extend(proposed_req.scope_boundaries.out_of_scope)
                        
                        # If no BRs in the group, flag and skip
                        if not all_group_brs:
                            if parent_req.open_questions == ["N/A"]:
                                parent_req.open_questions = []
                            group_summaries = ", ".join([req.summary for req in group])
                            parent_req.open_questions.append(
                                f"Proposed requirement group '{group_summaries}' has no business requirements. "
                                f"Sub-task cannot be created without at least one BR."
                            )
                            continue
                        
                        # Use canonical description from first proposed_req (PRIMARY capability only)
                        # DO NOT merge or rewrite descriptions
                        sub_task_description = base_req.description
                        sub_task_summary = base_req.summary
                        
                        # Union scope boundaries (deduplicate but do NOT rewrite)
                        unioned_scope_in = list(set(all_scope_in)) if all_scope_in else (base_req.scope_boundaries.in_scope if base_req.scope_boundaries else [])
                        unioned_scope_out = list(set(all_scope_out)) if all_scope_out else (base_req.scope_boundaries.out_of_scope if base_req.scope_boundaries else [])
                        
                        # Use base_req's other attributes (constraints, questions, gaps, risks)
                        # DO NOT merge - use canonical from first proposed_req
                        # Grouping affects packaging only, not content
                        sub_task_constraints = base_req.constraints_policies if base_req.constraints_policies else ["N/A"]
                        sub_task_questions = base_req.open_questions if base_req.open_questions else ["N/A"]
                        sub_task_gaps = base_req.gaps
                        sub_task_risks = base_req.risks
                        
                        # Ensure sub-task description doesn't duplicate parent verbatim
                        if sub_task_description.lower().strip() == parent_req.description.lower().strip():
                            # If identical, make it more specific based on the first BR
                            if all_group_brs:
                                br_statement = all_group_brs[0].statement
                                if "shall" in br_statement.lower():
                                    sub_task_description = br_statement
                        
                        # Create child with all BRs from the group (Pattern A: sub-task may have multiple BRs from related capabilities)
                        # Use base_req directly (no synthetic ProposedRequirement)
                        # All attributes come from base_req as-is, except scope which will be unioned
                        child_req = _create_child_requirement_pattern_a(
                            requirement=base_req,
                            parent_id=parent_id,
                            child_id=child_id,
                            business_requirements=all_group_brs,
                            capability=capability,
                            original_intent=original_intent,
                            llm_output=llm_output,
                            description_override=sub_task_description
                        )
                        
                        # Override scope boundaries with unioned scope (structural only, no rewriting)
                        # Check if unioned scope differs from base_req scope
                        base_scope_in = set(base_req.scope_boundaries.in_scope) if base_req.scope_boundaries and base_req.scope_boundaries.in_scope else set()
                        base_scope_out = set(base_req.scope_boundaries.out_of_scope) if base_req.scope_boundaries and base_req.scope_boundaries.out_of_scope else set()
                        unioned_scope_in_set = set(unioned_scope_in)
                        unioned_scope_out_set = set(unioned_scope_out)
                        
                        if base_scope_in != unioned_scope_in_set or base_scope_out != unioned_scope_out_set:
                            # Union scope differs - override with unioned scope (no rewriting, just union)
                            child_req.scope_boundaries = ScopeBoundaries(
                                in_scope=unioned_scope_in,
                                out_of_scope=unioned_scope_out
                            )
                        
                        # Hard rule: Never create a child that duplicates parent
                        if _child_duplicates_parent(parent_req, child_req):
                            # Skip this child - it duplicates the parent
                            continue
                        
                        # PATTERN A: Ensure sub-task scope is narrower than parent scope
                        # Sub-task should own atomic scope items
                        if child_req.scope_boundaries and parent_req.scope_boundaries:
                            # Ensure sub-task in_scope is more specific than parent
                            # If sub-task in_scope is identical to parent, make it more specific
                            child_in_scope_set = set(s.lower().strip() for s in child_req.scope_boundaries.in_scope)
                            parent_in_scope_set = set(s.lower().strip() for s in parent_req.scope_boundaries.in_scope)
                            if child_in_scope_set == parent_in_scope_set:
                                # Make sub-task scope more specific based on its BRs
                                if all_group_brs:
                                    br_statement = all_group_brs[0].statement.lower()
                                    # Extract key capability from BR
                                    if "shall" in br_statement:
                                        capability_match = re.search(r'shall\s+(.+?)(?:\.|$)', br_statement)
                                        if capability_match:
                                            capability_text = capability_match.group(1).strip()
                                            # Create more specific scope item
                                            child_req.scope_boundaries.in_scope = [capability_text.capitalize()]
                        
                        requirements.append(child_req)
                        child_index += 1
                        sub_tasks_created += 1
                        
                        # GUARDRAIL: Clear parent BRs only after first sub-task is successfully created
                        # This ensures we don't lose BRs if decomposition fails
                        if sub_tasks_created == 1:
                            # PATTERN A GUARDRAIL: Only clear parent BRs if parent is purely structural
                            # If parent represents a core obligation (e.g., references attachments, has scope/gaps/risks),
                            # retain exactly ONE high-level anchoring BR to represent the primary capability
                            if _parent_represents_core_obligation(parent_req):
                                # Parent represents a core obligation - retain one high-level anchoring BR
                                # This prevents hollow parents that reference attachments but have zero BRs
                                # The retained BR should reflect the primary capability (e.g., "integrate with vendor API")
                                if parent_brs and len(parent_brs) > 0:
                                    # Retain the first/highest-level BR as the anchoring BR
                                    # This BR represents the primary capability, while sub-tasks contain operational details
                                    # Ensure the retained BR has the correct ID (BR-001 for parent)
                                    retained_br = parent_brs[0]
                                    retained_br.id = _generate_br_id(parent_req.id, 0)
                                    parent_req.business_requirements = [retained_br]
                                # If no BRs available, parent remains with zero BRs (should not happen)
                            else:
                                # Parent is purely structural - clear all BRs (Pattern A standard behavior)
                                parent_req.business_requirements = []
                    except MappingError as e:
                        raise MappingError(
                            f"Failed to map requirement group in capability '{capability.capability_title}': {str(e)}"
                        )
                
                # DEFENSIVE GUARD: If no sub-tasks were created, restore BRs to parent
                # This prevents invariant violations where parent has zero BRs and no sub-tasks
                if sub_tasks_created == 0:
                    # No sub-tasks were created - restore BRs to parent
                    # This should not happen in normal flow, but protects against edge cases
                    if not parent_req.business_requirements or len(parent_req.business_requirements) == 0:
                        parent_req.business_requirements = parent_brs
                        
                        # Add open question to flag this issue
                        if parent_req.open_questions == ["N/A"]:
                            parent_req.open_questions = []
                        parent_req.open_questions.append(
                            f"Decomposition was attempted but no sub-tasks were created. "
                            f"Business requirements have been restored to the parent story. "
                            f"This may indicate an issue with proposed requirement grouping or BR assignment."
                        )
                        
                        # If Pattern A was locked, this is a critical error
                        if pattern_a_locked:
                            raise MappingError(
                                f"Pattern A is locked for capability '{capability.capability_title}', "
                                f"but no sub-tasks were created. Pattern A requires at least one sub-task. "
                                f"Parent story has {len(parent_brs)} business requirement(s) that could not be "
                                f"distributed to sub-tasks."
                            )
    
    # Validate hierarchy: ensure all parent_ids reference existing requirements
    req_ids = {req.id for req in requirements}
    for req in requirements:
        if req.parent_id and req.parent_id not in req_ids:
            raise MappingError(
                f"Invalid hierarchy: requirement {req.id} references non-existent parent {req.parent_id}"
            )
    
    # DEFENSIVE GUARD: Final check to prevent parent stories with zero BRs and no sub-tasks
    # This should never happen if mapping logic is correct, but provides a safety net
    for req in requirements:
        if req.parent_id is None:  # This is a parent story
            has_children = any(child.parent_id == req.id for child in requirements)
            has_brs = req.business_requirements and len(req.business_requirements) > 0
            
            # Pattern A: Parent with zero BRs MUST have sub-tasks
            # Non-Pattern-A: Parent MUST have BRs (sub-tasks are optional)
            if not has_brs and not has_children:
                raise MappingError(
                    f"Requirement {req.id}: Parent story has zero business requirements and no sub-tasks. "
                    f"This violates the invariant that parent stories must either have BRs or sub-tasks. "
                    f"Pattern A allows zero BRs only when sub-tasks exist."
                )
    
    # Enforce deterministic ticket_type assignment (post-processing layer)
    # This guarantees correctness regardless of LLM output
    _enforce_ticket_type(requirements)
    
    # Sanitize out_of_scope to remove test/verification terminology
    _sanitize_out_of_scope(requirements)
    
    # Check BR atomicity and flag issues as open questions (POST-PROCESSING ONLY)
    # IMPORTANT: This happens AFTER all packaging decisions are finalized.
    # Pattern A packaging decisions are made by _should_split_into_multiple_stories().
    # This function ONLY adds open questions - it does NOT influence story packaging.
    # Input-based atomicity detection MUST NOT override Pattern A packaging decisions.
    # Pass original_input for input-based atomicity checking (HARD REQUIREMENT for BRs only)
    _check_br_atomicity(requirements, original_input=original_input)
    
    # HUMANIZATION GUARDRAIL: Consolidate UI/presentation-only BRs (Pattern B only)
    # This reduces BR over-fragmentation for UI/presentation-heavy tickets
    # Applies ONLY to Pattern B (single capability, no sub-tasks)
    # Does NOT affect Pattern A behavior or decomposition logic
    _collapse_ui_presentation_brs_for_package(requirements)
    
    # Apply humanization layer (final style refinement pass)
    # This refines tone and phrasing to read naturally as if authored by a Sr BA
    # while preserving all scope meaning, atomicity, and structure
    _humanize_requirements(requirements)
    
    # Build gap analysis
    all_gaps = llm_output.global_gaps.copy()
    missing_info = []
    
    # Collect gaps from requirements
    for req in requirements:
        all_gaps.extend(req.gaps)
        missing_info.extend(req.ambiguities)
        # Also add open questions as missing information
        if req.open_questions and req.open_questions != ["N/A"]:
            missing_info.extend(req.open_questions)
    
    # Add interpretation notes as missing information if human decision required
    if llm_output.analysis_summary.requires_human_decision:
        missing_info.extend(llm_output.analysis_summary.interpretation_notes)
    
    gap_analysis = GapAnalysis(
        gaps=list(set(all_gaps)),  # Deduplicate
        missing_information=list(set(missing_info))  # Deduplicate
    )
    
    # Build risk analysis
    global_risk_strings = _map_global_risks(llm_output.global_risks)
    all_risks = global_risk_strings.copy()
    
    # Collect risks from requirements
    for req in requirements:
        all_risks.extend(req.risks)
    
    # Determine overall risk level
    risk_level = "low"
    if any("critical" in risk.lower() or "high" in risk.lower() for risk in all_risks):
        risk_level = "high"
    elif any("medium" in risk.lower() for risk in all_risks):
        risk_level = "medium"
    
    # Build audit concerns
    audit_concerns = []
    if llm_output.confidence.value == "low":
        audit_concerns.append("Low confidence analysis - requires additional review")
    if any(cap.inferred for cap in llm_output.proposed_capabilities):
        audit_concerns.append("Some capabilities were inferred rather than explicitly stated")
    if any(req.metadata.inferred_content for cap in llm_output.proposed_capabilities for req in cap.proposed_requirements):
        audit_concerns.append("Some content was inferred during enhancement")
    
    risk_analysis = RiskAnalysis(
        risks=list(set(all_risks)),  # Deduplicate
        risk_level=risk_level,
        audit_concerns=audit_concerns
    )
    
    # Generate package ID
    package_id = generate_package_id(
        prefix="PKG",
        seed=f"{original_intent}_{datetime.now().isoformat()}"
    )
    
    # Build audit metadata
    metadata: Dict[str, Any] = {
        "source": source or "unknown",
        "agent_version": agent_version or "0.1.0",
        "confidence": llm_output.confidence.value,
        "requires_human_review": llm_output.analysis_summary.requires_human_decision,
        "mapped_at": datetime.now().isoformat(),
        "interpretation_notes": llm_output.analysis_summary.interpretation_notes
    }
    
    # Create package
    package = RequirementPackage(
        package_id=package_id,
        version="1.0.0",  # Initial version
        requirements=requirements,
        gap_analysis=gap_analysis,
        risk_analysis=risk_analysis,
        original_input=original_input,
        metadata=metadata,
        created_at=datetime.now()
    )
    
    # Validate invariants
    is_valid, violations = InvariantValidator.validate_package(package)
    if not is_valid:
        violation_msg = "; ".join(violations)
        raise MappingError(
            f"Package failed invariant validation: {violation_msg}"
        )
    
    # Add quality scores to all requirements
    for req in requirements:
        quality_data = calculate_quality_scores(req, requirements)
        req.quality_scores = quality_data["quality_scores"]
        if "quality_notes" in quality_data:
            req.quality_notes = quality_data["quality_notes"]
    
    # Validate individual requirements
    for req in requirements:
        is_valid, violations = InvariantValidator.validate(req)
        if not is_valid:
            violation_msg = "; ".join(violations)
            raise MappingError(
                f"Requirement {req.id} failed invariant validation: {violation_msg}"
            )
    
    return package
