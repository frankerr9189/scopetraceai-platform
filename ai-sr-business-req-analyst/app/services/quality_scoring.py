"""
Deterministic quality scoring for requirements.

This module provides additive-only scoring that does not modify existing
requirement structure, IDs, or logic. Scores are informational and advisory.
"""
import re
from typing import Dict, List, Optional, Any
from app.models.requirement import Requirement, BusinessRequirement


def _has_actor(description: str, summary: str) -> bool:
    """Check if requirement has an actor specified."""
    text = f"{summary} {description}".lower()
    # Common actor patterns
    actor_patterns = [
        r'\b(user|users|actor|person|admin|administrator|system|developer|tester)\b',
        r'\b(they|he|she|it)\b',
        r'\b(who|whom)\b',
    ]
    return any(re.search(pattern, text) for pattern in actor_patterns)


def _has_action_verb(description: str, summary: str) -> bool:
    """Check if requirement has an action verb."""
    text = f"{summary} {description}".lower()
    # Common action verbs
    action_verbs = [
        'create', 'update', 'delete', 'view', 'display', 'show', 'edit',
        'modify', 'save', 'submit', 'send', 'receive', 'process', 'validate',
        'authenticate', 'authorize', 'login', 'logout', 'register', 'reset',
        'search', 'filter', 'sort', 'export', 'import', 'download', 'upload',
        'navigate', 'access', 'perform', 'execute', 'run', 'trigger', 'activate',
        'deactivate', 'enable', 'disable', 'configure', 'set', 'get', 'retrieve',
        'fetch', 'load', 'store', 'manage', 'handle', 'generate'
    ]
    # Check for action verbs as whole words
    for verb in action_verbs:
        if re.search(rf'\b{verb}\b', text):
            return True
    return False


def _has_outcome(description: str) -> bool:
    """Check if requirement specifies an expected outcome."""
    text = description.lower()
    # Outcome indicators
    outcome_patterns = [
        r'\b(should|must|will|shall|can|may)\s+(be|have|do|get|receive|see|view)',
        r'\b(expected|result|outcome|effect|consequence)',
        r'\b(then|after|finally|resulting)',
    ]
    return any(re.search(pattern, text) for pattern in outcome_patterns)


def _has_vague_language(description: str, summary: str) -> bool:
    """Check for vague language patterns."""
    text = f"{summary} {description}".lower()
    vague_patterns = [
        r'\b(should|appropriate|etc|etc\.|and so on|and the like)\b',
        r'\b(properly|correctly|adequately|sufficiently|appropriately)\b',
        r'\b(as needed|as required|when necessary|if applicable)\b',
    ]
    return any(re.search(pattern, text) for pattern in vague_patterns)


def _has_multiple_behaviors(description: str) -> bool:
    """Check if requirement combines multiple behaviors."""
    text = description.lower()
    # Indicators of multiple behaviors
    connectors = [' and ', ' also ', ' plus ', ' additionally ', ' furthermore ', ' moreover ']
    # Check for connector words between actions
    has_connectors = any(conn in text for conn in connectors)
    # Count distinct action verbs (simple heuristic)
    action_verbs = [
        'create', 'update', 'delete', 'view', 'display', 'show', 'edit',
        'modify', 'save', 'submit', 'send', 'receive', 'process', 'validate',
        'authenticate', 'authorize', 'login', 'logout', 'register', 'reset',
        'search', 'filter', 'sort', 'export', 'import', 'download', 'upload',
        'navigate', 'access', 'perform', 'execute', 'run', 'trigger', 'activate',
        'deactivate', 'enable', 'disable', 'configure', 'set', 'get', 'retrieve',
        'fetch', 'load', 'store', 'manage', 'handle', 'generate'
    ]
    action_verb_count = sum(1 for verb in action_verbs if re.search(rf'\b{verb}\b', text))
    return action_verb_count > 1 or has_connectors


def _has_observable_result(description: str) -> bool:
    """Check if requirement has observable result."""
    text = description.lower()
    observable_patterns = [
        r'\b(observable|visible|displayed|shown|presented|rendered)',
        r'\b(result|outcome|effect|consequence|output)',
        r'\b(see|view|display|show|present)',
    ]
    return any(re.search(pattern, text) for pattern in observable_patterns)


def _has_external_dependency(description: str, gaps: List[str]) -> bool:
    """Check if requirement has undefined external dependency."""
    text = f"{description} {' '.join(gaps)}".lower()
    dependency_patterns = [
        r'\b(depends? on|requires?|needs?|uses?|calls?|invokes?)\s+(?:an?|the|external|third.?party|other)',
        r'\b(api|service|system|component|module|library|framework)\s+(?:is|are|must|should)\s+(?:not|un)?defined',
    ]
    return any(re.search(pattern, text) for pattern in dependency_patterns)


def _has_unbounded_time_conditional(description: str) -> bool:
    """Check for unbounded time or conditional logic."""
    text = description.lower()
    unbounded_patterns = [
        r'\b(when|if|after|before|during|while)\s+(?:.*?)\s+(?:then|do|perform)',
        r'\b(time|timing|duration|interval|period|schedule|delay)\s+(?:is|are|must|should)\s+(?:not|un)?(?:specified|defined|bounded)',
    ]
    return any(re.search(pattern, text) for pattern in unbounded_patterns)


def _has_multiple_capabilities(summary: str, description: str) -> bool:
    """Check if requirement combines multiple capabilities."""
    text = f"{summary} {description}".lower()
    # Check for capability connectors
    capability_connectors = [' and ', ' & ', ' plus ', ' along with ', ' combined with ']
    # Check for multiple distinct actions that suggest different capabilities
    distinct_capability_indicators = [
        ('register', 'login'),
        ('create', 'update'),
        ('view', 'edit'),
        ('authenticate', 'authorize'),
    ]
    has_connector = any(conn in text for conn in capability_connectors)
    has_multiple_caps = any(
        all(indicator in text for indicator in pair)
        for pair in distinct_capability_indicators
    )
    return has_connector or has_multiple_caps


def _crosses_parent_boundary(requirement: Requirement, all_requirements: List[Requirement]) -> bool:
    """Check if requirement crosses into another parent requirement's scope."""
    if not requirement.parent_id:
        return False
    
    # Get parent requirement
    parent = next((r for r in all_requirements if r.id == requirement.parent_id), None)
    if not parent:
        return False
    
    # Get other parent requirements
    other_parents = [r for r in all_requirements if r.parent_id is None and r.id != parent.id]
    
    # Check if requirement description references other parent capabilities
    req_text = f"{requirement.summary} {requirement.description}".lower()
    for other_parent in other_parents:
        parent_keywords = other_parent.summary.lower().split()
        # Check if requirement mentions keywords from other parent
        if any(keyword in req_text for keyword in parent_keywords if len(keyword) > 3):
            return True
    
    return False


def _mixes_error_handling(description: str, summary: str) -> bool:
    """Check if requirement mixes error handling with core behavior."""
    text = f"{summary} {description}".lower()
    error_keywords = ['error', 'exception', 'failure', 'invalid', 'reject', 'deny', 'fail']
    core_behavior_keywords = ['create', 'update', 'view', 'display', 'process', 'submit']
    
    has_error = any(keyword in text for keyword in error_keywords)
    has_core = any(keyword in text for keyword in core_behavior_keywords)
    
    return has_error and has_core


def _references_unrelated_system_areas(description: str) -> bool:
    """Check if requirement references unrelated system areas."""
    text = description.lower()
    # Common system area keywords
    system_areas = [
        'database', 'api', 'ui', 'frontend', 'backend', 'service', 'component',
        'module', 'layer', 'tier', 'architecture', 'infrastructure'
    ]
    # Count distinct system areas mentioned
    mentioned_areas = [area for area in system_areas if area in text]
    return len(mentioned_areas) > 1


def _has_scope_text_misalignment(requirement: Requirement) -> bool:
    """
    Detect if edited text fields misalign with existing scope boundaries.
    
    SCOPE OWNERSHIP GUARDRAIL: This function detects when manual edits to text
    (summary, description, BRs) may have altered scope meaning without explicit
    scope boundary changes. This allows scope_containment score to decrease naturally.
    
    Returns True if:
    - Text fields have manual overrides
    - Scope boundaries were NOT explicitly edited
    - The edited text introduces concepts not in scope or removes scope-relevant concepts
    
    This is advisory-only and does NOT modify scope boundaries.
    """
    # Only check if text was edited but scope was NOT explicitly edited
    if not requirement.manual_override:
        return False
    
    # If scope was explicitly edited, no misalignment (user owns scope)
    if requirement.manual_override.scope_boundaries is not None:
        return False
    
    # Check if text fields were edited
    text_edited = (
        requirement.manual_override.summary is not None or
        requirement.manual_override.description is not None
    )
    
    if not text_edited:
        return False
    
    # Get display values (edited text)
    edited_summary = requirement.get_display_summary()
    edited_description = requirement.get_display_description()
    edited_text = f"{edited_summary} {edited_description}".lower()
    
    # Get original text for comparison
    original_text = f"{requirement.summary} {requirement.description}".lower()
    
    # Get scope boundaries (unchanged)
    scope = requirement.get_display_scope_boundaries()
    scope_text = " ".join(scope.in_scope + scope.out_of_scope).lower()
    
    # Extract key terms from scope
    import re
    scope_terms = set()
    for item in scope.in_scope:
        words = re.findall(r'\b[a-z]{4,}\b', item.lower())
        scope_terms.update(words)
    
    # Extract key terms from edited text
    edited_terms = set()
    words = re.findall(r'\b[a-z]{4,}\b', edited_text.lower())
    edited_terms.update(words)
    
    # Extract key terms from original text
    original_terms = set()
    words = re.findall(r'\b[a-z]{4,}\b', original_text.lower())
    original_terms.update(words)
    
    # Check for significant divergence
    # New terms introduced that aren't in scope
    new_terms = edited_terms - original_terms - scope_terms
    # Terms removed that were in scope
    removed_terms = original_terms - edited_terms
    
    # Heuristic: If significant new terms (>3) or scope-relevant terms removed (>2)
    significant_new = len([t for t in new_terms if len(t) > 5])
    significant_removed = len([t for t in removed_terms if t in scope_terms])
    
    return significant_new >= 3 or significant_removed >= 2


def calculate_clarity_score(requirement: Requirement) -> float:
    """
    Calculate clarity score (0.0-1.0).
    
    Starts at 1.0 and subtracts:
    - 0.25 if actor missing (skipped for sub-tasks - Pattern A, skipped for UI orchestration)
    - 0.25 if action verb missing (skipped for UI orchestration)
    - 0.25 if outcome missing (skipped for sub-tasks - Pattern A, skipped for UI orchestration)
    - 0.15 for vague language
    - 0.10 if multiple behaviors combined
    - 0.10 if behavior inferred
    
    PATTERN A: Sub-tasks inherit actor/context from parent, so actor/outcome checks are relaxed.
    
    UI ORCHESTRATION EXEMPTION: UI orchestration tickets are exempt from actor, action verb,
    and outcome checks. UI orchestration requirements focus on scope containment, internal
    consistency, and absence of contradictory statements rather than traditional actor/action/outcome patterns.
    
    NOTE: Uses display values (manual overrides applied if present) for scoring.
    """
    score = 1.0
    notes = []
    
    # Use display values (manual overrides applied if present)
    description = requirement.get_display_description()
    summary = requirement.get_display_summary()
    
    # UI ORCHESTRATION EXEMPTION: Skip actor, action verb, and outcome checks for UI orchestration tickets
    # UI orchestration requirements are evaluated on scope containment, internal consistency, and absence of contradictions
    is_ui_orchestration = requirement.metadata and requirement.metadata.ui_orchestration if requirement.metadata else False
    
    # PATTERN A: Sub-tasks inherit actor/context from parent - skip actor/outcome checks
    is_subtask = requirement.parent_id is not None
    
    if not is_subtask and not is_ui_orchestration:
        # Only check actor/outcome for parent stories (not UI orchestration)
        if not _has_actor(description, summary):
            score -= 0.25
            notes.append("Actor not clearly specified")
        
        if not _has_outcome(description):
            score -= 0.25
            notes.append("Expected outcome not specified")
    
    # Action verb check applies to all (parent and sub-tasks) except UI orchestration
    # UI ORCHESTRATION EXEMPTION: Skip action verb check (behavioral trigger) for UI orchestration tickets
    if not is_ui_orchestration:
        if not _has_action_verb(description, summary):
            score -= 0.25
            notes.append("Action verb missing")
    
    # These checks apply to all requirements (including UI orchestration):
    # - Vague language (internal consistency)
    # - Multiple behaviors (contradictory statements)
    # - Inferred logic (internal consistency)
    if _has_vague_language(description, summary):
        score -= 0.15
        notes.append("Vague language detected")
    
    if _has_multiple_behaviors(description):
        score -= 0.10
        notes.append("Multiple behaviors combined")
    
    if requirement.inferred_logic:
        score -= 0.10
        notes.append("Behavior inferred")
    
    return max(0.0, score)


def calculate_completeness_score(requirement: Requirement, all_requirements: List[Requirement] = None) -> float:
    """
    Calculate completeness score (0.0-1.0) - measures scope definition completeness.
    
    This is NOT about testability - it measures whether the scope is fully defined.
    
    Starts at 1.0 and subtracts:
    - 0.40 if no business requirements (skipped for Pattern A parents with children)
    - 0.15 if business requirements inferred
    - 0.25 if scope boundaries are vague or incomplete
    - 0.15 if external dependency undefined
    - 0.10 if time/conditional logic unbounded
    
    PATTERN A: If requirement has child sub-tasks, skip BR completeness checks.
    Parent completeness must NOT be penalized for missing BRs in Pattern A.
    Only leaf requirements (no children) are evaluated for BR completeness.
    
    Args:
        requirement: The requirement to score
        all_requirements: All requirements in the package (to check for children)
    """
    # PATTERN A: Check if this requirement has children (sub-tasks)
    has_children = False
    is_subtask = False
    if all_requirements:
        has_children = any(r.parent_id == requirement.id for r in all_requirements)
        is_subtask = requirement.parent_id is not None
    
    # PATTERN A: Skip BR completeness penalty for parents with sub-tasks
    # Only leaf requirements (no children) must have BRs
    if not has_children and not is_subtask:
        # Leaf requirement (no children, not a sub-task) - must have BRs
        if not requirement.business_requirements or len(requirement.business_requirements) == 0:
            return 0.0
    
    # PATTERN A: Sub-tasks are complete if they have ≥1 BR (may have multiple BRs)
    if is_subtask:
        if not requirement.business_requirements or len(requirement.business_requirements) == 0:
            return 0.0
        # Sub-task with ≥1 BR is complete (do NOT penalize for multiple BRs)
    
    score = 1.0
    
    # Check for inferred business requirements (only if BRs exist)
    # Use display values - check original BRs for inferred flag (override doesn't change inferred status)
    if requirement.business_requirements and len(requirement.business_requirements) > 0:
        has_inferred_br = any(br.inferred for br in requirement.business_requirements)
        if has_inferred_br:
            score -= 0.15
    
    # Use display values (manual overrides applied if present)
    scope_boundaries = requirement.get_display_scope_boundaries()
    description = requirement.get_display_description()
    
    # Check for scope definition completeness
    if not scope_boundaries or not scope_boundaries.in_scope:
        score -= 0.25
    elif len(scope_boundaries.in_scope) == 0:
        score -= 0.25
    
    # Check for external dependencies
    if _has_external_dependency(description, requirement.gaps):
        score -= 0.15
    
    # Check for unbounded time/conditional logic
    if _has_unbounded_time_conditional(description):
        score -= 0.10
    
    return max(0.0, score)


def calculate_scope_containment_score(
    requirement: Requirement,
    all_requirements: List[Requirement]
) -> float:
    """
    Calculate scope containment score (0.0-1.0).
    
    Starts at 1.0 and subtracts:
    - 0.30 if multiple capabilities combined
    - 0.25 if crosses into another parent requirement
    - 0.15 if mixes error handling with core behavior
    - 0.15 if unrelated system areas referenced
    - 0.20 if scope-text misalignment detected (manual edits to text without scope changes)
    
    SCOPE OWNERSHIP GUARDRAIL: When manual edits to text fields (summary, description, BRs)
    alter scope meaning without explicit scope boundary changes, the score decreases naturally.
    This reflects misalignment but does NOT auto-fix scope boundaries.
    
    NOTE: Uses display values (manual overrides applied if present) for scoring.
    """
    score = 1.0
    notes = []
    
    # Use display values (manual overrides applied if present)
    summary = requirement.get_display_summary()
    description = requirement.get_display_description()
    
    if _has_multiple_capabilities(summary, description):
        score -= 0.30
        notes.append("Multiple capabilities combined")
    
    if _crosses_parent_boundary(requirement, all_requirements):
        score -= 0.25
        notes.append("Crosses into another parent requirement scope")
    
    if _mixes_error_handling(description, summary):
        score -= 0.15
        notes.append("Mixes error handling with core behavior")
    
    if _references_unrelated_system_areas(description):
        score -= 0.15
        notes.append("References unrelated system areas")
    
    # SCOPE OWNERSHIP GUARDRAIL: Detect scope-text misalignment
    # This allows score to decrease naturally when text is edited but scope is not
    if _has_scope_text_misalignment(requirement):
        score -= 0.20
        notes.append("Scope boundaries may need review due to manual text edits")
    
    return max(0.0, score)


def calculate_quality_scores(
    requirement: Requirement,
    all_requirements: List[Requirement]
) -> Dict[str, Any]:
    """
    Calculate all quality scores for a requirement.
    
    Args:
        requirement: The requirement to score
        all_requirements: All requirements in the package (for scope containment checks)
        
    Returns:
        Dictionary with 'quality_scores' and optionally 'quality_notes'
    """
    clarity = calculate_clarity_score(requirement)
    completeness = calculate_completeness_score(requirement, all_requirements)
    scope_containment = calculate_scope_containment_score(requirement, all_requirements)
    
    quality_scores = {
        "clarity": round(clarity, 2),
        "completeness": round(completeness, 2),
        "scope_containment": round(scope_containment, 2)
    }
    
    result = {"quality_scores": quality_scores}
    
    # Add quality notes if any score < 0.75
    # Notes must use scope-quality phrasing, NOT test-oriented language
    if clarity < 0.75 or completeness < 0.75 or scope_containment < 0.75:
        notes = []
        
        if clarity < 0.75:
            clarity_notes = []
            # UI ORCHESTRATION EXEMPTION: Skip actor, action verb, and outcome checks for UI orchestration tickets
            # UI orchestration requirements are evaluated on scope containment, internal consistency, and absence of contradictions
            is_ui_orchestration = requirement.metadata and requirement.metadata.ui_orchestration if requirement.metadata else False
            
            # PATTERN A: Sub-tasks inherit actor/context from parent - skip these checks
            is_subtask = requirement.parent_id is not None
            
            if not is_subtask and not is_ui_orchestration:
                # Only check actor/outcome for parent stories (not UI orchestration)
                if not _has_actor(requirement.description, requirement.summary):
                    clarity_notes.append("Ambiguous business intent - actor not clearly specified")
                if not _has_outcome(requirement.description):
                    clarity_notes.append("Ambiguous business intent - expected outcome not specified")
            
            # Action verb check applies to all (parent and sub-tasks) except UI orchestration
            # UI ORCHESTRATION EXEMPTION: Skip action verb check (behavioral trigger) for UI orchestration tickets
            if not is_ui_orchestration:
                if not _has_action_verb(requirement.description, requirement.summary):
                    clarity_notes.append("Ambiguous business intent - action verb missing")
            
            # These checks apply to all requirements (including UI orchestration):
            # - Vague language (internal consistency)
            # - Multiple behaviors (contradictory statements)
            # - Inferred logic (internal consistency)
            if _has_vague_language(requirement.description, requirement.summary):
                clarity_notes.append("Vague language detected")
            if _has_multiple_behaviors(requirement.description):
                clarity_notes.append("Non-atomic requirement - multiple behaviors combined")
            if requirement.inferred_logic:
                clarity_notes.append("Behavior inferred")
            if clarity_notes:
                notes.extend(clarity_notes)
        
        if completeness < 0.75:
            completeness_notes = []
            # PATTERN A: Skip BR completeness check for parents with sub-tasks
            has_children = any(r.parent_id == requirement.id for r in all_requirements)
            if not has_children:
                # Only check BR completeness for leaf requirements (no children)
                if not requirement.business_requirements or len(requirement.business_requirements) == 0:
                    completeness_notes.append("Missing business requirements")
                elif any(br.inferred for br in requirement.business_requirements):
                    completeness_notes.append("Business requirements inferred")
            elif any(br.inferred for br in requirement.business_requirements) if requirement.business_requirements else False:
                # Parent with children - only flag inferred BRs, not missing BRs
                completeness_notes.append("Business requirements inferred")
            if not requirement.scope_boundaries or not requirement.scope_boundaries.in_scope:
                completeness_notes.append("Scope boundaries incomplete")
            if _has_external_dependency(requirement.description, requirement.gaps):
                completeness_notes.append("External dependency undefined")
            if _has_unbounded_time_conditional(requirement.description):
                completeness_notes.append("Time/conditional logic unbounded")
            if completeness_notes:
                notes.extend(completeness_notes)
        
        if scope_containment < 0.75:
            scope_notes = []
            if _has_multiple_capabilities(requirement.summary, requirement.description):
                scope_notes.append("Multiple capabilities combined")
            if _crosses_parent_boundary(requirement, all_requirements):
                scope_notes.append("Crosses parent boundary")
            if _mixes_error_handling(requirement.description, requirement.summary):
                scope_notes.append("Mixes error handling with core behavior")
            if _references_unrelated_system_areas(requirement.description):
                scope_notes.append("References unrelated system areas")
            if scope_notes:
                notes.extend(scope_notes)
        
        if notes:
            result["quality_notes"] = list(set(notes))  # Deduplicate
    
    return result

