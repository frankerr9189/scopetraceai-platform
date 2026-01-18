"""
Human-readable presentation layer for RequirementPackage.

This module generates a derived, non-authoritative readable_summary that makes
the output easy for humans to review while preserving audit-grade JSON.

The readable_summary is presentation-only and does not modify the authoritative schema.
"""
from typing import List, Dict, Any
from app.models.package import RequirementPackage
from app.models.requirement import Requirement, BusinessRequirement


def normalize_text(text: str) -> str:
    """
    Normalize text to natural BA style.
    
    Args:
        text: Text to normalize
        
    Returns:
        Normalized text
    """
    # Lowercase "The user" to "the user" at start of sentences
    text = text.strip()
    if text.startswith("The user"):
        text = "the user" + text[8:]
    elif text.startswith("A user"):
        text = "a user" + text[6:]
    
    return text


def format_business_requirements(requirements: List[BusinessRequirement]) -> List[Dict[str, Any]]:
    """
    Format business requirements into readable format with BR IDs.
    
    Args:
        requirements: List of business requirements
        
    Returns:
        List of dictionaries containing id and formatted text
    """
    formatted = []
    for req in requirements:
        statement = normalize_text(req.statement)
        
        # Ensure it's properly formatted
        if not statement.endswith('.'):
            statement = statement.rstrip('.') + '.'
        
        if req.inferred:
            statement += " [inferred]"
        
        formatted.append({
            "id": req.id,
            "text": statement
        })
    return formatted


def generate_reviewer_actions(package: RequirementPackage) -> List[str]:
    """
    Generate outcome-focused, actionable review prompts from gaps and ambiguities.
    
    Args:
        package: Requirement package to analyze
        
    Returns:
        List of actionable reviewer prompts in professional BA language
    """
    actions = []
    
    # Check for inferred logic - make outcome-focused
    for req in package.requirements:
        if req.inferred_logic:
            # Extract key inferred items for context
            inferred_summary = ", ".join(req.inferred_logic[:2])  # First 2 items
            if len(req.inferred_logic) > 2:
                inferred_summary += ", etc."
            actions.append(
                f"Confirm that inferred assumptions are acceptable ({req.id}): {inferred_summary}"
            )
        
        # Check for gaps - make specific and actionable
        if req.gaps:
            # Summarize gaps for this requirement
            gap_summary = "; ".join(req.gaps[:2])  # First 2 gaps
            if len(req.gaps) > 2:
                gap_summary += f" (and {len(req.gaps) - 2} more)"
            actions.append(
                f"Define missing details for {req.summary} ({req.id}): {gap_summary}"
            )
        
        # Check for open questions
        if req.open_questions and req.open_questions != ["N/A"]:
            question_summary = "; ".join(req.open_questions[:2])  # First 2 questions
            if len(req.open_questions) > 2:
                question_summary += f" (and {len(req.open_questions) - 2} more)"
            actions.append(
                f"Address open questions for {req.summary} ({req.id}): {question_summary}"
            )
        
        # Check for ambiguities - make them specific confirmation requests
        if req.ambiguities:
            ambiguity_summary = "; ".join(req.ambiguities[:2])  # First 2 ambiguities
            if len(req.ambiguities) > 2:
                ambiguity_summary += f" (and {len(req.ambiguities) - 2} more)"
            actions.append(
                f"Clarify ambiguous requirements for {req.summary} ({req.id}): {ambiguity_summary}"
            )
    
    # Check global gaps - make them executive-level
    if package.gap_analysis.gaps:
        gap_count = len(package.gap_analysis.gaps)
        actions.append(
            f"Address {gap_count} cross-cutting gap{'s' if gap_count > 1 else ''} affecting multiple requirements"
        )
    
    if package.gap_analysis.missing_information:
        info_count = len(package.gap_analysis.missing_information)
        actions.append(
            f"Provide {info_count} missing piece{'s' if info_count > 1 else ''} of information requiring confirmation"
        )
    
    # Check for high-risk items - make it outcome-focused
    if package.risk_analysis.risk_level in ["high", "critical"]:
        actions.append(
            f"Review and mitigate {package.risk_analysis.risk_level}-level risks before proceeding"
        )
    
    # Check audit concerns - make it actionable
    if package.risk_analysis.audit_concerns:
        concern_count = len(package.risk_analysis.audit_concerns)
        actions.append(
            f"Resolve {concern_count} audit concern{'s' if concern_count > 1 else ''} for ISO 27001 and SOC 2 compliance"
        )
    
    return list(set(actions))  # Deduplicate


def generate_readable_summary(package: RequirementPackage) -> Dict[str, Any]:
    """
    Generate a human-readable summary from a RequirementPackage.
    
    This is a derived, presentation-only view that does not modify the authoritative schema.
    
    Args:
        package: Requirement package to summarize
        
    Returns:
        Dictionary containing readable_summary structure
    """
    # Organize requirements by parent/child structure
    parent_requirements = {req.id: req for req in package.requirements if req.parent_id is None}
    child_requirements = {req.id: req for req in package.requirements if req.parent_id is not None}
    
    # Build capabilities structure
    capabilities = []
    for parent_id, parent_req in parent_requirements.items():
        # Find children for this parent
        children = [req for req in child_requirements.values() if req.parent_id == parent_id]
        
        # Build children summary
        children_summary = []
        for child in sorted(children, key=lambda x: x.id):  # Sort by ID for consistency
            # Collect notes (inferred logic, ambiguities, open questions) with natural BA language
            notes = []
            if child.inferred_logic:
                for item in child.inferred_logic:
                    note_text = normalize_text(item)
                    notes.append(f"Assumed behavior: {note_text}")
            if child.ambiguities:
                for item in child.ambiguities:
                    note_text = normalize_text(item)
                    notes.append(f"Clarification needed: {note_text}")
            if child.open_questions and child.open_questions != ["N/A"]:
                for item in child.open_questions:
                    note_text = normalize_text(item)
                    notes.append(f"Open question: {note_text}")
            
            children_summary.append({
                "id": child.id,
                "summary": child.summary,
                "business_requirements": format_business_requirements(child.business_requirements),
                "scope_boundaries": {
                    "in_scope": child.scope_boundaries.in_scope,
                    "out_of_scope": child.scope_boundaries.out_of_scope
                },
                "gaps": child.gaps,
                "notes": notes
            })
        
        # Polish capability summary
        summary = normalize_text(parent_req.description)
        
        capabilities.append({
            "id": parent_req.id,
            "summary": parent_req.summary,
            "description": summary,
            "business_requirements": format_business_requirements(parent_req.business_requirements),
            "scope_boundaries": {
                "in_scope": parent_req.scope_boundaries.in_scope,
                "out_of_scope": parent_req.scope_boundaries.out_of_scope
            },
            "children": children_summary
        })
    
    # Sort capabilities by ID for consistency
    capabilities.sort(key=lambda x: x["id"])
    
    # Determine if human review is required
    requires_human_review = (
        any(req.inferred_logic for req in package.requirements) or
        any(req.ambiguities for req in package.requirements) or
        any(req.open_questions != ["N/A"] for req in package.requirements) or
        bool(package.gap_analysis.gaps) or
        bool(package.gap_analysis.missing_information) or
        package.risk_analysis.risk_level in ["high", "critical"] or
        bool(package.risk_analysis.audit_concerns) or
        (package.metadata and package.metadata.get("requires_human_review", False))
    )
    
    # Get confidence from metadata if available
    confidence = package.metadata.get("confidence", "medium") if package.metadata else "medium"
    
    # Consolidate and deduplicate key gaps into high-level themes
    all_gaps = package.gap_analysis.gaps.copy()
    for req in package.requirements:
        all_gaps.extend(req.gaps)
    
    # Consolidate similar gaps into themes
    key_gaps = []
    gap_themes = {}
    
    for gap in all_gaps:
        gap_lower = gap.lower()
        
        # Identify themes
        if "field" in gap_lower and ("not defined" in gap_lower or "missing" in gap_lower or "undefined" in gap_lower):
            theme = "fields"
            if theme not in gap_themes:
                gap_themes[theme] = []
            gap_themes[theme].append(gap)
        elif "scope" in gap_lower or "boundary" in gap_lower:
            theme = "scope"
            if theme not in gap_themes:
                gap_themes[theme] = []
            gap_themes[theme].append(gap)
        elif "validation" in gap_lower or "constraint" in gap_lower:
            theme = "validation"
            if theme not in gap_themes:
                gap_themes[theme] = []
            gap_themes[theme].append(gap)
        else:
            # Keep unique gaps that don't fit themes
            if gap not in key_gaps:
                key_gaps.append(gap)
    
    # Consolidate themed gaps into high-level statements
    theme_consolidations = {
        "fields": "Data fields and their definitions are not fully specified",
        "scope": "Functional scope and boundaries are not clearly defined",
        "validation": "Validation rules and constraints are not specified",
    }
    
    for theme, gaps in gap_themes.items():
        if theme in theme_consolidations:
            consolidated = theme_consolidations[theme]
            if consolidated not in key_gaps:
                key_gaps.append(consolidated)
        else:
            # If no consolidation, add unique gaps from theme
            for gap in gaps:
                if gap not in key_gaps:
                    key_gaps.append(gap)
    
    # Sort for consistency
    key_gaps.sort()
    
    # Generate reviewer actions
    reviewer_actions = generate_reviewer_actions(package)
    
    # Add Jira context notes if available
    jira_notes = []
    if package.metadata and "jira_context" in package.metadata:
        jira_context = package.metadata["jira_context"]
        
        # Add sub-ticket note
        sub_tickets = jira_context.get("sub_tickets", [])
        if sub_tickets:
            sub_count = len(sub_tickets)
            jira_notes.append(f"{sub_count} sub-ticket(s) detected — used as contextual signal only")
        
        # Add attachment note
        attachments = jira_context.get("attachments", [])
        if attachments:
            jira_notes.append("Attachments detected but not analyzed")
    
    # Add jira_notes to overview if present
    overview = {
        "original_intent": package.original_input,
        "confidence": confidence,
        "requires_human_review": requires_human_review
    }
    if jira_notes:
        overview["jira_notes"] = jira_notes
    
    # PHASE 1 ATTACHMENT SUPPORT: Add Supporting Materials section
    supporting_materials = []
    if package.attachments:
        for attachment in package.attachments:
            supporting_materials.append({
                "filename": attachment.filename,
                "mime_type": attachment.mime_type,
                "note": "Extracted text available for reference. Requirements may reference this file manually (e.g., 'See Vendor_API.pdf §2.1')."
            })
    
    result = {
        "overview": overview,
        "capabilities": capabilities,
        "key_gaps": key_gaps,
        "reviewer_actions": reviewer_actions
    }
    
    if supporting_materials:
        result["supporting_materials"] = supporting_materials
    
    return result
