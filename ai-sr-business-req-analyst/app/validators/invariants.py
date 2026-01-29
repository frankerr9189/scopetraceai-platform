"""
Invariant rules enforcement for requirements.
"""
from typing import Dict, Any, List, Tuple
import re
from app.models.requirement import Requirement
from app.models.package import RequirementPackage
from app.models.enums import RequirementStatus


class InvariantValidator:
    """Validates invariants for requirements."""
    
    @staticmethod
    def validate(requirement: Requirement) -> Tuple[bool, List[str]]:
        """
        Validate requirement against invariant rules.
        
        Enforces:
        - Summary must not be empty
        - Description must meet minimum length
        - Must have stable, hierarchical ID
        - Must have business requirements
        - Must have scope boundaries
        - Must have metadata
        - Must start in REVIEW status
        - Inferred logic must be flagged
        
        Args:
            requirement: Requirement to validate
            
        Returns:
            Tuple of (is_valid, list_of_violations)
        """
        violations = []
        
        # Summary validation
        if not requirement.summary or not requirement.summary.strip():
            violations.append("Requirement summary cannot be empty")
        
        # Description validation
        if not requirement.description or len(requirement.description.strip()) < 10:
            violations.append("Requirement description must be at least 10 characters")
        
        # ID validation (must be hierarchical format)
        if not requirement.id or not requirement.id.strip():
            violations.append("Requirement must have a stable ID")
        elif not requirement.id.startswith("REQ-"):
            violations.append("Requirement ID must follow hierarchical format (e.g., REQ-001, REQ-001.1)")
        
        # Business requirements validation
        # PATTERN A: Parent stories may have zero BRs ONLY when sub-tasks exist (BRs moved to sub-tasks)
        # PATTERN A: Sub-tasks must have at least one BR (may have multiple if same capability)
        # NON-PATTERN-A: Parent stories MUST have at least one BR (sub-tasks are optional)
        if not requirement.business_requirements or len(requirement.business_requirements) == 0:
            if requirement.parent_id is not None:
                # Sub-task must have at least one BR (Pattern A)
                violations.append("Sub-task must have at least one business requirement (Pattern A)")
            # Parent story with zero BRs is allowed ONLY in Pattern A when sub-tasks exist
            # Note: This will be validated at package level to ensure parent has sub-tasks if BRs are empty
            # If parent has zero BRs and no sub-tasks, that's an invariant violation
        else:
            for idx, br in enumerate(requirement.business_requirements):
                # Validate BR ID format
                if not br.id or not br.id.strip():
                    violations.append(f"Business requirement {idx + 1} missing ID")
                elif not br.id.startswith("BR-") or not br.id[3:].isdigit():
                    violations.append(
                        f"Business requirement {idx + 1} has invalid ID format: {br.id}. "
                        f"Expected format: BR-001, BR-002, BR-003 (numbering resets per ticket)"
                    )
                # Validate that "statement" field contains a declarative statement
                if not br.statement or not br.statement.strip():
                    violations.append(f"Business requirement {idx + 1} missing declarative statement")
                else:
                    # Normalize: strip leading numbering/bullets (e.g. "8. ", "12) ", "- ") so we check the actual start
                    statement_text = br.statement.strip()
                    statement_text = re.sub(r'^\s*\d+[.)]\s*', '', statement_text)
                    statement_text = re.sub(r'^\s*[-*]\s+', '', statement_text)
                    statement_text = statement_text.strip().lower()
                    # Accept declarative variations (canonical + common LLM variants)
                    valid_starters = [
                        r'^the\s+system\s+shall',
                        r'^the\s+solution\s+shall',
                        r'^the\s+platform\s+shall',
                        r'^this\s+capability\s+shall',
                        r'^the\s+application\s+shall',
                        r'^the\s+product\s+shall',
                        r'^the\s+service\s+shall',
                    ]
                    if not any(re.match(pattern, statement_text) for pattern in valid_starters):
                        violations.append(
                            f"Business requirement {idx + 1} must be a declarative statement "
                            f"starting with 'The system shall', 'The solution shall', 'The platform shall', "
                            f"or 'This capability shall <capability or constraint>.'"
                        )
                    else:
                        # Check for atomicity violations (compound behaviors)
                        # Only flag TRUE multiple obligations, not temporal/conditional qualifiers
                        
                        # Pattern 1: Multiple modal verbs (strongest signal of multiple obligations)
                        # Look for patterns like "shall X and shall Y" or "shall X, and shall Y"
                        modal_verbs = ['shall', 'must', 'should']
                        modal_count = sum(1 for modal in modal_verbs if re.search(rf'\b{modal}\b', statement_text))
                        
                        # Pattern 2: Multiple independent clauses with modal verbs
                        compound_modal_patterns = [
                            r'\band\s+(?:the\s+system\s+)?(?:shall|must)',  # "and the system shall" or "and shall"
                            r',\s+(?:and\s+)?(?:the\s+system\s+)?(?:shall|must)',  # ", and the system shall" or ", and shall"
                            r'\bor\s+(?:the\s+system\s+)?(?:shall|must)',  # "or the system shall" or "or shall"
                        ]
                        has_compound_modal = any(re.search(pattern, statement_text) for pattern in compound_modal_patterns)
                        
                        # Pattern 3: Multiple action verbs in independent clauses (not in qualifiers)
                        # Action verbs that indicate separate obligations when joined by "and/or"
                        action_verbs = [
                            'publish', 'associate', 'link', 'create', 'update', 'delete', 'validate', 
                            'process', 'retrieve', 'store', 'display', 'authenticate', 'authorize',
                            'generate', 'save', 'send', 'attach', 'make', 'show', 'fetch', 
                            'transform', 'export', 'log', 'notify', 'redirect', 'encrypt', 'cache'
                        ]
                        
                        # Build pattern to match "verb1 ... and/or verb2" where both are action verbs
                        # This indicates multiple independent actions
                        verb_list = '|'.join(action_verbs)
                        explicit_compound_pattern = rf'\b({verb_list})[s]?\s+.*?\s+(?:and|or)\s+({verb_list})[s]?\b'
                        has_explicit_compound = re.search(explicit_compound_pattern, statement_text, re.IGNORECASE)
                        
                        # Pattern 4: Check for action verbs that are NOT in qualifier clauses
                        # Temporal/conditional qualifiers: during, while, when, if, unless, until, before, after, as long as, in order to, so that
                        qualifier_keywords = [
                            r'\bduring\s+',
                            r'\bwhile\s+',
                            r'\bwhen\s+',
                            r'\bif\s+',
                            r'\bunless\s+',
                            r'\buntil\s+',
                            r'\bbefore\s+',
                            r'\bafter\s+',
                            r'\bas\s+long\s+as\s+',
                            r'\bin\s+order\s+to\s+',
                            r'\bso\s+that\s+',
                        ]
                        
                        # Find all qualifier positions
                        qualifier_ranges = []
                        for qualifier_pattern in qualifier_keywords:
                            for match in re.finditer(qualifier_pattern, statement_text, re.IGNORECASE):
                                # Qualifier extends from start to end of statement or until next punctuation/clause boundary
                                qual_start = match.start()
                                # Find the end: look for period, comma, or end of string
                                remaining_text = statement_text[qual_start:]
                                # Match up to next clause boundary (period, semicolon, or end)
                                clause_end_match = re.search(r'[.;]|$', remaining_text)
                                qual_end = qual_start + (clause_end_match.start() if clause_end_match else len(remaining_text))
                                qualifier_ranges.append((qual_start, qual_end))
                        
                        # Count action verbs that are in predicate position (not noun uses like "permission updates").
                        # Only count: (1) the first action verb after "shall", or (2) verbs after " and "/" or "/", " (compound).
                        main_clause_verb_count = 0
                        shall_match = re.search(r'\bshall\b', statement_text, re.IGNORECASE)
                        start_after = shall_match.end() if shall_match else 0
                        seen_positions = []
                        for verb in action_verbs:
                            for match in re.finditer(rf'\b{verb}[s]?\b', statement_text, re.IGNORECASE):
                                verb_pos = match.start()
                                # Skip if in qualifier
                                in_qualifier = any(qual_start <= verb_pos < qual_end for qual_start, qual_end in qualifier_ranges)
                                if in_qualifier:
                                    continue
                                # First verb after "shall" always counts (main predicate)
                                if verb_pos >= start_after and main_clause_verb_count == 0:
                                    main_clause_verb_count += 1
                                    seen_positions.append(verb_pos)
                                    break
                                # Later verb counts only if it follows " and " or " or " (compound predicate)
                                text_before = statement_text[:verb_pos].rstrip()
                                if re.search(r'\s+(?:and|or)\s+$', text_before):
                                    if verb_pos not in seen_positions:
                                        main_clause_verb_count += 1
                                        seen_positions.append(verb_pos)
                                break  # Count each verb type only once
                        
                        # Determine if we have multiple obligations
                        has_multiple_obligations = False
                        
                        if modal_count > 1 or has_compound_modal:
                            # Multiple modal verbs = multiple obligations
                            has_multiple_obligations = True
                        elif has_explicit_compound:
                            # Explicit "verb1 and/or verb2" pattern = multiple obligations
                            has_multiple_obligations = True
                        elif main_clause_verb_count > 1:
                            # Multiple action verbs in main clause (not in qualifiers) = multiple obligations
                            has_multiple_obligations = True
                        
                        if has_multiple_obligations:
                            violations.append(
                                f"Business requirement {idx + 1} contains multiple obligations and must be split. "
                                f"Each BR must represent exactly ONE obligation. Statement: '{br.statement}'"
                            )
        
        # Scope boundaries validation
        if not requirement.scope_boundaries:
            violations.append("Requirement must have scope boundaries")
        else:
            if not requirement.scope_boundaries.in_scope:
                violations.append("Requirement scope boundaries must have at least one in-scope item")
            # Note: Atomicity check (mismatch between in_scope items and BR count) is handled
            # in post-processing layer (_check_br_atomicity) which adds open questions.
            # This invariant validator only checks for hard structural violations.
        
        # Metadata validation
        if not requirement.metadata:
            violations.append("Requirement must have metadata")
        else:
            if requirement.metadata.source_type not in ["brd", "freeform", "jira_existing"]:
                violations.append(f"Invalid source_type: {requirement.metadata.source_type}. Must be: brd | freeform | jira_existing")
            if requirement.metadata.enhancement_mode not in [0, 1, 2, 3]:
                violations.append(f"Invalid enhancement_mode: {requirement.metadata.enhancement_mode}. Must be: 0 | 1 | 2 | 3")
        
        # Status validation (must start in REVIEW)
        if requirement.status != RequirementStatus.IN_REVIEW:
            violations.append(f"Requirement must start in REVIEW status, found: {requirement.status.value}")
        
        # Original intent validation
        if not requirement.original_intent or not requirement.original_intent.strip():
            violations.append("Requirement must preserve original business intent")
        
        # Constraints and policies validation
        if not requirement.constraints_policies:
            violations.append("Requirement must have constraints_policies (use ['N/A'] if none)")
        
        # Open questions validation
        if not requirement.open_questions:
            violations.append("Requirement must have open_questions (use ['N/A'] if none)")
        
        # Check for banned test-oriented terminology
        # NOTE: "test plans" as a business artifact is ALLOWED (e.g., "publish test plans", "test plan editing")
        # NOTE: "test execution tracking" as a business capability is ALLOWED
        # Only ban test-oriented phrases in testing/verification contexts
        banned_terms = [
            r'\bvalidation\s+of\s+(?:test\s+)?(?:plans?|cases?|execution)',
            r'\bverification\s+of\s+(?:test\s+)?(?:plans?|cases?|execution)',
            r'\btesting\s+of\s+(?:test\s+)?(?:plans?|cases?|execution)',
            r'\btestability\b',
            # Only ban "test execution" when it's clearly a testing activity, not a capability
            # Allow "test execution tracking" (legitimate capability)
            r'^\s*test\s+execution\s*$',
            r'\btest\s+execution\s+(?:is|are|must|should|will|can)\s+(?:not\s+)?(?:in|out\s+of)\s+scope',
            r'\btest\s+execution\s+(?:validation|verification|testing)',
            r'\btest\s+cases?\s+(?:execution|validation|verification|testing)',
            r'\bnegative\s+scenarios?\b',
            r'\bpass/fail\b',
            r'\bevidence\s+(?:of|for|that)',
            # Only ban RTM when in testing context, allow "RTM generation" (legitimate capability)
            r'\bRTM\s+(?:validation|verification|testing)',
            r'\bGiven/When/Then\b',
            r'\btest\s+steps?\b',
        ]
        
        # Legitimate business capabilities that should NOT be flagged
        # These patterns match legitimate business capabilities containing "test"
        legitimate_capabilities = [
            r'test\s+execution\s+tracking',
            r'test\s+execution\s+monitoring',
            r'rtm\s+generation',
            r'rtm\s+creation',
            r'test\s+plan\s+(?:edit|publish|manage|create|delete|view|display|show|generation|creation)',
            r'test\s+case\s+management',
            r'publish\s+test\s+plans?',
            r'associate\s+test\s+plans?',
            r'link\s+test\s+plans?',
            r'generate\s+test\s+plans?',
            r'create\s+test\s+plans?',
            r'test\s+plans?\s+(?:to|in|for|with)',
        ]
        
        # Check summary
        if requirement.summary:
            summary_lower = requirement.summary.lower()
            # First check if it's a legitimate capability
            is_legitimate = any(re.search(pattern, summary_lower) for pattern in legitimate_capabilities)
            if not is_legitimate:
                for pattern in banned_terms:
                    if re.search(pattern, summary_lower):
                        violations.append(
                            f"Summary contains banned test-oriented terminology. "
                            f"Found pattern matching: {pattern}"
                        )
                        break
        
        # Check description
        if requirement.description:
            desc_lower = requirement.description.lower()
            # First check if it's a legitimate capability
            is_legitimate = any(re.search(pattern, desc_lower) for pattern in legitimate_capabilities)
            if not is_legitimate:
                for pattern in banned_terms:
                    if re.search(pattern, desc_lower):
                        violations.append(
                            f"Description contains banned test-oriented terminology. "
                            f"Found pattern matching: {pattern}"
                        )
                        break
        
        # Check business requirements
        for idx, br in enumerate(requirement.business_requirements, 1):
            if br.statement:
                br_lower = br.statement.lower()
                # First check if it's a legitimate capability
                is_legitimate = any(re.search(pattern, br_lower) for pattern in legitimate_capabilities)
                if not is_legitimate:
                    for pattern in banned_terms:
                        if re.search(pattern, br_lower):
                            violations.append(
                                f"Business requirement {idx} contains banned test-oriented terminology. "
                                f"Found pattern matching: {pattern}"
                            )
                            break
        
        # Check out_of_scope (most critical - must never contain test language)
        if requirement.scope_boundaries and requirement.scope_boundaries.out_of_scope:
            for idx, item in enumerate(requirement.scope_boundaries.out_of_scope, 1):
                if item != "N/A":
                    item_lower = item.lower()
                    
                    # First check if it's a legitimate capability (don't flag these)
                    is_legitimate = any(re.search(pattern, item_lower) for pattern in legitimate_capabilities)
                    if is_legitimate:
                        continue
                    
                    # Then check for banned terms
                    for pattern in banned_terms:
                        if re.search(pattern, item_lower):
                            violations.append(
                                f"Out of scope item {idx} contains banned test-oriented terminology: '{item}'. "
                                f"Out of scope must describe capability exclusions, not test/verification terminology."
                            )
                            break
        
        # Check open questions
        for idx, question in enumerate(requirement.open_questions, 1):
            if question != "N/A":
                q_lower = question.lower()
                # First check if it's a legitimate capability
                is_legitimate = any(re.search(pattern, q_lower) for pattern in legitimate_capabilities)
                if not is_legitimate:
                    for pattern in banned_terms:
                        if re.search(pattern, q_lower):
                            violations.append(
                                f"Open question {idx} contains banned test-oriented terminology. "
                                f"Found pattern matching: {pattern}"
                            )
                            break
        
        # Check quality notes if present
        if requirement.quality_notes:
            for idx, note in enumerate(requirement.quality_notes, 1):
                note_lower = note.lower()
                for pattern in banned_terms:
                    if re.search(pattern, note_lower):
                        violations.append(
                            f"Quality note {idx} contains banned test-oriented terminology. "
                            f"Found pattern matching: {pattern}"
                        )
                        break
        
        return len(violations) == 0, violations
    
    @staticmethod
    def validate_package(package: RequirementPackage) -> Tuple[bool, List[str]]:
        """
        Validate requirement package against invariant rules.
        
        Args:
            package: Package to validate
            
        Returns:
            Tuple of (is_valid, list_of_violations)
        """
        violations = []
        
        # Package ID validation
        if not package.package_id or not package.package_id.strip():
            violations.append("Package must have a package_id")
        
        # Version validation
        if not package.version or not package.version.strip():
            violations.append("Package must have a version")
        
        # Original input validation
        if not package.original_input or not package.original_input.strip():
            violations.append("Package must preserve original input")
        
        # Validate all requirements in package
        for req in package.requirements:
            is_valid, req_violations = InvariantValidator.validate(req)
            if not is_valid:
                violations.extend([f"Requirement {req.id}: {v}" for v in req_violations])
        
        # Check for hierarchical ID structure
        req_ids = [req.id for req in package.requirements]
        parent_ids = {req.parent_id for req in package.requirements if req.parent_id}
        
        for parent_id in parent_ids:
            if parent_id not in req_ids:
                violations.append(f"Parent requirement {parent_id} referenced but not found")
        
        # PATTERN A validation: If parent has zero BRs, it must have sub-tasks
        for req in package.requirements:
            if req.parent_id is None:  # This is a parent story
                has_children = any(child.parent_id == req.id for child in package.requirements)
                if (not req.business_requirements or len(req.business_requirements) == 0) and not has_children:
                    violations.append(
                        f"Requirement {req.id}: Parent story with zero business requirements must have sub-tasks (Pattern A)"
                    )
                # PATTERN A: If parent has sub-tasks, it should have zero BRs (BRs are in sub-tasks)
                if has_children and req.business_requirements and len(req.business_requirements) > 0:
                    # This is a warning, not a hard violation - parent may have abstract BR
                    # But Pattern A prefers zero BRs when sub-tasks exist
                    pass
        
        return len(violations) == 0, violations
