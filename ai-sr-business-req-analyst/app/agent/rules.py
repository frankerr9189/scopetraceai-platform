"""
Guardrails and prohibitions for the analyst agent.
"""
from typing import List, Dict, Any


class AgentRules:
    """Rules and guardrails for the analyst agent."""
    
    PROHIBITED_ACTIONS: List[str] = [
        "Auto-approve requirements",
        "Write back to Jira",
        "Parse or interpret attachments",
        "Treat inferred logic as confirmed fact",
        "Generate code or test cases",
        "Execute or validate behavior",
        "Invent new features",
        "Expand scope beyond original intent",
        "Redesign workflows",
        "Optimize business logic",
        "Assume policy unless explicitly stated",
        "Guess or resolve ambiguities without flagging",
    ]
    
    REQUIRED_VALIDATIONS: List[str] = [
        "All requirements must have acceptance criteria",
        "All requirements must start in REVIEW status",
        "All inferred logic must be explicitly flagged",
        "All requirements must be in structured format",
        "All requirements must have stable, hierarchical IDs",
        "Gaps must be flagged and documented",
        "Risks must be identified and documented",
        "Ambiguities must be flagged for human confirmation",
    ]
    
    @staticmethod
    def check_prohibitions(content: str) -> List[str]:
        """
        Check if content violates any prohibitions.
        
        Args:
            content: Content to check
            
        Returns:
            List of violations found
        """
        violations = []
        content_lower = content.lower()
        
        # Check for prohibited patterns
        prohibited_patterns = {
            "auto-approve": "Auto-approve requirements",
            "write back to jira": "Write back to Jira",
            "generate code": "Generate code or test cases",
            "execute": "Execute or validate behavior",
        }
        
        for pattern, violation in prohibited_patterns.items():
            if pattern in content_lower:
                violations.append(violation)
        
        return violations
    
    @staticmethod
    def validate_requirements(requirements: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate requirements against rules.
        
        Args:
            requirements: Requirements to validate
            
        Returns:
            Validation results with any violations
        """
        violations = []
        
        # Check if requirements list exists
        req_list = requirements.get("requirements", [])
        if not isinstance(req_list, list):
            violations.append("Requirements must be a list")
            return {"valid": False, "violations": violations}
        
        # Validate each requirement
        for req in req_list:
            # Must have acceptance criteria
            if "acceptance_criteria" not in req or not req.get("acceptance_criteria"):
                violations.append(f"Requirement {req.get('id', 'unknown')} missing acceptance criteria")
            
            # Must start in REVIEW status
            if req.get("status") != "REVIEW":
                violations.append(f"Requirement {req.get('id', 'unknown')} must start in REVIEW status")
            
            # Must have structured format (title, description)
            if not req.get("title") or not req.get("description"):
                violations.append(f"Requirement {req.get('id', 'unknown')} missing title or description")
            
            # Must have stable ID
            if not req.get("id"):
                violations.append(f"Requirement missing stable ID")
        
        return {
            "valid": len(violations) == 0,
            "violations": violations
        }

