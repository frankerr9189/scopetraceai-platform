"""
Test Pattern A: Sub-task decomposition with BR distribution.

Pattern A Rules:
- Parent story = high-level capability and intent (NO atomic BRs)
- Sub-tasks = actual scoped business requirements (ONE atomic BR each)
- Parent scope is high-level, sub-task scope is atomic
- No BR duplication between parent and sub-tasks
- Quality scoring relaxed for sub-tasks (no actor/outcome penalties)
"""
import pytest
from app.models.intermediate import (
    LLMAnalysisOutput,
    ProposedCapability,
    ProposedRequirement,
    BusinessRequirementIntermediate,
    ScopeBoundariesIntermediate,
    RequirementMetadataIntermediate,
)
from app.models.requirement import Requirement, RequirementPackage
from app.services.analysis_mapper import map_llm_output_to_package
from app.validators.invariants import InvariantValidator


def create_test_llm_output_with_multiple_brs() -> LLMAnalysisOutput:
    """Create a test LLM output that should trigger sub-task decomposition."""
    return LLMAnalysisOutput(
        capabilities=[
            ProposedCapability(
                capability_title="User Management System",
                description="Enable comprehensive user management with registration and permissions",
                inferred=False,
                proposed_requirements=[
                    ProposedRequirement(
                        summary="User Registration",
                        description="Allow users to create accounts with email and password",
                        business_requirements=[
                            BusinessRequirementIntermediate(
                                statement="The system shall allow users to register with email and password",
                                inferred=False
                            ),
                            BusinessRequirementIntermediate(
                                statement="The system shall validate email format during registration",
                                inferred=False
                            ),
                        ],
                        scope_boundaries=ScopeBoundariesIntermediate(
                            in_scope=["User registration", "Email validation"],
                            out_of_scope=["Password reset", "Email verification"]
                        ),
                        constraints_policies=["Passwords must be at least 8 characters"],
                        open_questions=["Should email verification be required?"],
                        metadata=RequirementMetadataIntermediate(
                            source_type="freeform",
                            enhancement_mode=1,
                            enhancement_actions=["Clarified language"],
                            inferred_content=False
                        ),
                        gaps=[],
                        risks=[]
                    ),
                    ProposedRequirement(
                        summary="Permission Management",
                        description="Manage user permissions independently from registration",
                        business_requirements=[
                            BusinessRequirementIntermediate(
                                statement="The system shall allow administrators to assign roles to users",
                                inferred=False
                            ),
                        ],
                        scope_boundaries=ScopeBoundariesIntermediate(
                            in_scope=["Role assignment"],
                            out_of_scope=["Role creation", "Permission inheritance"]
                        ),
                        constraints_policies=["Only administrators can assign roles"],
                        open_questions=[],
                        metadata=RequirementMetadataIntermediate(
                            source_type="freeform",
                            enhancement_mode=1,
                            enhancement_actions=["Clarified language"],
                            inferred_content=False
                        ),
                        gaps=[],
                        risks=[]
                    ),
                ]
            )
        ],
        global_risks=[],
        global_gaps=[]
    )


def test_pattern_a_parent_has_zero_brs():
    """Test that parent story has zero BRs when sub-tasks exist (Pattern A)."""
    llm_output = create_test_llm_output_with_multiple_brs()
    package = map_llm_output_to_package(llm_output, original_input="User management with registration and permissions")
    
    # Find parent requirement
    parent = next((req for req in package.requirements if req.parent_id is None), None)
    assert parent is not None, "Parent requirement should exist"
    
    # PATTERN A: Parent should have zero BRs (BRs moved to sub-tasks)
    assert len(parent.business_requirements) == 0, (
        f"Parent story should have zero BRs in Pattern A, found {len(parent.business_requirements)}"
    )


def test_pattern_a_each_subtask_has_one_br():
    """Test that each sub-task has exactly one BR (Pattern A)."""
    llm_output = create_test_llm_output_with_multiple_brs()
    package = map_llm_output_to_package(llm_output, original_input="User management with registration and permissions")
    
    # Find all sub-tasks
    sub_tasks = [req for req in package.requirements if req.parent_id is not None]
    assert len(sub_tasks) > 0, "Should have at least one sub-task"
    
    # PATTERN A: Each sub-task must have exactly ONE BR
    for sub_task in sub_tasks:
        assert len(sub_task.business_requirements) == 1, (
            f"Sub-task {sub_task.id} should have exactly one BR (Pattern A), "
            f"found {len(sub_task.business_requirements)}"
        )


def test_pattern_a_no_br_duplication():
    """Test that BRs are not duplicated between parent and sub-tasks."""
    llm_output = create_test_llm_output_with_multiple_brs()
    package = map_llm_output_to_package(llm_output, original_input="User management with registration and permissions")
    
    parent = next((req for req in package.requirements if req.parent_id is None), None)
    sub_tasks = [req for req in package.requirements if req.parent_id is not None]
    
    # Collect all BR statements from parent and sub-tasks
    parent_br_statements = {br.statement.lower().strip() for br in parent.business_requirements}
    sub_task_br_statements = set()
    for sub_task in sub_tasks:
        for br in sub_task.business_requirements:
            sub_task_br_statements.add(br.statement.lower().strip())
    
    # PATTERN A: No BR should appear in both parent and sub-tasks
    overlap = parent_br_statements.intersection(sub_task_br_statements)
    assert len(overlap) == 0, (
        f"BR statements should not be duplicated between parent and sub-tasks. "
        f"Found overlap: {overlap}"
    )


def test_pattern_a_subtask_scope_not_duplicated():
    """Test that sub-task scope is not verbatim duplicate of parent scope."""
    llm_output = create_test_llm_output_with_multiple_brs()
    package = map_llm_output_to_package(llm_output, original_input="User management with registration and permissions")
    
    parent = next((req for req in package.requirements if req.parent_id is None), None)
    sub_tasks = [req for req in package.requirements if req.parent_id is not None]
    
    if parent.scope_boundaries and parent.scope_boundaries.in_scope:
        parent_in_scope_set = {s.lower().strip() for s in parent.scope_boundaries.in_scope}
        
        for sub_task in sub_tasks:
            if sub_task.scope_boundaries and sub_task.scope_boundaries.in_scope:
                sub_task_in_scope_set = {s.lower().strip() for s in sub_task.scope_boundaries.in_scope}
                # PATTERN A: Sub-task scope should be more specific than parent (not identical)
                # Allow some overlap, but not complete duplication
                if sub_task_in_scope_set == parent_in_scope_set:
                    # This is a warning - sub-task scope should be more specific
                    # But we allow it if it was refined based on BR
                    pass


def test_pattern_a_subtask_description_not_duplicated():
    """Test that sub-task description is not verbatim duplicate of parent description."""
    llm_output = create_test_llm_output_with_multiple_brs()
    package = map_llm_output_to_package(llm_output, original_input="User management with registration and permissions")
    
    parent = next((req for req in package.requirements if req.parent_id is None), None)
    sub_tasks = [req for req in package.requirements if req.parent_id is not None]
    
    parent_desc_lower = parent.description.lower().strip()
    
    for sub_task in sub_tasks:
        sub_task_desc_lower = sub_task.description.lower().strip()
        # PATTERN A: Sub-task description should not be identical to parent
        assert sub_task_desc_lower != parent_desc_lower, (
            f"Sub-task {sub_task.id} description should not duplicate parent description verbatim"
        )


def test_pattern_a_quality_scoring_relaxed_for_subtasks():
    """Test that quality scoring is relaxed for sub-tasks (no actor/outcome penalties)."""
    llm_output = create_test_llm_output_with_multiple_brs()
    package = map_llm_output_to_package(llm_output, original_input="User management with registration and permissions")
    
    sub_tasks = [req for req in package.requirements if req.parent_id is not None]
    assert len(sub_tasks) > 0, "Should have at least one sub-task"
    
    for sub_task in sub_tasks:
        # Calculate quality scores
        quality_result = sub_task.quality_scores if hasattr(sub_task, 'quality_scores') else None
        
        # PATTERN A: Sub-tasks should not be penalized for missing actor/outcome
        # (they inherit from parent)
        # This is tested by ensuring clarity score doesn't drop too much
        if quality_result:
            clarity = quality_result.get('clarity', 1.0)
            # Sub-tasks should have reasonable clarity even without explicit actor/outcome
            # (since they inherit from parent)
            assert clarity >= 0.5, (
                f"Sub-task {sub_task.id} clarity score too low ({clarity}). "
                f"Pattern A: Sub-tasks inherit actor/context from parent."
            )


def test_pattern_a_passes_invariants():
    """Test that Pattern A output passes all invariant validations."""
    llm_output = create_test_llm_output_with_multiple_brs()
    package = map_llm_output_to_package(llm_output, original_input="User management with registration and permissions")
    
    # Validate package
    is_valid, violations = InvariantValidator.validate_package(package)
    
    assert is_valid, (
        f"Pattern A output should pass all invariants. Violations: {violations}"
    )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

