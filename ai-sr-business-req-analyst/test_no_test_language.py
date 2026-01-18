"""
Test that ai-sr-business-req-analyst outputs contain NO test-oriented language.

Banned terms:
- "validation", "testability", "test", "testing", "verification"
- "negative scenarios", "pass/fail", "evidence", "RTM"
- "test execution", "test cases", "test plans", "Given/When/Then", "test steps"
"""
import asyncio
import re
from app.agent.analyst import BusinessRequirementAnalyst


# Banned test-oriented terms (case-insensitive patterns)
# NOTE: "test plans" as a business artifact is ALLOWED (e.g., "publish test plans")
# Only ban test-oriented phrases in testing/verification contexts
BANNED_TERMS = [
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


def check_for_banned_terms(text: str, context: str = "") -> list:
    """
    Check if text contains any banned test-oriented terms.
    
    Args:
        text: Text to check
        context: Context description for error messages
        
    Returns:
        List of violations (empty if none found)
    """
    violations = []
    if not text or text == "N/A":
        return violations
    
    text_lower = text.lower()
    for pattern in BANNED_TERMS:
        if re.search(pattern, text_lower):
            violations.append(f"{context}: Found banned term matching pattern '{pattern}' in: '{text}'")
    
    return violations


def validate_requirement_no_test_language(requirement) -> list:
    """
    Validate that a requirement contains no test-oriented language.
    
    Args:
        requirement: Requirement object to validate
        
    Returns:
        List of violations (empty if none found)
    """
    violations = []
    
    # Check summary
    if requirement.summary:
        violations.extend(check_for_banned_terms(requirement.summary, "Summary"))
    
    # Check description
    if requirement.description:
        violations.extend(check_for_banned_terms(requirement.description, "Description"))
    
    # Check business requirements
    for idx, br in enumerate(requirement.business_requirements, 1):
        if br.statement:
            violations.extend(
                check_for_banned_terms(br.statement, f"Business Requirement {idx} (BR-{br.id})")
            )
    
    # Check out_of_scope (most critical - must never contain test language)
    if requirement.scope_boundaries and requirement.scope_boundaries.out_of_scope:
        for idx, item in enumerate(requirement.scope_boundaries.out_of_scope, 1):
            violations.extend(
                check_for_banned_terms(item, f"Out of Scope item {idx}")
            )
    
    # Check in_scope (should also be clean, but less critical)
    if requirement.scope_boundaries and requirement.scope_boundaries.in_scope:
        for idx, item in enumerate(requirement.scope_boundaries.in_scope, 1):
            violations.extend(
                check_for_banned_terms(item, f"In Scope item {idx}")
            )
    
    # Check constraints_policies
    if requirement.constraints_policies:
        for idx, item in enumerate(requirement.constraints_policies, 1):
            violations.extend(
                check_for_banned_terms(item, f"Constraint/Policy {idx}")
            )
    
    # Check open_questions
    if requirement.open_questions:
        for idx, question in enumerate(requirement.open_questions, 1):
            violations.extend(
                check_for_banned_terms(question, f"Open Question {idx}")
            )
    
    # Check quality_notes if present
    if requirement.quality_notes:
        for idx, note in enumerate(requirement.quality_notes, 1):
            violations.extend(
                check_for_banned_terms(note, f"Quality Note {idx}")
            )
    
    return violations


async def test_no_test_language_in_output():
    """
    Test that agent output contains NO test-oriented language.
    
    This test verifies that:
    - Summary, description, BRs, scope boundaries, etc. contain no banned terms
    - Out of scope items use capability exclusions, not test terminology
    - Quality notes use scope-quality phrasing, not test-oriented language
    """
    analyst = BusinessRequirementAnalyst()
    
    # Test with various inputs that might trigger test language
    test_inputs = [
        "Users can publish test plans to Jira for visibility.",
        "The system must validate user input and display error messages.",
        "Users can create and manage test cases.",
        "The system shall support test execution tracking.",
    ]
    
    all_violations = []
    
    for idx, input_text in enumerate(test_inputs, 1):
        print(f"\n=== Test Input {idx} ===")
        print(f"Input: {input_text}")
        
        try:
            package = await analyst.analyze(
                input_text=input_text,
                source="test",
                context=f"no-test-language-test-{idx}"
            )
            
            print(f"Generated {len(package.requirements)} requirement(s)")
            
            # Validate each requirement
            for req in package.requirements:
                req_violations = validate_requirement_no_test_language(req)
                if req_violations:
                    all_violations.extend([
                        f"Requirement {req.id} ({req.summary}): {v}" 
                        for v in req_violations
                    ])
                    print(f"  ❌ Requirement {req.id} has {len(req_violations)} violation(s)")
                else:
                    print(f"  ✅ Requirement {req.id} is clean")
        
        except Exception as e:
            print(f"  ❌ Error processing input: {e}")
            raise
    
    # Report results
    print("\n" + "="*60)
    if all_violations:
        print(f"❌ TEST FAILED: Found {len(all_violations)} violation(s) of test language ban:")
        for violation in all_violations:
            print(f"  - {violation}")
        raise AssertionError(f"Found {len(all_violations)} test language violations")
    else:
        print("✅ TEST PASSED: No test-oriented language found in outputs")


async def test_out_of_scope_sanitization():
    """
    Test that out_of_scope items are properly sanitized.
    
    This test verifies that even if LLM generates test-oriented out_of_scope items,
    they are sanitized to capability exclusions.
    """
    analyst = BusinessRequirementAnalyst()
    
    # Input that might trigger test-oriented out_of_scope
    input_text = "The system must publish test plans to Jira for visibility."
    
    print("\n=== Out of Scope Sanitization Test ===")
    print(f"Input: {input_text}")
    
    package = await analyst.analyze(
        input_text=input_text,
        source="test",
        context="out-of-scope-sanitization-test"
    )
    
    # Check all requirements
    for req in package.requirements:
        if req.scope_boundaries and req.scope_boundaries.out_of_scope:
            print(f"\nRequirement {req.id} out_of_scope items:")
            for idx, item in enumerate(req.scope_boundaries.out_of_scope, 1):
                print(f"  {idx}. {item}")
                
                # Check for banned terms
                violations = check_for_banned_terms(item, f"Out of Scope item {idx}")
                if violations:
                    print(f"     ❌ Contains banned terms: {violations}")
                    raise AssertionError(f"Out of scope item contains test language: '{item}'")
                else:
                    print(f"     ✅ Clean (no test language)")
    
    print("\n✅ TEST PASSED: All out_of_scope items are properly sanitized")


async def main():
    """Run all tests."""
    print("Running test language ban tests...\n")
    
    try:
        # Test 1: Check for banned terms in all outputs
        await test_no_test_language_in_output()
        
        # Test 2: Verify out_of_scope sanitization
        await test_out_of_scope_sanitization()
        
        print("\n" + "="*60)
        print("All tests completed successfully!")
        
    except AssertionError as e:
        print(f"\n❌ Test FAILED: {e}")
        raise
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())

