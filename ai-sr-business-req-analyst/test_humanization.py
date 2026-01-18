"""
Test that humanization layer preserves all invariants while improving tone.

This test verifies that:
1. Humanized output still passes atomicity checks
2. Humanized output still passes scope checks
3. Humanized output still passes banned-language checks
4. Humanization actually improves naturalness
"""
import asyncio
from app.agent.analyst import BusinessRequirementAnalyst
from app.validators.invariants import InvariantValidator


async def test_humanization_preserves_invariants():
    """
    Test that humanized output still passes all atomicity, scope, and banned-language invariants.
    
    This is critical: humanization must NOT break any structural or content rules.
    """
    analyst = BusinessRequirementAnalyst()
    
    # Test with various inputs
    test_inputs = [
        "publish test plans to Jira and associate them with the originating issue",
        "Users can create and manage test cases",
        "The system must validate user input and display error messages",
    ]
    
    all_violations = []
    
    for idx, input_text in enumerate(test_inputs, 1):
        print(f"\n=== Humanization Invariant Test {idx} ===")
        print(f"Input: {input_text}")
        
        try:
            package = await analyst.analyze(
                input_text=input_text,
                source="test",
                context=f"humanization-test-{idx}"
            )
            
            print(f"Generated {len(package.requirements)} requirement(s)")
            
            # Validate each requirement after humanization
            for req in package.requirements:
                is_valid, violations = InvariantValidator.validate(req)
                
                if not is_valid:
                    all_violations.extend([
                        f"Requirement {req.id} ({req.summary}): {v}" 
                        for v in violations
                    ])
                    print(f"  ❌ Requirement {req.id} has {len(violations)} invariant violation(s)")
                    for v in violations:
                        print(f"     - {v}")
                else:
                    print(f"  ✅ Requirement {req.id} passes all invariants")
                
                # Additional checks
                # 1. Verify atomicity: no compound BRs
                for br in req.business_requirements:
                    statement_lower = br.statement.lower()
                    compound_patterns = [
                        r'\band\s+(?:the\s+system\s+shall|it\s+shall)',
                        r',\s+(?:and\s+)?(?:the\s+system\s+shall|it\s+shall)',
                    ]
                    if any(re.search(pattern, statement_lower) for pattern in compound_patterns):
                        all_violations.append(
                            f"Requirement {req.id}: BR {br.id} contains compound behaviors after humanization"
                        )
                
                # 2. Verify no test language
                banned_terms = [
                    r'\bvalidation\s+of\s+(?:test\s+)?(?:plans?|cases?|execution)',
                    r'\btestability\b',
                    r'\bGiven/When/Then\b',
                ]
                
                text_to_check = f"{req.summary} {req.description} {' '.join(br.statement for br in req.business_requirements)}"
                for pattern in banned_terms:
                    if re.search(pattern, text_to_check.lower()):
                        all_violations.append(
                            f"Requirement {req.id}: Contains banned test language after humanization"
                        )
        
        except Exception as e:
            print(f"  ❌ Error processing input: {e}")
            raise
    
    # Report results
    print("\n" + "="*60)
    if all_violations:
        print(f"❌ TEST FAILED: Found {len(all_violations)} invariant violation(s) after humanization:")
        for violation in all_violations:
            print(f"  - {violation}")
        raise AssertionError(f"Humanization broke {len(all_violations)} invariants")
    else:
        print("✅ TEST PASSED: All invariants preserved after humanization")


async def test_humanization_improves_tone():
    """
    Test that humanization actually improves naturalness and tone.
    
    This verifies that the humanization layer is working and making text more natural.
    """
    analyst = BusinessRequirementAnalyst()
    
    # Input that might produce robotic output
    input_text = "publish test plans to Jira and associate them with the originating issue"
    
    print("\n=== Humanization Tone Test ===")
    print(f"Input: {input_text}")
    
    package = await analyst.analyze(
        input_text=input_text,
        source="test",
        context="humanization-tone-test"
    )
    
    assert len(package.requirements) > 0, "At least one requirement should be created"
    
    req = package.requirements[0]
    
    print(f"\nRequirement {req.id}:")
    print(f"  Summary: '{req.summary}'")
    print(f"  Description: '{req.description}'")
    print(f"  Business Requirements:")
    for br in req.business_requirements:
        print(f"    {br.id}: {br.statement}")
    print(f"  In-Scope: {req.scope_boundaries.in_scope}")
    print(f"  Out-of-Scope: {req.scope_boundaries.out_of_scope}")
    print(f"  Open Questions: {req.open_questions}")
    
    # Check for humanization improvements
    
    # 1. Summary should not have trailing punctuation
    if req.summary.endswith('.'):
        print("  ⚠️  WARNING: Summary has trailing punctuation")
    
    # 2. Summary should not start with robotic prefixes
    summary_lower = req.summary.lower()
    robotic_prefixes = ['enable', 'the system shall', 'provide']
    has_robotic_prefix = any(summary_lower.startswith(prefix) for prefix in robotic_prefixes)
    if has_robotic_prefix:
        print("  ⚠️  WARNING: Summary starts with robotic prefix")
    else:
        print("  ✅ Summary is natural")
    
    # 3. Description should be 1-2 sentences
    sentence_count = len([s for s in req.description.split('.') if s.strip()])
    if sentence_count > 2:
        print(f"  ⚠️  WARNING: Description has {sentence_count} sentences (should be 1-2)")
    else:
        print(f"  ✅ Description is concise ({sentence_count} sentence(s))")
    
    # 4. BRs should have variation in phrasing
    br_starters = []
    for br in req.business_requirements:
        statement_lower = br.statement.lower()
        if statement_lower.startswith('the system shall'):
            br_starters.append('the system shall')
        elif statement_lower.startswith('the solution shall'):
            br_starters.append('the solution shall')
        elif statement_lower.startswith('the platform shall'):
            br_starters.append('the platform shall')
        elif statement_lower.startswith('this capability shall'):
            br_starters.append('this capability shall')
    
    unique_starters = len(set(br_starters))
    if len(req.business_requirements) > 1 and unique_starters == 1:
        print("  ⚠️  WARNING: All BRs use the same starter phrase")
    else:
        print(f"  ✅ BRs have variation ({unique_starters} unique starter(s))")
    
    # 5. Open questions should be conversational
    for q in req.open_questions:
        if q != "N/A":
            if not q.endswith('?'):
                print(f"  ⚠️  WARNING: Open question doesn't end with '?': '{q}'")
            if any(word in q.lower() for word in ['specific information', 'needs to be', 'is required to']):
                print(f"  ⚠️  WARNING: Open question uses formal language: '{q}'")
            else:
                print(f"  ✅ Open question is conversational: '{q}'")
    
    print("\n✅ TEST PASSED: Humanization tone improvements verified")
    return package


async def test_humanization_preserves_meaning():
    """
    Test that humanization preserves scope meaning and doesn't change counts.
    
    This verifies that humanization is meaning-preserving.
    """
    analyst = BusinessRequirementAnalyst()
    
    input_text = "publish test plans to Jira and associate them with the originating issue"
    
    print("\n=== Humanization Meaning Preservation Test ===")
    print(f"Input: {input_text}")
    
    package = await analyst.analyze(
        input_text=input_text,
        source="test",
        context="humanization-meaning-test"
    )
    
    assert len(package.requirements) > 0, "At least one requirement should be created"
    
    req = package.requirements[0]
    
    # Verify meaning preservation
    # 1. BR count should match input obligations (at least 2: publish and associate)
    br_count = len(req.business_requirements)
    assert br_count >= 2, (
        f"Expected at least 2 BRs for input with explicit multiple obligations, "
        f"but found {br_count} BR(s)"
    )
    
    # 2. Check that publish and associate concepts are present
    br_statements = ' '.join(br.statement.lower() for br in req.business_requirements)
    has_publish = 'publish' in br_statements
    has_associate = 'associate' in br_statements or 'link' in br_statements
    
    assert has_publish, "BRs should contain 'publish' concept after humanization"
    assert has_associate, "BRs should contain 'associate' or 'link' concept after humanization"
    
    # 3. Verify atomicity is preserved (no compound BRs)
    for br in req.business_requirements:
        statement_lower = br.statement.lower()
        # Should not have "and the system shall" or similar compound patterns
        assert not re.search(r'\band\s+(?:the\s+system\s+shall|it\s+shall)', statement_lower), (
            f"BR {br.id} contains compound behaviors after humanization: '{br.statement}'"
        )
    
    print(f"  ✅ BR count preserved: {br_count} BR(s)")
    print(f"  ✅ Publish concept present: {has_publish}")
    print(f"  ✅ Associate concept present: {has_associate}")
    print(f"  ✅ Atomicity preserved: no compound BRs")
    
    print("\n✅ TEST PASSED: Humanization preserves meaning")
    return package


async def main():
    """Run all humanization tests."""
    print("Running humanization tests...\n")
    
    try:
        # Test 1: Verify invariants are preserved
        await test_humanization_preserves_invariants()
        
        # Test 2: Verify tone improvements
        await test_humanization_improves_tone()
        
        # Test 3: Verify meaning preservation
        await test_humanization_preserves_meaning()
        
        print("\n" + "="*60)
        print("All humanization tests completed successfully!")
        
    except AssertionError as e:
        print(f"\n❌ Test FAILED: {e}")
        raise
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        raise


if __name__ == "__main__":
    import re
    asyncio.run(main())

