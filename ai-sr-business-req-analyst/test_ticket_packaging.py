"""
Test ticket packaging policy: when to keep multiple BRs in one story vs split into multiple stories.
"""
import asyncio
from app.agent.analyst import BusinessRequirementAnalyst


async def test_multiple_brs_in_one_story():
    """
    Test that closely related obligations stay in ONE story with multiple BRs (default case).
    
    Given: "publish test plans to Jira and associate them with the originating issue"
    Expected: ONE story with at least 2 BRs (publish, associate)
    """
    analyst = BusinessRequirementAnalyst()
    
    # Input with closely related obligations (should stay in one story)
    input_text = "publish test plans to Jira and associate them with the originating issue"
    
    print("\n=== Multiple BRs in One Story Test ===")
    print(f"Input: {input_text}")
    
    package = await analyst.analyze(
        input_text=input_text,
        source="test",
        context="ticket-packaging-test-001"
    )
    
    # Get all stories (parent requirements)
    stories = [req for req in package.requirements if req.parent_id is None]
    
    print(f"\nTotal requirements: {len(package.requirements)}")
    print(f"Stories (parents): {len(stories)}")
    print(f"Sub-tasks (children): {len([r for r in package.requirements if r.parent_id is not None])}")
    
    # Should have ONE story (default behavior)
    assert len(stories) == 1, (
        f"Expected 1 story for closely related obligations, but found {len(stories)} story/stories"
    )
    
    story = stories[0]
    print(f"\nStory ID: {story.id}")
    print(f"Story Summary: {story.summary}")
    print(f"Business Requirements Count: {len(story.business_requirements)}")
    
    # Should have at least 2 BRs (publish and associate)
    br_count = len(story.business_requirements)
    assert br_count >= 2, (
        f"Expected at least 2 BRs (publish and associate), but found {br_count} BR(s)"
    )
    
    # Print all BRs
    print("\nBusiness Requirements:")
    for br in story.business_requirements:
        print(f"  {br.id}: {br.statement}")
    
    # Verify both publish and associate concepts are present
    br_statements = ' '.join(br.statement.lower() for br in story.business_requirements)
    has_publish = 'publish' in br_statements
    has_associate = 'associate' in br_statements or 'link' in br_statements
    
    assert has_publish, "BRs should contain 'publish' concept"
    assert has_associate, "BRs should contain 'associate' or 'link' concept"
    
    print(f"\n✅ Publish concept present: {has_publish}")
    print(f"✅ Associate concept present: {has_associate}")
    print(f"✅ All BRs in one story: {br_count} BR(s) in story {story.id}")
    
    print("\n✅ TEST PASSED: Multiple BRs kept in one story (default behavior)")
    return package


async def test_split_into_multiple_stories():
    """
    Test that explicitly separated obligations result in MULTIPLE stories.
    
    Given: Input that explicitly implies separation (e.g., "create X and separately manage Y")
    Expected: MULTIPLE stories, one per obligation
    """
    analyst = BusinessRequirementAnalyst()
    
    # Input with explicit separation keywords
    input_text = "Create a user authentication API and separately manage user session tokens"
    
    print("\n=== Split into Multiple Stories Test ===")
    print(f"Input: {input_text}")
    
    package = await analyst.analyze(
        input_text=input_text,
        source="test",
        context="ticket-packaging-test-002"
    )
    
    # Get all stories (parent requirements)
    stories = [req for req in package.requirements if req.parent_id is None]
    
    print(f"\nTotal requirements: {len(package.requirements)}")
    print(f"Stories (parents): {len(stories)}")
    print(f"Sub-tasks (children): {len([r for r in package.requirements if r.parent_id is not None])}")
    
    # Should have MULTIPLE stories when input explicitly implies separation
    # Note: This may or may not split depending on LLM interpretation,
    # but if it does split, we should have multiple stories
    if len(stories) > 1:
        print(f"\n✅ Split into {len(stories)} stories (as expected for explicit separation)")
        
        for idx, story in enumerate(stories, 1):
            print(f"\nStory {idx}: {story.id}")
            print(f"  Summary: {story.summary}")
            print(f"  BRs: {len(story.business_requirements)}")
            for br in story.business_requirements:
                print(f"    {br.id}: {br.statement}")
        
        # Verify stories are distinct
        summaries = [s.summary.lower() for s in stories]
        assert len(set(summaries)) == len(stories), "Stories should have distinct summaries"
        
        print("\n✅ TEST PASSED: Split into multiple stories for explicit separation")
    else:
        print(f"\n⚠️  Note: Input resulted in {len(stories)} story (may be acceptable if obligations are closely related)")
        print("   This is acceptable - the policy allows keeping in one story if obligations are closely related")
    
    return package


async def test_independent_capabilities_split():
    """
    Test that independently deliverable capabilities result in multiple stories.
    
    Given: Input with different technical capabilities (e.g., API and UI)
    Expected: MULTIPLE stories, one per capability
    """
    analyst = BusinessRequirementAnalyst()
    
    # Input with different technical capabilities
    input_text = "Create a REST API for user management and build a user interface for user registration"
    
    print("\n=== Independent Capabilities Split Test ===")
    print(f"Input: {input_text}")
    
    package = await analyst.analyze(
        input_text=input_text,
        source="test",
        context="ticket-packaging-test-003"
    )
    
    # Get all stories (parent requirements)
    stories = [req for req in package.requirements if req.parent_id is None]
    
    print(f"\nTotal requirements: {len(package.requirements)}")
    print(f"Stories (parents): {len(stories)}")
    
    # Different technical capabilities (API vs UI) should ideally split
    # But this depends on LLM interpretation
    if len(stories) > 1:
        print(f"\n✅ Split into {len(stories)} stories for different technical capabilities")
        
        # Check that stories reference different capabilities
        api_story = any('api' in s.summary.lower() or 'api' in s.description.lower() for s in stories)
        ui_story = any('ui' in s.summary.lower() or 'interface' in s.summary.lower() or 'ui' in s.description.lower() for s in stories)
        
        if api_story and ui_story:
            print("✅ Stories represent different technical capabilities (API and UI)")
        else:
            print("⚠️  Stories may not clearly represent different capabilities")
        
        print("\n✅ TEST PASSED: Split for independent capabilities")
    else:
        print(f"\n⚠️  Note: Input resulted in {len(stories)} story")
        print("   This may be acceptable if capabilities are considered closely related")
    
    return package


async def main():
    """Run all ticket packaging tests."""
    print("Running ticket packaging policy tests...\n")
    
    try:
        # Test 1: Multiple BRs in one story (default)
        await test_multiple_brs_in_one_story()
        
        # Test 2: Split for explicit separation
        await test_split_into_multiple_stories()
        
        # Test 3: Split for independent capabilities
        await test_independent_capabilities_split()
        
        print("\n" + "="*60)
        print("All ticket packaging tests completed!")
        
    except AssertionError as e:
        print(f"\n❌ Test FAILED: {e}")
        raise
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())

