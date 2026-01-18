"""
Test script for the Business Requirement Analyst.
"""
import asyncio
from app.agent.analyst import BusinessRequirementAnalyst


async def main():
    """Test the analyst with a sample requirement."""
    analyst = BusinessRequirementAnalyst()
    
    package = await analyst.analyze(
        input_text="Users can manage their profile information.",
        source="manual",
        context="smoke-test-001"
    )
    
    # Use model_dump_json() for Pydantic v2
    print(package.model_dump_json(indent=2))


if __name__ == "__main__":
    asyncio.run(main())

