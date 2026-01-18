"""
Utility function for generating URL-friendly slugs from text.

Converts text to a deterministic slug:
- Lowercase
- Replace whitespace with hyphens
- Remove punctuation/special chars (keep a-z, 0-9, hyphen)
- Collapse multiple hyphens
- Trim leading/trailing hyphens
"""
import re


def slugify(text: str) -> str:
    """
    Convert text to a URL-friendly slug.
    
    Args:
        text: Input text to convert to slug
        
    Returns:
        str: URL-friendly slug
        
    Examples:
        >>> slugify("Demo Client")
        'demo-client'
        >>> slugify("  My   Company  ")
        'my-company'
        >>> slugify("Test & Co.!!!")
        'test-co'
        >>> slugify("ABC---123")
        'abc-123'
    """
    if not text:
        return ""
    
    # Convert to lowercase
    slug = text.lower()
    
    # Replace whitespace with hyphens
    slug = re.sub(r'\s+', '-', slug)
    
    # Remove all characters except a-z, 0-9, and hyphens
    slug = re.sub(r'[^a-z0-9-]', '', slug)
    
    # Collapse multiple consecutive hyphens into a single hyphen
    slug = re.sub(r'-+', '-', slug)
    
    # Trim leading and trailing hyphens
    slug = slug.strip('-')
    
    return slug
