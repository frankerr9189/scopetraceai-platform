"""
Deterministic ID generation for requirements and packages.
"""
from typing import Optional
import hashlib


def generate_requirement_id(prefix: str = "REQ", seed: Optional[str] = None) -> str:
    """
    Generate a deterministic requirement ID.
    
    Args:
        prefix: ID prefix (default: "REQ")
        seed: Optional seed for deterministic generation
        
    Returns:
        Generated requirement ID
    """
    # TODO: Implement deterministic ID generation
    if seed:
        hash_value = hashlib.md5(seed.encode()).hexdigest()[:8]
        return f"{prefix}-{hash_value.upper()}"
    return f"{prefix}-PLACEHOLDER"


def generate_package_id(prefix: str = "PKG", seed: Optional[str] = None) -> str:
    """
    Generate a deterministic package ID.
    
    Args:
        prefix: ID prefix (default: "PKG")
        seed: Optional seed for deterministic generation
        
    Returns:
        Generated package ID
    """
    # TODO: Implement deterministic package ID generation
    if seed:
        hash_value = hashlib.md5(seed.encode()).hexdigest()[:8]
        return f"{prefix}-{hash_value.upper()}"
    return f"{prefix}-PLACEHOLDER"

