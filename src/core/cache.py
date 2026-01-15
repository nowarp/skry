"""
Cache configuration for LLM prompts cache.
"""

import os
import hashlib


CACHE_DIR = os.environ.get("SKRY_CACHE_DIR", "./.skry_cache")


def sha256(data: str) -> str:
    """Compute SHA256 hash of a string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()
