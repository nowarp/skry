"""Tests for LLM prompt cache."""

import tempfile
from pathlib import Path

from llm.prompt_cache import PromptCache


def test_cache_basic():
    """Test basic cache operations."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = PromptCache(cache_dir=Path(tmpdir))

        prompt = "Is this code safe?"
        response = {"result": True}

        # Initially empty
        assert cache.get(prompt) is None

        # Store and retrieve
        cache.put(prompt, "test-model", response)
        cached = cache.get(prompt)
        assert cached == response

        # Same prompt returns cached value
        assert cache.get(prompt) == response


def test_cache_different_prompts():
    """Test cache distinguishes between different prompts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = PromptCache(cache_dir=Path(tmpdir))

        prompt1 = "Is this safe?"
        prompt2 = "Is this vulnerable?"
        response1 = {"result": True}
        response2 = {"result": False}

        cache.put(prompt1, "test-model", response1)
        cache.put(prompt2, "test-model", response2)

        assert cache.get(prompt1) == response1
        assert cache.get(prompt2) == response2


def test_cache_clear():
    """Test cache clearing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = PromptCache(cache_dir=Path(tmpdir))

        cache.put("prompt1", "model", {"result": True})
        cache.put("prompt2", "model", {"result": False})

        assert cache.stats()["count"] == 2

        count = cache.clear()
        assert count == 2
        assert cache.stats()["count"] == 0


def test_cache_stats():
    """Test cache statistics."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = PromptCache(cache_dir=Path(tmpdir))

        stats = cache.stats()
        assert stats["count"] == 0
        assert stats["size_bytes"] == 0

        cache.put("test prompt", "model", {"result": True})

        stats = cache.stats()
        assert stats["count"] == 1
        assert stats["size_bytes"] > 0


def test_cache_corrupted_json():
    """Test that corrupted cache entries are treated as cache miss."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = PromptCache(cache_dir=Path(tmpdir))

        prompt = "test prompt"
        prompt_hash = cache._hash(prompt)
        cache_file = cache.cache_dir / f"{prompt_hash}.json"

        # Write corrupted JSON
        cache_file.write_text("not valid json")

        # Should return None (cache miss)
        assert cache.get(prompt) is None


def test_cache_persistence():
    """Test that cache persists across instances."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_dir = Path(tmpdir)

        # Create first cache instance and store data
        cache1 = PromptCache(cache_dir=cache_dir)
        prompt = "persistent test"
        response = {"result": True}
        cache1.put(prompt, "model", response)

        # Create second cache instance and verify data is there
        cache2 = PromptCache(cache_dir=cache_dir)
        assert cache2.get(prompt) == response


def test_cache_hash_stability():
    """Test that hash function is stable."""
    cache = PromptCache()
    prompt = "test prompt"

    hash1 = cache._hash(prompt)
    hash2 = cache._hash(prompt)

    assert hash1 == hash2
    assert len(hash1) == 12
