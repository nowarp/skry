"""
LLM prompt-response cache.

Caches LLM responses by prompt hash to avoid redundant API calls.
"""

import json
import hashlib
import shutil
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from core.cache import CACHE_DIR


class PromptCache:
    """
    Cache for LLM prompt-response pairs.

    Stores responses in CACHE_DIR/llm_prompts/ as JSON files.
    Cache key is sha256(prompt)[:12].
    """

    def __init__(self, cache_dir: Optional[Path] = None):
        """
        Initialize prompt cache.

        Args:
            cache_dir: Optional cache directory override. Defaults to CACHE_DIR/llm_prompts/
        """
        base = Path(cache_dir) if cache_dir is not None else Path(CACHE_DIR)
        self.cache_dir = base / "llm_prompts"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _hash(self, prompt: str) -> str:
        """
        Generate hash for prompt.

        Args:
            prompt: The prompt text

        Returns:
            First 12 characters of SHA256 hash
        """
        return hashlib.sha256(prompt.encode()).hexdigest()[:12]

    def get(self, prompt: str) -> Optional[Dict[str, Any]]:
        """
        Get cached response for prompt.

        Args:
            prompt: The prompt text

        Returns:
            Cached response dict, or None if not found
        """
        prompt_hash = self._hash(prompt)
        path = self.cache_dir / f"{prompt_hash}.json"

        if not path.exists():
            return None

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data["response"]
        except (json.JSONDecodeError, KeyError, OSError):
            # Corrupted cache entry - treat as miss
            return None

    def put(self, prompt: str, model: str, response: Dict[str, Any]) -> None:
        """
        Store response in cache.

        Args:
            prompt: The prompt text
            model: Model identifier
            response: Response data to cache
        """
        prompt_hash = self._hash(prompt)
        path = self.cache_dir / f"{prompt_hash}.json"

        data = {
            "prompt_hash": prompt_hash,
            "prompt": prompt,
            "model": model,
            "response": response,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        try:
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except OSError:
            # Disk full or permission error - fail silently
            pass

    def clear(self) -> int:
        """
        Clear all cached prompts.

        Returns:
            Number of cache entries removed
        """
        count = len(list(self.cache_dir.glob("*.json")))
        if count > 0:
            shutil.rmtree(self.cache_dir)
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        return count

    def stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache size and count
        """
        files = list(self.cache_dir.glob("*.json"))
        total_size = sum(f.stat().st_size for f in files)

        return {
            "count": len(files),
            "size_bytes": total_size,
            "size_mb": total_size / (1024 * 1024),
        }
