"""
LLM classification cache.

Handles caching of LLM classification results to avoid redundant API calls.

NOTE: Cache is keyed by source hash only. If prompt format changes, manually
clear .skry_cache/llm_* directories to invalidate stale results.
"""

import os
import json
import hashlib
from typing import List, Dict, Set, Optional, Tuple

from core.cache import CACHE_DIR
from core.utils import debug, warn


class LLMCache:
    """Generic cache for LLM classification results."""

    def __init__(self, cache_name: str):
        self.cache_dir = f".{CACHE_DIR}/llm_{cache_name}"
        self.cache_name = cache_name

    @staticmethod
    def _to_safe_name(func_name: str) -> str:
        """Convert function name to safe filename prefix."""
        return func_name.replace("::", "_").replace("<", "_").replace(">", "_")

    def _get_path(self, func_name: str, file_path: str) -> str:
        """Get cache file path for a function."""
        os.makedirs(self.cache_dir, exist_ok=True)
        key = f"{file_path}::{func_name}"
        key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
        safe_name = self._to_safe_name(func_name)
        return os.path.join(self.cache_dir, f"{safe_name}_{key_hash}.json")

    def load(self, func_name: str, file_path: str, source_hash: str) -> Optional[Tuple[bool, str, Optional[bool]]]:
        """Load cached result if valid.

        Returns:
            Tuple of (is_vulnerable, reason, has_access_control) or None if not cached.
        """
        if os.environ.get("SKRY_LLM_NOCACHE", "0").lower() == "1":
            debug(f"[{self.cache_name}] Cache bypass (SKRY_LLM_NOCACHE=1)")
            return None
        cache_path = self._get_path(func_name, file_path)
        if not os.path.exists(cache_path):
            return None
        try:
            with open(cache_path, "r") as f:
                data = json.load(f)
            if data.get("source_hash") != source_hash:
                return None
            return (data["is_vulnerable"], data["reason"], data.get("has_access_control"))
        except Exception as e:
            debug(f"[{self.cache_name}] Cache read error: {e}")
            return None

    def load_full(self, func_name: str) -> Optional[Dict]:
        """Load full cached data without hash validation (for reporting)."""
        if not os.path.exists(self.cache_dir):
            return None
        # Filter by filename prefix to avoid scanning all files
        safe_prefix = self._to_safe_name(func_name) + "_"
        for filename in os.listdir(self.cache_dir):
            if not filename.startswith(safe_prefix) or not filename.endswith(".json"):
                continue
            cache_path = os.path.join(self.cache_dir, filename)
            try:
                with open(cache_path, "r") as f:
                    data = json.load(f)
                # Validate func_name matches (in case of prefix collision)
                if data.get("func_name") == func_name:
                    return data
            except Exception:
                continue
        return None

    def save(
        self,
        func_name: str,
        file_path: str,
        source_hash: str,
        is_vulnerable: bool,
        reason: str,
        call_trace: Optional[List[str]] = None,
        sink_types: Optional[Set[str]] = None,
        has_access_control: Optional[bool] = None,
    ) -> None:
        """Save result to cache with optional extended context."""
        cache_path = self._get_path(func_name, file_path)
        try:
            data = {
                "func_name": func_name,
                "file_path": file_path,
                "source_hash": source_hash,
                "is_vulnerable": is_vulnerable,
                "reason": reason,
            }
            if call_trace:
                data["call_trace"] = call_trace
            if sink_types:
                data["sink_types"] = list(sink_types)
            if has_access_control is not None:
                data["has_access_control"] = has_access_control
            with open(cache_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            warn(f"[{self.cache_name}] Cache write error: {e}")


# Cache instances and registry
_llm_cache_registry: List[LLMCache] = []


def _register_cache(name: str) -> LLMCache:
    """Create and register an LLM cache instance."""
    cache = LLMCache(name)
    _llm_cache_registry.append(cache)
    return cache


def get_llm_cache_registry() -> List[LLMCache]:
    """Get all registered LLM caches."""
    return _llm_cache_registry


# Pre-registered cache instances
access_control_cache = _register_cache("access_control")
unlock_cache = _register_cache("unlock")
drain_cache = _register_cache("drain")
transfer_cache = _register_cache("transfer")
sensitive_setter_cache = _register_cache("sensitive_setter")
internal_helper_exposure_cache = _register_cache("internal_helper_exposure")
