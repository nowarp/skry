from typing import Dict, List, Set, Optional
from dataclasses import dataclass, field

from llm.cache import get_llm_cache_registry


# =============================================================================
# Debug Mode
# =============================================================================


@dataclass
class VulnerabilityContext:
    """Rich context for a detected vulnerability (debug mode)."""

    func_name: str
    file_path: str
    classification: str
    reasoning: str
    entry_point: str = ""
    call_trace: List[str] = field(default_factory=list)
    sink_types: Set[str] = field(default_factory=set)
    attack_scenario: str = ""
    missing_checks: str = ""
    suggested_fix: str = ""

    def to_dict(self) -> Dict:
        return {
            "func_name": self.func_name,
            "file_path": self.file_path,
            "classification": self.classification,
            "reasoning": self.reasoning,
            "entry_point": self.entry_point,
            "call_trace": self.call_trace,
            "sink_types": list(self.sink_types),
            "attack_scenario": self.attack_scenario,
            "missing_checks": self.missing_checks,
            "suggested_fix": self.suggested_fix,
        }


_vulnerability_contexts: Dict[str, VulnerabilityContext] = {}


def get_vulnerability_context(func_name: str) -> Optional[VulnerabilityContext]:
    """Get stored vulnerability context for a function."""
    return _vulnerability_contexts.get(func_name)


def get_all_vulnerability_contexts() -> Dict[str, VulnerabilityContext]:
    """Get all stored vulnerability contexts."""
    return _vulnerability_contexts.copy()


def get_cached_llm_context(func_name: str) -> Optional[Dict]:
    """Load LLM context from cache for reporting (tries all registered caches)."""
    for cache in get_llm_cache_registry():
        data = cache.load_full(func_name)
        if data and data.get("is_vulnerable"):
            return data
    return None
