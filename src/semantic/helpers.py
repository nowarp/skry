"""
Helper functions for semantic property checking.

Contains utilities for extracting binding keys from rules and fact lookups.
"""

from typing import Optional, Type, List, Callable, TYPE_CHECKING

from core.facts import Fact
from rules.ir import (
    Rule,
    CapabilityPattern,
    EventPattern,
    FunPattern,
)

if TYPE_CHECKING:
    from semantic.checker import SemanticChecker


# =============================================================================
# Fact gathering and checking helpers
# =============================================================================


def gather_facts_for_func(checker: "SemanticChecker", facts: List[Fact], func_name: str) -> List[Fact]:
    """Gather local facts + global index facts for a function."""
    all_facts = list(facts)
    if checker.ctx.global_facts_index and func_name in checker.ctx.global_facts_index:
        for file_facts in checker.ctx.global_facts_index[func_name].values():
            all_facts.extend(file_facts)
    return all_facts


def has_fact(facts: List[Fact], fact_name: str, match_fn: Callable[[Fact], bool]) -> bool:
    """Check if any fact matches criteria."""
    return any(f.name == fact_name and match_fn(f) for f in facts)


def find_fact(facts: List[Fact], fact_name: str, match_fn: Callable[[Fact], bool]) -> Optional[Fact]:
    """Find first fact matching criteria."""
    for f in facts:
        if f.name == fact_name and match_fn(f):
            return f
    return None


def apply_negation(result: bool, negation: bool) -> bool:
    """Apply negation if needed."""
    return not result if negation else result


# =============================================================================
# Binding key extraction helpers
# =============================================================================


def _get_binding_key(rule: Rule, pattern_class: Type, pattern_type: str) -> Optional[str]:
    """
    Generic helper to get binding key from a rule.

    Args:
        rule: The rule to extract binding from
        pattern_class: The pattern class to check (FunPattern, RolePattern, EventPattern)
        pattern_type: The type string for duck-typed MinimalPattern ("fun", "role", "event")
    """
    pattern = rule.match_clause.pattern
    if isinstance(pattern, pattern_class):
        return pattern.binding  # type: ignore[union-attr]
    # Duck-type check for MinimalPattern from hy_bridge
    if hasattr(pattern, "binding") and hasattr(pattern, "type") and pattern.type == pattern_type:
        return str(pattern.binding) if pattern.binding else None
    return None


def get_function_binding_key(rule: Rule) -> Optional[str]:
    """Get the function binding key from a rule."""
    return _get_binding_key(rule, FunPattern, "fun")


def get_capability_binding_key(rule: Rule) -> Optional[str]:
    """Get the capability binding key from a rule."""
    return _get_binding_key(rule, CapabilityPattern, "capability")


def get_event_binding_key(rule: Rule) -> Optional[str]:
    """Get the event binding key from a rule."""
    return _get_binding_key(rule, EventPattern, "event")
