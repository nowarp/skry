"""
Hy Rules Loader - Load security rules written in Hy.

This module replaces the Lark-based parser.py for loading rules.
Rules are written in Hy (a Lisp dialect) and compiled to Python at load time.

Usage:
    from rules.hy_loader import load_hy_rules
    rules = load_hy_rules("rules/access_control.hy")
"""

import sys
from pathlib import Path
from typing import List, Dict, Callable, Optional
from dataclasses import dataclass, field

from rules.ir import Severity


@dataclass
class HyRule:
    """
    Rule loaded from Hy - compatible with existing evaluation pipeline.

    This replaces the Rule class from ir.py for Hy-based rules.
    The key difference: predicates are callables instead of AST.

    Rule evaluation flow:
    1. filter_clause: Structural checks (fast, no LLM). Returns candidates.
    2. classify_clause: Semantic checks (may use LLM). Returns final matches.

    A rule can have:
    - Only :filter (structural-only rules, produce violations directly)
    - Both :filter and :classify (LLM-assisted rules)
    """

    name: str
    severity: Severity = Severity.MEDIUM
    categories: List[str] = field(default_factory=list)
    description: str = ""

    # Pattern matching config (used by matcher.py)
    match_pattern: str = "fun"  # "fun", "role", "event", "const"
    match_modifiers: List[str] = field(default_factory=list)  # ["public", "entry"]
    match_binding: str = "f"

    # Filter clause: (entity: str, facts: List[Fact], ctx: EvalContext) -> bool
    # Structural checks - fast, no LLM. Produces candidates for classify.
    filter_clause: Optional[Callable] = None

    # Classify clause: (entity: str, facts: List[Fact], ctx: EvalContext) -> bool
    # Semantic checks - may use LLM. Runs only on filter candidates.
    classify_clause: Optional[Callable] = None

    # Required features - auto-detected from filter/classify clauses
    # e.g. ["version", "category"] - triggers expensive fact generators
    features: List[str] = field(default_factory=list)

    @property
    def requires_llm(self) -> bool:
        """Rule requires LLM if it has a classify clause."""
        return self.classify_clause is not None

    def __repr__(self):
        mods = " ".join(self.match_modifiers)
        llm_tag = " [LLM]" if self.requires_llm else ""
        return f"HyRule({self.name}, {self.severity.value}, match={mods} {self.match_pattern}{llm_tag})"


# Global registry - Hy defrule macro registers rules here
_registered_rules: Dict[str, HyRule] = {}


def register_rule(rule: HyRule) -> None:
    """
    Register a rule. Called by the defrule macro.

    Args:
        rule: HyRule instance to register
    """
    _registered_rules[rule.name] = rule


def clear_registry() -> None:
    """Clear all registered rules. Used before loading new files."""
    _registered_rules.clear()


def _ensure_hy_imported():
    """Ensure Hy is installed and importable."""
    try:
        import hy
        import hy.importer

        return hy
    except ImportError:
        raise ImportError("Hy is not installed. Install with: pip install hy\nRequired version: hy>=0.28.0")


def _add_macros_to_path():
    """Add the hy/ directory to Hy's import path."""
    hy_dir = Path(__file__).parent / "hy"
    if str(hy_dir) not in sys.path:
        sys.path.insert(0, str(hy_dir))


def load_hy_rules(path: str) -> List[HyRule]:
    """
    Load all rules from a single .hy file.

    Args:
        path: Path to .hy file

    Returns:
        List of HyRule objects defined in the file
    """
    hy = _ensure_hy_imported()
    _add_macros_to_path()

    # Convert path to absolute
    abs_path = str(Path(path).resolve())

    # Track rules before loading
    initial_rules = set(_registered_rules.keys())

    # Execute the Hy file - this triggers defrule calls which register rules
    try:
        hy.importer.runhy.run_path(abs_path)
    except Exception as e:
        raise RuntimeError(f"Failed to load Hy rules from {path}: {e}") from e

    # Return only newly registered rules
    new_rules = [rule for name, rule in _registered_rules.items() if name not in initial_rules]

    # If no new rules (file was already loaded), return rules that match this file's pattern
    # This handles the case where the file was previously loaded
    if not new_rules:
        # Heuristic: rules from a file usually have names related to the file
        # But more reliably, just return all rules if this is a reload
        # Actually, let's just return all rules - the caller can filter if needed
        new_rules = list(_registered_rules.values())

    return new_rules


def severity_from_keyword(kw: str) -> Severity:
    """
    Convert Hy keyword to Severity enum.

    Args:
        kw: Keyword like ":high", ":critical", "high", etc.

    Returns:
        Severity enum value
    """
    # Strip leading colon if present (Hy keyword)
    clean = kw.lstrip(":").lower()

    mapping = {
        "info": Severity.INFO,
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }

    return mapping.get(clean, Severity.MEDIUM)
