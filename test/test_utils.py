"""Shared test utilities."""
import textwrap
import tempfile
import os
from typing import List, Tuple, Any, Optional, Callable

from core.facts import Fact
from core.context import ProjectContext
from rules.ir import Severity
from rules.hy_loader import HyRule
from rules.utils import find_hy_bindings
from move.parse import parse_move_source, build_code_facts
from analysis.structural import StructuralBuilder

# Re-export find_hy_bindings for backward compatibility
__all__ = ["find_hy_bindings", "make_hy_rule", "parse_move", "parse_move_full", "has_fact", "has_fact_prefix", "get_facts", "get_fact_args", "make_fact", "make_facts", "q"]


def make_hy_rule(
    name: str,
    predicate: Callable,
    match_pattern: str = "fun",
    match_modifiers: Optional[List[str]] = None,
    severity: Severity = Severity.MEDIUM,
) -> HyRule:
    """Create a HyRule for testing.

    Note: The predicate argument is used as filter_clause for backward compatibility.
    """
    return HyRule(
        name=name,
        severity=severity,
        match_pattern=match_pattern,
        match_modifiers=match_modifiers or [],
        match_binding="f",
        filter_clause=predicate,
    )


def parse_move(source: str) -> Tuple[Any, List[Fact], dict]:
    """Parse Move source and return (root, facts, location_map).

    NOTE: This only runs parsing, not the full structural analysis.
    Use parse_move_full() for tests that need IsCapability, ChecksCapability, etc.
    """
    source = textwrap.dedent(source)
    root = parse_move_source(source)
    facts, location_map = build_code_facts(source, root)
    return root, facts, location_map


def parse_move_full(source: str) -> Tuple[ProjectContext, List[Fact]]:
    """Parse Move source and run full structural analysis.

    Returns (ctx, facts) where facts is the list from the single file.
    Use this for tests that need IsCapability, ChecksCapability, and other derived facts.
    """
    source = textwrap.dedent(source)

    # Write to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.move', delete=False) as f:
        f.write(source)
        temp_path = f.name

    try:
        ctx = ProjectContext([temp_path])
        builder = StructuralBuilder()
        builder.build(ctx)
        facts = ctx.source_files[temp_path].facts
        return ctx, facts
    finally:
        os.unlink(temp_path)


def has_fact(facts: List[Fact], name: str, args: Tuple) -> bool:
    """Check if a fact with given name and args exists."""
    return any(f.name == name and f.args == args for f in facts)


def has_fact_prefix(facts: List[Fact], name: str, args_prefix: Tuple) -> bool:
    """Check if a fact with given name and args prefix exists."""
    return any(
        f.name == name and f.args[: len(args_prefix)] == args_prefix for f in facts
    )


def get_facts(facts: List[Fact], name: str) -> List[Fact]:
    """Get all facts with given name."""
    return [f for f in facts if f.name == name]


def get_fact_args(facts: List[Fact], name: str) -> List[Tuple]:
    """Get args of all facts with given name."""
    return [f.args for f in facts if f.name == name]


def make_fact(name: str, *args) -> Fact:
    """Create a fact with given name and args."""
    return Fact(name, args)


def make_facts(*specs) -> List[Fact]:
    """Create multiple facts from (name, *args) specs."""
    return [Fact(spec[0], spec[1:]) for spec in specs]


def q(module: str, name: str) -> str:
    """Qualify a name with module path."""
    return f"{module}::{name}"
