"""
Rules IR - Internal Representation for security rules.

This module defines the core data structures used by both Hy rules and semantic checks.
"""

from typing import List, Optional
from dataclasses import dataclass
from enum import Enum


ID = str


class Binding(dict):
    """
    Binding maps rule pattern variables to matched values.

    Example:
    For a rule matching public entry functions, generates:
    * `{ 'f': 'module::function_name' }`
    """

    pass


class Severity(Enum):
    """Rule severity levels, ordered from lowest to highest."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_string(cls, s: str) -> "Severity":
        """Parse severity from string."""
        s_lower = s.lower().strip()
        for sev in cls:
            if sev.value == s_lower:
                return sev
        raise ValueError(f"Unknown severity: {s}")

    @property
    def level(self) -> int:
        """Numeric level for comparison (higher = more severe)."""
        levels = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return levels[self]

    def __ge__(self, other: "Severity") -> bool:
        return self.level >= other.level

    def __gt__(self, other: "Severity") -> bool:
        return self.level > other.level

    def __le__(self, other: "Severity") -> bool:
        return self.level <= other.level

    def __lt__(self, other: "Severity") -> bool:
        return self.level < other.level


# =============================================================================
# Pattern types - used by semantic check helpers to determine binding context
# =============================================================================


@dataclass
class Pattern:
    """Base class for match patterns."""

    pass


@dataclass
class FunPattern(Pattern):
    """Function pattern: matches functions with optional modifiers."""

    modifiers: List[str]  # e.g., ["public", "entry"]
    binding: Optional[ID]  # The function binding name (e.g., "f")

    def __str__(self):
        mods = " ".join(self.modifiers) + " " if self.modifiers else ""
        return f"{mods}fun {self.binding}"


@dataclass
class CapabilityPattern(Pattern):
    """Capability pattern: matches capability structs."""

    binding: Optional[ID]  # The capability binding name (e.g., "c")

    def __str__(self):
        return f"capability {self.binding}"


@dataclass
class EventPattern(Pattern):
    """Event pattern: matches event structs."""

    binding: Optional[ID]  # The event binding name (e.g., "e")

    def __str__(self):
        return f"event {self.binding}"


# =============================================================================
# Property types - used by semantic checks via hy_bridge
# =============================================================================


@dataclass
class PropName:
    """Named property for semantic checks."""

    name: ID
    arg: Optional[ID] = None

    # Structural properties available for Hy rules
    # These map to check functions in semantic/*_checks.py via hy_bridge
    STRUCTURAL_PROPERTIES = {
        # Access Control
        "public",
        "entry",
        "transfer",
        "checks_capability",
        "checks_sender",
        "is_init",
        # Taint Analysis
        "tainted_state_write",
        "tainted_state_read",
        "tainted_recipient",
        "tainted_amount",
        "tainted_capability_check",
        "tainted_callee",
        "tainted_emit",
        "sanitized",
        # CFG Patterns
        "missing_transfer",
        "double_init",
        # Other
        "exists",
        "typed",
        "returns_mutable_ref",
        "transfers_to_zero_address",
        "weak_randomness",
        "orphan_txcontext",
        "orphan_capability",
        "orphan_event",
        "duplicated_branch_condition",
        "duplicated_branch_body",
        "self_recursive",
        "sensitive_event_leak",
        "unused",
        "version_check_inconsistent",
    }

    def __str__(self):
        arg = f"({self.arg})" if self.arg else ""
        return f"{self.name}{arg}"


@dataclass
class Condition:
    """Condition for semantic checks: subject is [not] property."""

    subject: ID
    negation: bool
    property: PropName

    def __str__(self):
        neg = "not " if self.negation else ""
        return f"{self.subject} is {neg}{self.property}"


# =============================================================================
# Rule type - minimal shim for semantic check compatibility
# =============================================================================


@dataclass
class Rule:
    """
    Minimal Rule structure for semantic check compatibility.

    The semantic checks expect a Rule object to extract binding keys.
    This is used by MinimalRule in hy_bridge.py.
    """

    name: ID
    match_clause: "Match"
    where_clause: None = None
    severity: Severity = Severity.MEDIUM
    categories: List[str] = None  # type: ignore
    description: Optional[str] = None
    example_bad: Optional[str] = None
    example_fixed: Optional[str] = None

    def __post_init__(self):
        if self.categories is None:
            self.categories = []


@dataclass
class Match:
    """Match clause containing pattern and body."""

    pattern: Pattern
    body: List  # List of clauses (empty for Hy rules)
