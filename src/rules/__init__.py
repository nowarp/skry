"""
Rule engine: IR types, Hy loader, and semantic checks.

Rules are written in Hy (Lisp dialect) - see rules/ directory.
"""

from rules.ir import (
    Rule,
    Binding,
    FunPattern,
    CapabilityPattern,
    EventPattern,
    PropName,
    Condition,
    Severity,
)
from rules.hy_loader import HyRule, load_hy_rules

__all__ = [
    # IR types
    "Rule",
    "Binding",
    "FunPattern",
    "CapabilityPattern",
    "EventPattern",
    "PropName",
    "Condition",
    "Severity",
    # Hy rules
    "HyRule",
    "load_hy_rules",
]
