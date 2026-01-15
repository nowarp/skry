"""
Sanitization-related property checks.

Contains checks for:
- sanitized_recipient, sanitized_state_write, sanitized_amount
- sanitized_transfer_value, sanitized_object_destroy
"""

from typing import List, TYPE_CHECKING

from core.facts import Fact
from rules.ir import Rule, Condition
from rules.ir import Binding

from semantic.helpers import (
    get_function_binding_key,
    gather_facts_for_func,
    has_fact,
    apply_negation,
)

if TYPE_CHECKING:
    from semantic.checker import SemanticChecker


def _check_sanitized_generic(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    sink_type: str,
) -> bool:
    """Generic sanitization checker - looks for SanitizedAtSink facts with specific sink_type."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    all_facts = gather_facts_for_func(checker, facts, func_name)
    # SanitizedAtSink(func_name, source, stmt_id, sink_type, cap)
    found = has_fact(all_facts, "SanitizedAtSink", lambda f: f.args[0] == func_name and f.args[3] == sink_type)
    return apply_negation(found, condition.negation)


def check_sanitized_recipient(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if recipient was sanitized/validated."""
    return _check_sanitized_generic(checker, rule, binding, condition, facts, "transfer_recipient")


def check_sanitized_state_write(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if state write value was sanitized/validated."""
    return _check_sanitized_generic(checker, rule, binding, condition, facts, "state_write")


def check_sanitized_amount(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if amount was sanitized/validated (bounds checked)."""
    return _check_sanitized_generic(checker, rule, binding, condition, facts, "amount_extraction")


def check_sanitized_transfer_value(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if transfer value was sanitized/validated."""
    return _check_sanitized_generic(checker, rule, binding, condition, facts, "transfer_value")


def check_sanitized_object_destroy(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if destroyed object was sanitized/validated."""
    return _check_sanitized_generic(checker, rule, binding, condition, facts, "object_destroy")
