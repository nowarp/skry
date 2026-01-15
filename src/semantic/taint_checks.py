"""
Taint-related property checks.

Contains checks for:
- tainted_param, tainted_recipient, tainted_state_write
- tainted_amount, tainted_transfer_value, tainted_object_destroy
- tainted_loop_bound
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


def check_tainted_param(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if function has tainted params reaching sinks."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    all_facts = gather_facts_for_func(checker, facts, func_name)
    # TaintedAtSink(func_name, source, stmt_id, sink_type, cap) where sink_type != ""
    found = has_fact(all_facts, "TaintedAtSink", lambda f: f.args[0] == func_name)
    return apply_negation(found, condition.negation)


def _is_value_type_param(func_name: str, param_name: str, facts: List[Fact]) -> bool:
    """Check if a parameter is a value type (Coin, Balance) that the user provides."""
    VALUE_TYPE_PATTERNS = {"Coin", "Balance"}
    for fact in facts:
        if fact.name == "FormalArg" and fact.args[0] == func_name:
            _, _, name, param_type = fact.args
            if name == param_name:
                return any(pattern in param_type for pattern in VALUE_TYPE_PATTERNS)
    return False


def _has_owned_object_guard(func_name: str, facts: List[Fact]) -> bool:
    """Check if a function operates only on owned objects."""
    return has_fact(facts, "OperatesOnOwnedOnly", lambda f: f.args[0] == func_name)


def check_tainted_recipient(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if transfer recipient is tainted (user-controlled)."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    all_facts = gather_facts_for_func(checker, facts, func_name)

    if _has_owned_object_guard(func_name, all_facts):
        return apply_negation(False, condition.negation)

    result = False
    for fact in all_facts:
        # TaintedAtSink(func_name, source, stmt_id, sink_type, cap)
        if fact.name == "TaintedAtSink" and fact.args[0] == func_name and fact.args[3] == "transfer_recipient":
            stmt_id = fact.args[2]
            # Check if value comes from user's own asset
            value_from_user_asset = False
            for vf in all_facts:
                # Check for tainted transfer value at same stmt_id
                if (
                    vf.name == "TaintedAtSink"
                    and vf.args[0] == func_name
                    and vf.args[2] == stmt_id
                    and vf.args[3] == "transfer_value"
                ):
                    value_source = vf.args[1]
                    if _is_value_type_param(func_name, value_source, all_facts):
                        value_from_user_asset = True
                        break
            if not value_from_user_asset:
                result = True
                break

    return apply_negation(result, condition.negation)


def check_tainted_state_write(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if state write is tainted (user-controlled)."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    all_facts = gather_facts_for_func(checker, facts, func_name)
    # TaintedAtSink with sink_type="state_write"
    found = has_fact(all_facts, "TaintedAtSink", lambda f: f.args[0] == func_name and f.args[3] == "state_write")
    return apply_negation(found, condition.negation)


def check_tainted_amount(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if extraction amount is tainted (user-controlled)."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    all_facts = gather_facts_for_func(checker, facts, func_name)
    # TaintedAtSink with sink_type="amount_extraction"
    found = has_fact(all_facts, "TaintedAtSink", lambda f: f.args[0] == func_name and f.args[3] == "amount_extraction")
    return apply_negation(found, condition.negation)


def check_tainted_transfer_value(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if transfer value (coin/object) is tainted."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    all_facts = gather_facts_for_func(checker, facts, func_name)
    # TaintedAtSink with sink_type="transfer_value"
    found = has_fact(all_facts, "TaintedAtSink", lambda f: f.args[0] == func_name and f.args[3] == "transfer_value")
    return apply_negation(found, condition.negation)


def check_tainted_object_destroy(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if destroyed object is tainted (user-controlled)."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    all_facts = gather_facts_for_func(checker, facts, func_name)
    # TaintedAtSink with sink_type="object_destroy"
    found = has_fact(all_facts, "TaintedAtSink", lambda f: f.args[0] == func_name and f.args[3] == "object_destroy")
    return apply_negation(found, condition.negation)


def check_tainted_loop_bound(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if loop bound is tainted (user-controlled) - DoS vulnerability."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    all_facts = gather_facts_for_func(checker, facts, func_name)

    result = False
    for fact in all_facts:
        # TaintedAtSink with sink_type="loop_bound"
        if fact.name == "TaintedAtSink" and fact.args[0] == func_name and fact.args[3] == "loop_bound":
            stmt_id = fact.args[2]
            # Check if this specific loop bound is sanitized
            is_sanitized = has_fact(
                all_facts,
                "SanitizedAtSink",
                lambda f: f.args[0] == func_name and f.args[2] == stmt_id and f.args[3] == "loop_bound",
            )
            if not is_sanitized:
                result = True
                break

    return apply_negation(result, condition.negation)
