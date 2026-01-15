"""
Structural property checks.

Contains checks for:
- is_init, public, entry
- orphan_txcontext, orphan_capability, orphan_event
- missing_transfer, double_init, self_recursive
"""

from typing import List

from core.facts import Fact, names_match
from rules.ir import Rule, Condition
from rules.ir import Binding
from core.utils import debug, get_simple_name

from semantic.helpers import (
    get_function_binding_key,
    get_capability_binding_key,
    get_event_binding_key,
    gather_facts_for_func,
    has_fact,
    apply_negation,
)
from semantic.checker import SemanticChecker


def check_is_init(
    checker: SemanticChecker,
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if function is the Sui module init function."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    all_facts = gather_facts_for_func(checker, facts, func_name)
    found = has_fact(all_facts, "IsInit", lambda f: f.args[0] == func_name)
    return apply_negation(found, condition.negation)


def check_public(
    checker: SemanticChecker,
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if function has public modifier."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    all_facts = gather_facts_for_func(checker, facts, func_name)
    found = has_fact(all_facts, "IsPublic", lambda f: names_match(f.args[0], func_name))
    return apply_negation(found, condition.negation)


def check_entry(
    checker: SemanticChecker,
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if function has entry modifier."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    all_facts = gather_facts_for_func(checker, facts, func_name)
    found = has_fact(all_facts, "IsEntry", lambda f: names_match(f.args[0], func_name))
    return apply_negation(found, condition.negation)


def check_orphan_txcontext(
    checker: SemanticChecker,
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if function is an orphan TxContext function."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    all_facts = gather_facts_for_func(checker, facts, func_name)
    found = has_fact(all_facts, "OrphanTxContextFunction", lambda f: f.args[0] == func_name)
    return apply_negation(found, condition.negation)


def check_orphan_capability(
    checker: SemanticChecker,
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if capability is orphan (defined but never used as parameter)."""
    cap_type = binding.get(get_capability_binding_key(rule))
    if not cap_type:
        return condition.negation

    simple_cap = get_simple_name(cap_type)
    found = has_fact(
        facts,
        "OrphanCapability",
        lambda f: f.args[0] == cap_type or get_simple_name(f.args[0]) == simple_cap,
    )
    return apply_negation(found, condition.negation)


def check_orphan_event(
    checker: SemanticChecker,
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if event is an orphan event (defined but never emitted)."""
    event_type = binding.get(get_event_binding_key(rule))
    if not event_type:
        return condition.negation

    simple_event = get_simple_name(event_type)
    found = has_fact(
        facts,
        "OrphanEvent",
        lambda f: f.args[0] == event_type or get_simple_name(f.args[0]) == simple_event,
    )
    return apply_negation(found, condition.negation)


def check_double_init(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if a non-init function calls init or init helper functions.

    INIT-1: Detects when a public/entry function can trigger module initialization.
    """
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    # Collect init functions AND init impl helpers
    init_and_helpers: set[str] = set()
    for source_file in checker.ctx.source_files.values():
        for fact in source_file.facts:
            if fact.name in ("IsInit", "InitImpl"):
                init_and_helpers.add(fact.args[0])

    if not init_and_helpers:
        return condition.negation

    # Skip if current function IS init or init helper
    if func_name in init_and_helpers:
        return condition.negation

    # Only flag public/entry functions
    is_public_or_entry = False
    for source_file in checker.ctx.source_files.values():
        for fact in source_file.facts:
            if fact.name in ("IsPublic", "IsEntry") and fact.args[0] == func_name:
                is_public_or_entry = True
                break
        if is_public_or_entry:
            break

    if not is_public_or_entry:
        return condition.negation

    # Get transitive callees
    transitive_callees: set[str] = set()
    if checker.ctx.call_graph:
        transitive_callees = checker.ctx.call_graph.transitive_callees.get(func_name, set())

    # Check if ANY transitive callee is an init/helper
    result = False
    for callee in transitive_callees:
        callee_simple = get_simple_name(callee)
        for init_helper in init_and_helpers:
            if callee == init_helper or callee_simple == get_simple_name(init_helper):
                debug(f"[double_init] {func_name} transitively calls {init_helper}")
                result = True
                break
        if result:
            break

    return apply_negation(result, condition.negation)


def check_self_recursive(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if function is self-recursive (calls itself)."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    all_facts = gather_facts_for_func(checker, facts, func_name)
    found = has_fact(all_facts, "SelfRecursive", lambda f: f.args[0] == func_name)
    return apply_negation(found, condition.negation)
