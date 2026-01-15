"""
Access control property checks.

Contains checks for:
- checks_capability, checks_sender
- creates_privileged_cap, requires_parent_cap
- verifies_ownership, transfers_privileged_to_tainted
"""

from typing import List, TYPE_CHECKING

from core.facts import Fact, names_match
from rules.ir import Rule, Condition
from rules.ir import Binding
from core.utils import get_simple_name

from semantic.helpers import (
    get_function_binding_key,
    gather_facts_for_func,
    has_fact,
    apply_negation,
)

if TYPE_CHECKING:
    from semantic.checker import SemanticChecker


def check_checks_capability(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if function requires a capability parameter."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    all_facts = gather_facts_for_func(checker, facts, func_name)

    cap_binding_key = condition.property.arg
    cap_type = binding.get(cap_binding_key) if cap_binding_key else None

    if cap_type:
        # Check for specific capability
        simple_cap = get_simple_name(cap_type)
        found = has_fact(
            all_facts,
            "ChecksCapability",
            lambda f: f.args[1] == func_name and (f.args[0] == cap_type or get_simple_name(f.args[0]) == simple_cap),
        )
    else:
        # Check for ANY capability
        found = has_fact(all_facts, "ChecksCapability", lambda f: f.args[1] == func_name)

    return apply_negation(found, condition.negation)


def check_checks_sender(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if function calls tx_context::sender()."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    all_facts = gather_facts_for_func(checker, facts, func_name)
    found = has_fact(all_facts, "HasSenderEqualityCheck", lambda f: f.args[0] == func_name)
    return apply_negation(found, condition.negation)


def check_creates_privileged_cap(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if function creates a privileged capability."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    all_facts = gather_facts_for_func(checker, facts, func_name)

    # Get privileged capability types from all files
    privileged_caps = set()
    for file_ctx in checker.ctx.source_files.values():
        for f in file_ctx.facts:
            if f.name == "IsPrivileged":
                privileged_caps.add(f.args[0])

    # Check if function creates any privileged capability (STRICT FQN match)
    found = has_fact(
        all_facts,
        "CreatesCapability",
        lambda f: f.args[0] == func_name and f.args[1] in privileged_caps,
    )
    return apply_negation(found, condition.negation)


def check_requires_parent_cap(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if function requires a parent capability via CapabilityHierarchy."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    all_facts = gather_facts_for_func(checker, facts, func_name)

    # Get capabilities this function checks and caps it creates
    checked_caps = {f.args[0] for f in all_facts if f.name == "ChecksCapability" and f.args[1] == func_name}
    created_caps = {f.args[1] for f in all_facts if f.name == "CreatesCapability" and f.args[0] == func_name}

    # Check capability hierarchy from all files
    for file_ctx in checker.ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "CapabilityHierarchy":
                parent_cap, child_cap = fact.args[0], fact.args[1]
                for checked_cap in checked_caps:
                    for created in created_caps:
                        if names_match(checked_cap, parent_cap) and names_match(created, child_cap):
                            return apply_negation(True, condition.negation)

    return apply_negation(False, condition.negation)


def check_verifies_ownership(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if function verifies asset ownership."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    # Get transitive callees
    callees = []
    if checker.ctx.call_graph:
        callees = list(checker.ctx.call_graph.transitive_callees.get(func_name, set()))

    ownership_fields = {"owner", "authority", "admin", "creator"}

    for fn in [func_name] + callees:
        fn_facts = gather_facts_for_func(checker, facts, fn)

        # Check for ownership field access
        has_owner_field_access = has_fact(
            fn_facts,
            "FieldAccess",
            lambda f: f.args[0] == fn and any(field in f.args[2].lower() for field in ownership_fields),
        )

        if not has_owner_field_access:
            continue

        if fn == func_name:
            # Main function needs field access + sender check
            if has_fact(fn_facts, "HasSenderEqualityCheck", lambda f: f.args[0] == fn):
                return apply_negation(True, condition.negation)
        else:
            # Callees need field access + assertion
            if has_fact(fn_facts, "SanitizedByAssert", lambda f: f.args[0] == fn):
                return apply_negation(True, condition.negation)

    return apply_negation(False, condition.negation)


def check_transfers_privileged_to_tainted(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if function transfers privileged capability to tainted recipient."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    all_facts = gather_facts_for_func(checker, facts, func_name)

    # Check for tainted transfer recipient (TaintedAtSink with sink_type='transfer_recipient')
    if not has_fact(
        all_facts,
        "TaintedAtSink",
        lambda f: f.args[0] == func_name and len(f.args) > 3 and f.args[3] == "transfer_recipient",
    ):
        return apply_negation(False, condition.negation)

    # Get privileged types from all files
    privileged_types = set()
    for file_ctx in checker.ctx.source_files.values():
        for f in file_ctx.facts:
            if f.name == "IsPrivileged":
                privileged_types.add(f.args[0])

    # Check if function creates or transfers privileged type (STRICT FQN match)
    for fact in all_facts:
        if fact.name == "CreatesCapability" and fact.args[0] == func_name:
            if fact.args[1] in privileged_types:
                return apply_negation(True, condition.negation)
        elif fact.name == "TransfersUserAsset" and fact.args[0] == func_name:
            if fact.args[1] in privileged_types:
                return apply_negation(True, condition.negation)

    return apply_negation(False, condition.negation)


def check_single_step_ownership(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if function performs single-step ownership transfer."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return False

    all_facts = gather_facts_for_func(checker, facts, func_name)
    return has_fact(all_facts, "SingleStepOwnershipTransfer", lambda f: f.args[0] == func_name)
