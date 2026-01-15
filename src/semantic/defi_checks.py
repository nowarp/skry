"""
DeFi-specific property checks.

Contains checks for:
- transfer, transfers_to_zero_address, returns_mutable_ref
- weak_randomness
- sensitive_event_leak
"""

from typing import List, Optional, TYPE_CHECKING

from core.facts import Fact, get_fact_boolean
from rules.ir import Rule, Condition
from rules.ir import Binding
from llm.sensitivity import analyze_sensitivity
from move.types import extract_base_type, get_module_path

from semantic.helpers import (
    get_function_binding_key,
    gather_facts_for_func,
    has_fact,
    apply_negation,
)

if TYPE_CHECKING:
    from semantic.checker import SemanticChecker


def check_transfer(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if function performs a transfer operation."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    all_facts = gather_facts_for_func(checker, facts, func_name)
    cached_result = get_fact_boolean(all_facts, "Transfers", (func_name,))

    result = cached_result if cached_result is not None else False
    return apply_negation(result, condition.negation)


def check_transfers_to_zero_address(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if function transfers value to a zero address constant."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    all_facts = gather_facts_for_func(checker, facts, func_name)
    found = has_fact(all_facts, "TransfersToZeroAddress", lambda f: f.args[0] == func_name)
    return apply_negation(found, condition.negation)


def check_returns_mutable_ref(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if a public function returns a mutable reference (&mut)."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    all_facts = gather_facts_for_func(checker, facts, func_name)
    found = has_fact(all_facts, "ReturnsMutableRef", lambda f: f.args[0] == func_name)
    return apply_negation(found, condition.negation)


def check_weak_randomness(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if function uses weak/predictable randomness sources."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    all_facts = gather_facts_for_func(checker, facts, func_name)

    found = has_fact(
        all_facts,
        "TrackedDerived",
        lambda f: f.args[0] == func_name and f.args[2] == "weak_random",
    ) or has_fact(
        all_facts,
        "TrackedSource",
        lambda f: f.args[0] == func_name and f.args[3] == "weak_random",
    )
    return apply_negation(found, condition.negation)


def _resolve_var_type(func_name: str, var_name: str, facts: List[Fact]) -> Optional[str]:
    """Resolve variable to struct type via FormalArg facts."""
    module_path = get_module_path(func_name)

    for fact in facts:
        if fact.name == "FormalArg" and fact.args[0] == func_name:
            param_name = fact.args[2]
            param_type = fact.args[3]
            if param_name == var_name:
                base_type = extract_base_type(param_type, keep_fqn=True)
                if base_type and "::" not in base_type and module_path:
                    return f"{module_path}::{base_type}"
                return base_type
    return None


def _var_flows_from(source: str, target: str, func_name: str, facts: List[Fact]) -> bool:
    """Check if target variable's value originated from source variable."""
    if source == target:
        return True

    visited = set()
    worklist = [target]

    while worklist:
        var = worklist.pop()
        if var in visited:
            continue
        visited.add(var)

        for f in facts:
            if f.name == "Assigns" and f.args[0] == func_name and f.args[2] == var:
                rhs_vars = f.args[3]
                for rhs in rhs_vars:
                    if rhs == source:
                        return True
                    worklist.append(rhs)

    return False


def _resolve_field_chain_type(base_type: str, field_path: List[str], struct_facts: List[Fact]) -> Optional[str]:
    """Resolve the type that owns the final field in a nested path."""
    current_type = base_type
    module_path = get_module_path(base_type)

    for field in field_path[:-1]:
        found = False
        for sf in struct_facts:
            if sf.name == "StructField" and sf.args[0] == current_type and sf.args[2] == field:
                field_type = extract_base_type(sf.args[3], keep_fqn=True)
                if field_type and "::" not in field_type and module_path:
                    field_type = f"{module_path}::{field_type}"
                current_type = field_type
                found = True
                break
        if not found:
            return None
    return current_type


def check_sensitive_event_leak(
    checker: "SemanticChecker",
    rule: Rule,
    binding: Binding,
    condition: Condition,
    facts: List[Fact],
    source_code: str,
    root,
) -> bool:
    """Check if function emits sensitive data in events."""
    func_name = binding.get(get_function_binding_key(rule))
    if not func_name:
        return condition.negation

    all_facts = gather_facts_for_func(checker, facts, func_name)

    # Lazily run LLM sensitivity analysis on first call
    if not checker.ctx.sensitivity_facts:
        all_project_facts = []
        for file_ctx in checker.ctx.source_files.values():
            all_project_facts.extend(file_ctx.facts)
        checker.ctx.sensitivity_facts = analyze_sensitivity(all_project_facts, ctx=checker.ctx)

    sensitive_fields = set()
    for fact in all_facts:
        if fact.name == "FieldClassification" and len(fact.args) == 6:
            # FieldClassification(struct_type, field_path, category, negative, confidence, reason)
            struct_type, field_path, category, negative = fact.args[0], fact.args[1], fact.args[2], fact.args[3]
            # Only include positive sensitive classifications
            if category == "sensitive" and not negative:
                sensitive_fields.add((struct_type, field_path))
    for fact in checker.ctx.sensitivity_facts:
        if fact.name == "FieldClassification" and len(fact.args) == 6:
            struct_type, field_path, category, negative = fact.args[0], fact.args[1], fact.args[2], fact.args[3]
            if category == "sensitive" and not negative:
                sensitive_fields.add((struct_type, field_path))

    if not sensitive_fields:
        return condition.negation

    result = False
    for fact in all_facts:
        if fact.name == "EventFieldValue" and fact.args[0] == func_name:
            struct_name = fact.args[2]
            field_name = fact.args[3]
            field_vars = fact.args[4]

            if (struct_name, field_name) in sensitive_fields:
                result = True
                break

            # Check aliasing
            for fv in field_vars:
                for ff in all_facts:
                    if ff.name == "FieldAssign" and ff.args[0] == func_name:
                        target_var = ff.args[2]
                        base_var = ff.args[3]
                        src_field = ff.args[4]
                        if _var_flows_from(target_var, fv, func_name, all_facts):
                            struct_type = _resolve_var_type(func_name, base_var, all_facts)
                            if struct_type and (struct_type, src_field) in sensitive_fields:
                                result = True
                                break
                if result:
                    break
            if result:
                break

        elif fact.name == "EventFieldFromField" and fact.args[0] == func_name:
            source_field = fact.args[4]
            base_vars = fact.args[5]
            if base_vars:
                source_struct = _resolve_var_type(func_name, base_vars[0], all_facts)
                if source_struct and (source_struct, source_field) in sensitive_fields:
                    result = True
                    break

        elif fact.name == "FieldAccessChain" and fact.args[0] == func_name:
            base_var = fact.args[2]
            field_path = list(fact.args[3])

            if len(field_path) < 2:
                continue

            base_type = _resolve_var_type(func_name, base_var, all_facts)
            if not base_type:
                continue

            struct_facts = [f for f in all_facts if f.name == "StructField"]
            owner_type = _resolve_field_chain_type(base_type, field_path, struct_facts)
            if not owner_type:
                continue

            final_field = field_path[-1]
            if (owner_type, final_field) in sensitive_fields:
                result = True
                break

        elif fact.name == "TaintedAtSink" and fact.args[0] == func_name and fact.args[3] == "event_field":
            source_var = fact.args[1]
            for ff in all_facts:
                if ff.name == "FieldAssign" and ff.args[0] == func_name:
                    target_var = ff.args[2]
                    base_var = ff.args[3]
                    field_name = ff.args[4]

                    if _var_flows_from(target_var, source_var, func_name, all_facts):
                        struct_type = _resolve_var_type(func_name, base_var, all_facts)
                        if struct_type and (struct_type, field_name) in sensitive_fields:
                            result = True
                            break
            if result:
                break

    # Check IPA-derived event field taints
    if not result and checker.ctx.function_summaries:
        for fact in all_facts:
            if fact.name == "CallArgFieldAccess" and fact.args[0] == func_name:
                callee = fact.args[2]
                arg_idx = fact.args[3]
                base_var = fact.args[4]
                field_name = fact.args[5]

                callee_summary = checker.ctx.function_summaries.get(callee)
                if callee_summary and "event_field" in callee_summary.param_to_sinks.get(arg_idx, set()):
                    struct_type = _resolve_var_type(func_name, base_var, all_facts)
                    if struct_type and (struct_type, field_name) in sensitive_fields:
                        result = True
                        break

            elif fact.name == "CallArg" and fact.args[0] == func_name:
                callee = fact.args[2]
                arg_idx = fact.args[3]
                arg_vars = fact.args[4]

                callee_summary = checker.ctx.function_summaries.get(callee)
                if callee_summary and "event_field" in callee_summary.param_to_sinks.get(arg_idx, set()):
                    for av in arg_vars:
                        for ff in all_facts:
                            if ff.name == "FieldAssign" and ff.args[0] == func_name:
                                target_var = ff.args[2]
                                base_var = ff.args[3]
                                field_name = ff.args[4]
                                if _var_flows_from(target_var, av, func_name, all_facts):
                                    struct_type = _resolve_var_type(func_name, base_var, all_facts)
                                    if struct_type and (struct_type, field_name) in sensitive_fields:
                                        result = True
                                        break
                        if result:
                            break
                if result:
                    break

    return apply_negation(result, condition.negation)
