"""
Interprocedural Taint Analysis - Function summaries and cross-function propagation.

This extends the basic intraprocedural taint analysis with:
1. Function summaries: "param N tainted → sink reached" or "param N tainted → return tainted"
2. Summary application at call sites
3. Fixed-point iteration across the whole module
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional

from core.utils import debug, error
from core.facts import Fact
from core.context import ProjectContext
from move.ir import Module, Function
from move.taint_facts import generate_taint_base_facts
from taint.analysis import propagate_taint, analyze_sink_reachability
from move.cst_to_ir import build_ir_from_source

# Sink types for parameterized facts
SINK_TYPES = {
    "transfer_recipient",
    "transfer_value",
    "state_write",
    "amount_extraction",
    "object_destroy",
    "loop_bound",
    "event_field",
    "generic",
}


@dataclass
class FunctionSummary:
    """Summary of taint behavior for a function."""

    func_name: str
    # param_idx -> set of sink types reached if that param is tainted
    # sink types: "transfer_recipient", "transfer_value", "state_write", "amount"
    param_to_sinks: Dict[int, Set[str]] = field(default_factory=dict)
    # param_idx -> set of sink types that are SANITIZED before being reached
    param_to_sanitized_sinks: Dict[int, Set[str]] = field(default_factory=dict)
    # Guards that protect ALL sinks in this function
    # guard types: "sender", "role:<RoleType>", "pause", "lock", "version"
    guards: Set[str] = field(default_factory=set)
    # param_idx -> set of param indices that become tainted via mutable reference
    # When param N is tainted and flows through *param_M = val, param M becomes tainted
    param_to_mutref_params: Dict[int, Set[int]] = field(default_factory=dict)


def compute_function_summary(func: Function, all_module_facts: List[Fact]) -> FunctionSummary:
    """
    Compute taint summary for a single function.

    This runs intraprocedural analysis and extracts what happens
    when each parameter is tainted.

    Args:
        all_module_facts: IPA-derived facts from previous iterations. These are merged
            with base facts to allow multi-level call chain propagation.
    """
    summary = FunctionSummary(func_name=func.name)

    # Get base facts for this function
    base_facts = generate_taint_base_facts(func)

    # Include IPA-derived facts for this function from previous iterations
    # This enables multi-level call chain propagation (A → B → C → sink)
    ipa_facts_for_func = [f for f in all_module_facts if f.args and f.args[0] == func.name]

    # Run intraprocedural propagation with IPA facts included
    taint_derived = propagate_taint(func.name, base_facts + ipa_facts_for_func)
    all_facts = base_facts + ipa_facts_for_func + taint_derived

    # Run sink analysis
    sink_facts = analyze_sink_reachability(func.name, all_facts)
    all_facts.extend(sink_facts)

    # Extract which params reach which sinks
    for fact in all_facts:
        if fact.args[0] != func.name:
            continue

        # Handle TaintedAtSink facts
        if fact.name == "TaintedAtSink":
            # TaintedAtSink(func_name, source, stmt_id, sink_type, cap)
            source_param = fact.args[1]
            sink_type = fact.args[3]
            param_idx = _get_param_index(func, source_param)
            if param_idx is not None:
                summary.param_to_sinks.setdefault(param_idx, set()).add(sink_type)

        # Handle SanitizedAtSink facts
        elif fact.name == "SanitizedAtSink":
            # SanitizedAtSink(func_name, source, stmt_id, sink_type, cap)
            source_param = fact.args[1]
            sink_type = fact.args[3]
            param_idx = _get_param_index(func, source_param)
            if param_idx is not None:
                summary.param_to_sanitized_sinks.setdefault(param_idx, set()).add(sink_type)

    # Track param-to-param tainting via mutable references
    # DerefAssigns(func, stmt_id, target_var, (source_vars)) means *target = source
    # If source is a param and target is a param, then tainting source taints target
    for fact in all_facts:
        if fact.name == "DerefAssigns" and fact.args[0] == func.name:
            target_var = fact.args[2]  # The param receiving taint via *target = ...
            source_vars = fact.args[3]  # The vars being assigned
            target_param_idx = _get_param_index(func, target_var)
            if target_param_idx is not None:
                for src_var in source_vars:
                    src_param_idx = _get_param_index(func, src_var)
                    if src_param_idx is not None:
                        # src_param taints target_param via mutable reference
                        summary.param_to_mutref_params.setdefault(src_param_idx, set()).add(target_param_idx)

    return summary


def _get_param_index(func: Function, param_name: str) -> Optional[int]:
    """Get parameter index by name, or None if not a parameter."""
    for p in func.params:
        if p.name == param_name:
            return p.idx
    return None


def run_interprocedural_analysis(module: Module) -> Tuple[List[Fact], Dict[str, FunctionSummary]]:
    """
    Run full interprocedural taint analysis on a module.

    Returns:
        - All derived facts (including interprocedural ones)
        - Function summaries for each function
    """
    all_facts: List[Fact] = []
    summaries: Dict[str, FunctionSummary] = {}

    # Phase 1: Compute initial summaries for all functions
    for func in module.functions:
        summary = compute_function_summary(func, [])
        summaries[func.name] = summary

    # Phase 2: Fixed-point iteration - apply summaries at call sites
    changed = True
    iteration = 0
    max_iterations = 10  # Prevent infinite loops

    while changed and iteration < max_iterations:
        changed = False
        iteration += 1

        for func in module.functions:
            new_facts = apply_summaries_to_caller(func, summaries, all_facts)
            if new_facts:
                all_facts.extend(new_facts)
                changed = True

                # Recompute summary for this function with new facts
                new_summary = compute_function_summary(func, all_facts)
                if new_summary.param_to_sinks != summaries[func.name].param_to_sinks:
                    summaries[func.name] = new_summary
                    changed = True

    # Phase 3: Generate final interprocedural facts
    for func in module.functions:
        interproc_facts = generate_interproc_facts(func, summaries, all_facts)
        all_facts.extend(interproc_facts)

    return all_facts, summaries


def apply_summaries_to_caller(
    caller: Function,
    summaries: Dict[str, FunctionSummary],
    existing_facts: List[Fact],
) -> List[Fact]:
    """
    Apply callee summaries to propagate taint through call sites in caller.
    """
    derived: List[Fact] = []

    # Get caller's base facts
    base_facts = generate_taint_base_facts(caller)
    taint_derived = propagate_taint(caller.name, base_facts + existing_facts)
    caller_facts = base_facts + taint_derived

    # Find what's tainted in caller
    tainted_vars = {f.args[1] for f in caller_facts if f.name == "Tainted" and f.args[0] == caller.name}
    taint_sources = {f.args[1]: f.args[2] for f in caller_facts if f.name == "TaintedBy" and f.args[0] == caller.name}

    # Look at each call in caller
    for fact in caller_facts:
        if fact.name != "CallArg":
            continue

        _, stmt_id, callee, arg_idx, arg_vars = fact.args

        # Check if callee has a summary
        if callee not in summaries:
            continue
        callee_summary = summaries[callee]

        # Check if any arg var is tainted
        for arg_var in arg_vars:
            if arg_var not in tainted_vars:
                continue

            source = taint_sources.get(arg_var, arg_var)

            # If this arg position reaches sinks in callee, propagate to caller
            if arg_idx in callee_summary.param_to_sinks:
                for sink_type in callee_summary.param_to_sinks[arg_idx]:
                    # Create interprocedural fact with parameterized fact
                    # TaintedAtSink(func_name, source, stmt_id, sink_type, cap)
                    new_fact = Fact("TaintedAtSink", (caller.name, source, f"{stmt_id}_via_{callee}", sink_type, ""))
                    if new_fact not in derived and new_fact not in existing_facts:
                        derived.append(new_fact)

            # Check if this tainted arg affects other params via mutable reference
            # If callee has: *param_M = param_N, and arg_N is tainted in caller,
            # then the variable passed as arg_M becomes tainted in caller
            if arg_idx in callee_summary.param_to_mutref_params:
                for target_param_idx in callee_summary.param_to_mutref_params[arg_idx]:
                    # Find what variable is passed at target_param_idx position
                    for other_fact in caller_facts:
                        if (
                            other_fact.name == "CallArg"
                            and other_fact.args[1] == stmt_id  # Same call site
                            and other_fact.args[2] == callee  # Same callee
                            and other_fact.args[3] == target_param_idx
                        ):  # Target param position
                            target_vars = other_fact.args[4]
                            for target_var in target_vars:
                                # Generate Tainted and TaintedBy facts for the target variable
                                tainted_fact = Fact("Tainted", (caller.name, target_var))
                                if tainted_fact not in derived and tainted_fact not in existing_facts:
                                    derived.append(tainted_fact)
                                tainted_by_fact = Fact("TaintedBy", (caller.name, target_var, source))
                                if tainted_by_fact not in derived and tainted_by_fact not in existing_facts:
                                    derived.append(tainted_by_fact)

    return derived


def generate_interproc_facts(
    func: Function,
    summaries: Dict[str, FunctionSummary],
    existing_facts: List[Fact],
) -> List[Fact]:
    """
    Generate final interprocedural facts for a function based on all summaries.
    """
    derived: List[Fact] = []

    # Run full analysis with all facts
    base_facts = generate_taint_base_facts(func)
    all_facts = base_facts + existing_facts
    taint_derived = propagate_taint(func.name, all_facts)
    all_facts.extend(taint_derived)
    sink_facts = analyze_sink_reachability(func.name, all_facts)

    # Add taint-derived facts (including WeakRandom, WeakRandomBy, Tainted, etc.)
    for fact in taint_derived:
        if fact not in existing_facts and fact not in derived:
            derived.append(fact)

    # Add sink facts that aren't already in existing
    for fact in sink_facts:
        if fact not in existing_facts and fact not in derived:
            derived.append(fact)

    return derived


def run_structural_taint_analysis(ctx: ProjectContext):
    """
    Run interprocedural taint analysis on all functions.
    """
    from move.taint_facts import generate_taint_base_facts, generate_unused_arg_facts

    debug("[run_structural_taint_analysis]")
    taint_fact_count = 0

    role_types: set[str] = set()
    for source_file in ctx.source_files.values():
        for fact in source_file.facts:
            if fact.name == "IsCapability":
                role_types.add(fact.args[0])

    file_modules = {}
    for file_path, file_ctx in ctx.source_files.items():
        try:
            if file_ctx.source_code is None:
                continue
            module = build_ir_from_source(file_ctx.source_code, file_ctx.root)
            if not module or not module.functions:
                continue

            file_modules[file_path] = module

            for func in module.functions:
                ctx.module_index[func.name] = func

            for func in module.functions:
                base_facts = generate_taint_base_facts(func)
                file_ctx.facts.extend(base_facts)

                # Add base_facts (including sink facts) to global index
                for fact in base_facts:
                    if len(fact.args) > 0:
                        fact_func_name = fact.args[0]
                        if fact_func_name in ctx.global_facts_index:
                            if file_path in ctx.global_facts_index[fact_func_name]:
                                ctx.global_facts_index[fact_func_name][file_path].append(fact)

                unused_arg_facts = generate_unused_arg_facts(func, role_types)
                file_ctx.facts.extend(unused_arg_facts)
                # Also add to global_facts_index for reporter lookup
                for fact in unused_arg_facts:
                    func_name = fact.args[0]
                    if func_name in ctx.global_facts_index:
                        if file_path in ctx.global_facts_index[func_name]:
                            ctx.global_facts_index[func_name][file_path].append(fact)

        except Exception as e:
            import traceback

            traceback.print_exc()
            error(f"Base taint fact generation failed for {file_path}: {e}")

    for file_path, module in file_modules.items():
        file_ctx = ctx.source_files[file_path]
        try:
            interproc_facts, summaries = run_interprocedural_analysis(module)

            # Save summaries for cross-module propagation in Pass 3
            ctx.function_summaries.update(summaries)

            if interproc_facts:
                file_ctx.facts.extend(interproc_facts)
                taint_fact_count += len(interproc_facts)

                for fact in interproc_facts:
                    if len(fact.args) > 0:
                        func_name = fact.args[0]
                        if func_name in ctx.global_facts_index:
                            if file_path in ctx.global_facts_index[func_name]:
                                ctx.global_facts_index[func_name][file_path].append(fact)

        except Exception as e:
            import traceback

            traceback.print_exc()
            error(f"Interprocedural taint analysis failed for {file_path}: {e}")

    if taint_fact_count > 0:
        debug(f"Generated {taint_fact_count} taint-related facts (interprocedural).")
