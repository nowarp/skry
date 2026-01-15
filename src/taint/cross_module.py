"""
Cross-module taint propagation.

Uses function summaries from Pass 1 to detect tainted data flowing
to sinks in other modules.
"""

from typing import Dict, List, Set

from core.context import ProjectContext
from core.facts import Fact
from core.utils import debug
from analysis.call_graph import build_global_call_graph
from taint.guards import make_guarded_sink_facts


def _make_taint_fact(func_name: str, source_param: str, stmt_id: str, sink_type: str) -> Fact:
    """Create TaintedAtSink fact."""
    # TaintedAtSink(func_name, source, stmt_id, sink_type, cap)
    return Fact("TaintedAtSink", (func_name, source_param, stmt_id, sink_type, ""))


def _make_sanitized_fact(func_name: str, source_param: str, stmt_id: str, sink_type: str) -> Fact:
    """Create SanitizedAtSink fact."""
    # SanitizedAtSink(func_name, source, stmt_id, sink_type, cap)
    return Fact("SanitizedAtSink", (func_name, source_param, stmt_id, sink_type, ""))


def _compose_summaries_transitively(ctx: ProjectContext) -> None:
    """
    Compose function summaries transitively.

    If A calls B at param position i->j, and B.param_to_sinks[j] has sinks,
    then A.param_to_sinks[i] should also have those sinks.
    Also propagates guards: if B has guards, those apply to A's via-sinks.

    Uses CallArg facts to track param flow: A's local var flows to B's param j.
    If that local var came from A's param i, we propagate B's sinks to A's param i.
    """
    # Build func -> CallArg facts mapping
    func_call_args: Dict[str, List[Fact]] = {}
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "CallArg":
                caller = fact.args[0]
                if caller not in func_call_args:
                    func_call_args[caller] = []
                func_call_args[caller].append(fact)

    # Build func -> TaintSource (param_name -> param_idx) mapping
    func_param_idx: Dict[str, Dict[str, int]] = {}
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "TaintSource":
                func_name, param_name, param_idx = fact.args
                if func_name not in func_param_idx:
                    func_param_idx[func_name] = {}
                func_param_idx[func_name][param_name] = param_idx

    # Build func -> Tainted var set (from intraprocedural)
    func_tainted: Dict[str, Set[str]] = {}
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "Tainted":
                func_name, var_name = fact.args
                if func_name not in func_tainted:
                    func_tainted[func_name] = set()
                func_tainted[func_name].add(var_name)

    # Fixed-point iteration
    changed = True
    iterations = 0
    while changed and iterations < 10:
        changed = False
        iterations += 1

        for func_name, summary in ctx.function_summaries.items():
            call_args = func_call_args.get(func_name, [])
            tainted_vars = func_tainted.get(func_name, set())
            param_map = func_param_idx.get(func_name, {})

            for call_arg in call_args:
                # CallArg(caller, stmt_id, callee, arg_idx, arg_vars)
                _, _, callee, callee_arg_idx, arg_vars = call_arg.args

                callee_summary = ctx.function_summaries.get(callee)
                if not callee_summary or not callee_summary.param_to_sinks:
                    continue

                # If callee's arg position reaches sinks...
                if callee_arg_idx not in callee_summary.param_to_sinks:
                    continue

                callee_sinks = callee_summary.param_to_sinks[callee_arg_idx]

                # ...and we pass a tainted var that comes from our param...
                for arg_var in arg_vars:
                    if arg_var not in tainted_vars:
                        continue

                    # Check if arg_var is one of our params
                    if arg_var in param_map:
                        our_param_idx = param_map[arg_var]

                        # Propagate callee's sinks to our param
                        if our_param_idx not in summary.param_to_sinks:
                            summary.param_to_sinks[our_param_idx] = set()

                        for sink_type in callee_sinks:
                            if sink_type not in summary.param_to_sinks[our_param_idx]:
                                summary.param_to_sinks[our_param_idx].add(sink_type)
                                changed = True

                        # Propagate callee's guards to caller
                        # If callee has guards, caller's via-sinks are protected
                        if callee_summary.guards:
                            for guard in callee_summary.guards:
                                if guard not in summary.guards:
                                    summary.guards.add(guard)
                                    changed = True

    if iterations > 1:
        debug(f"Composed summaries transitively in {iterations} iterations")


def propagate_taint_across_modules(ctx: ProjectContext) -> None:
    """
    Cross-module taint propagation using stored function summaries.

    For each entry point:
      1. Compose summaries transitively (propagate callee sinks to callers)
      2. Get transitive callees via global call graph
      3. For each callee with a summary, check if:
         - Entry passes tainted param to callee
         - Callee's summary says that param reaches a sink
      4. Emit proper taint fact for entry (e.g., TaintedTransferRecipient)
    """
    if not ctx.function_summaries:
        debug("No function summaries available for cross-module taint")
        return

    call_graph = build_global_call_graph(ctx)
    if not call_graph:
        debug("Empty call graph, skipping cross-module taint")
        return

    # Compose summaries transitively before checking entry points
    _compose_summaries_transitively(ctx)

    # Collect entry functions and their taint sources
    entry_funcs: Dict[str, Set[str]] = {}  # entry_name -> set of tainted param names
    entry_to_file: Dict[str, str] = {}  # entry_name -> file_path

    for file_path, file_ctx in ctx.source_files.items():
        for fact in file_ctx.facts:
            if fact.name == "IsEntry":
                entry_name = fact.args[0]
                entry_funcs[entry_name] = set()
                entry_to_file[entry_name] = file_path
            elif fact.name == "TaintSource":
                func_name = fact.args[0]
                param_name = fact.args[1]
                if func_name in entry_funcs:
                    entry_funcs[func_name].add(param_name)

    if not entry_funcs:
        return

    debug(f"Checking {len(entry_funcs)} entry functions for cross-module taint")

    # Build mapping: func_name -> list of CallArg facts
    func_call_args: Dict[str, List[Fact]] = {}
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "CallArg":
                caller = fact.args[0]
                if caller not in func_call_args:
                    func_call_args[caller] = []
                func_call_args[caller].append(fact)

    # Build mapping: func_name -> set of tainted vars (from intraprocedural)
    func_tainted_vars: Dict[str, Set[str]] = {}
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "Tainted":
                func_name = fact.args[0]
                var_name = fact.args[1]
                if func_name not in func_tainted_vars:
                    func_tainted_vars[func_name] = set()
                func_tainted_vars[func_name].add(var_name)

    # Build mapping: func_name -> set of sanitized vars (from intraprocedural)
    func_sanitized_vars: Dict[str, Set[str]] = {}
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "Sanitized":
                func_name = fact.args[0]
                var_name = fact.args[1]
                if func_name not in func_sanitized_vars:
                    func_sanitized_vars[func_name] = set()
                func_sanitized_vars[func_name].add(var_name)

    new_facts_count = 0

    for entry_name, tainted_params in entry_funcs.items():
        if not tainted_params:
            continue

        # Get all tainted vars in entry (includes propagated taint)
        entry_tainted = func_tainted_vars.get(entry_name, tainted_params)

        # Build multihop taint propagation: track (func, tainted_vars) pairs
        # Start with entry function
        worklist = [(entry_name, entry_tainted)]
        visited_funcs = {entry_name}

        # Track taint reaching each function in the call chain
        func_taint_map: Dict[str, Set[str]] = {entry_name: entry_tainted}

        while worklist:
            current_func, current_tainted = worklist.pop(0)

            # Get all calls from current function
            call_args = func_call_args.get(current_func, [])

            for call_arg_fact in call_args:
                # CallArg(func, stmt_id, callee, arg_idx, (arg_vars))
                _, stmt_id, callee, arg_idx, arg_vars = call_arg_fact.args

                # Check if we pass tainted data to callee
                tainted_passed = False
                for arg_var in arg_vars:
                    if arg_var in current_tainted:
                        tainted_passed = True
                        break

                if not tainted_passed:
                    continue

                # Get callee's summary
                callee_summary = ctx.function_summaries.get(callee)

                # If callee has sinks, emit taint facts for entry point
                if callee_summary and callee_summary.param_to_sinks:
                    if arg_idx in callee_summary.param_to_sinks:
                        for sink_type in callee_summary.param_to_sinks[arg_idx]:
                            # Check if sanitized in caller OR in callee
                            is_sanitized = False

                            # Check if the passed argument is sanitized in current_func (caller)
                            for arg_var in arg_vars:
                                if arg_var in current_tainted:
                                    current_sanitized = func_sanitized_vars.get(current_func, set())
                                    if arg_var in current_sanitized:
                                        is_sanitized = True
                                        break

                            # Check if callee sanitizes this parameter before the sink
                            if not is_sanitized and arg_idx in callee_summary.param_to_sanitized_sinks:
                                if sink_type in callee_summary.param_to_sanitized_sinks[arg_idx]:
                                    is_sanitized = True

                            # Emit taint fact attributed to entry point
                            via_id = f"{stmt_id}_via_{callee}"
                            new_fact = _make_taint_fact(entry_name, list(current_tainted)[0], via_id, sink_type)

                            file_path = entry_to_file[entry_name]
                            file_ctx = ctx.source_files[file_path]
                            if new_fact not in file_ctx.facts:
                                file_ctx.facts.append(new_fact)
                                new_facts_count += 1

                                # Also update global index
                                if entry_name in ctx.global_facts_index:
                                    if file_path in ctx.global_facts_index[entry_name]:
                                        ctx.global_facts_index[entry_name][file_path].append(new_fact)

                            # If sanitized, also emit sanitized fact (outside the taint fact check)
                            if is_sanitized:
                                sanitized_fact = _make_sanitized_fact(
                                    entry_name, list(current_tainted)[0], via_id, sink_type
                                )
                                if sanitized_fact not in file_ctx.facts:
                                    file_ctx.facts.append(sanitized_fact)
                                    if entry_name in ctx.global_facts_index:
                                        if file_path in ctx.global_facts_index[entry_name]:
                                            ctx.global_facts_index[entry_name][file_path].append(sanitized_fact)

                            # Emit GuardedSink facts if callee has guards (also outside)
                            if callee_summary.guards:
                                for guarded_fact in make_guarded_sink_facts(entry_name, via_id, callee_summary.guards):
                                    if guarded_fact not in file_ctx.facts:
                                        file_ctx.facts.append(guarded_fact)

                # Propagate taint to callee for further exploration
                # If we haven't visited this callee yet, add to worklist
                if callee not in visited_funcs:
                    visited_funcs.add(callee)

                    # Get callee's tainted vars (from intraprocedural analysis)
                    callee_tainted = func_tainted_vars.get(callee, set()).copy()

                    # Build param name from TaintSource facts for the callee
                    # We need to know which params exist in the callee
                    callee_params = set()
                    for file_ctx in ctx.source_files.values():
                        for fact in file_ctx.facts:
                            if fact.name == "TaintSource" and fact.args[0] == callee:
                                callee_params.add(fact.args[1])  # param_name

                    # If we pass tainted data to arg_idx, that param becomes tainted
                    # This is a simplified model - we assume all params are potentially tainted
                    # A better approach would track param flow precisely
                    if callee_params:
                        callee_tainted.update(callee_params)

                    # Only add to worklist if there's taint to propagate
                    if callee_tainted:
                        if callee not in func_taint_map:
                            func_taint_map[callee] = set()
                        func_taint_map[callee].update(callee_tainted)

                        worklist.append((callee, callee_tainted))

    if new_facts_count > 0:
        debug(f"Cross-module taint: generated {new_facts_count} taint facts")
