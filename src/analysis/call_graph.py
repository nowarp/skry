"""
Call graph analysis.

Extracts structural call graph facts from InFun facts:
- Calls(caller, callee) - direct call edges

CallGraph IR:
- Pre-computed transitive callees for efficient queries
- Used by has_fact_transitive() for query-time transitive checks
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, TYPE_CHECKING

from core.facts import Fact
from core.utils import debug, get_simple_name

if TYPE_CHECKING:
    from core.context import ProjectContext


# =============================================================================
# CallGraph IR
# =============================================================================


@dataclass
class CallGraph:
    """
    Pre-computed call graph with transitive relationships.

    Built once after Calls facts are generated, stored in ctx.call_graph.
    Used for query-time transitive checks without materializing transitive facts.
    """

    # Direct edges: caller -> {callees}
    callees: Dict[str, Set[str]] = field(default_factory=dict)
    # Reverse edges: callee -> {callers}
    callers: Dict[str, Set[str]] = field(default_factory=dict)
    # Pre-computed transitive callees: func -> {all reachable callees}
    transitive_callees: Dict[str, Set[str]] = field(default_factory=dict)


def build_call_graph_ir(ctx: "ProjectContext") -> CallGraph:
    """
    Build CallGraph IR from Calls facts.

    Should be called after build_call_facts() has run.
    Stores result in ctx.call_graph.
    """
    cg = CallGraph()

    # Collect direct edges from all files
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "Calls":
                caller, callee = fact.args
                if caller not in cg.callees:
                    cg.callees[caller] = set()
                cg.callees[caller].add(callee)
                if callee not in cg.callers:
                    cg.callers[callee] = set()
                cg.callers[callee].add(caller)

    # Pre-compute transitive callees for each function
    def compute_transitive(func: str, visited: Set[str]) -> Set[str]:
        if func in visited:
            return set()
        visited.add(func)

        result = set()
        for callee in cg.callees.get(func, set()):
            result.add(callee)
            result.update(compute_transitive(callee, visited))
        return result

    for func in cg.callees.keys():
        cg.transitive_callees[func] = compute_transitive(func, set())

    ctx.call_graph = cg
    debug(f"Built CallGraph IR: {len(cg.callees)} callers, {len(cg.transitive_callees)} with transitive callees")
    return cg


# =============================================================================
# Calls fact generation
# =============================================================================


def build_call_facts(ctx: "ProjectContext") -> None:
    """
    Generate Calls facts from InFun facts.
    Extracts direct call edges from all source files.
    """
    calls_count = 0

    for source_file in ctx.source_files.values():
        seen_edges: Set[tuple] = set()

        for fact in source_file.facts:
            if fact.name == "InFun" and "@" in fact.args[1]:
                caller = fact.args[0]
                call_id = fact.args[1]
                callee = call_id.split("@")[0]

                edge = (caller, callee)
                if edge not in seen_edges:
                    seen_edges.add(edge)
                    calls_fact = Fact("Calls", edge)
                    source_file.facts.append(calls_fact)
                    calls_count += 1

    if calls_count > 0:
        debug(f"Generated {calls_count} Calls facts")


def get_transitive_callees(
    func_name: str,
    call_graph: Dict[str, Set[str]],
    visited: Optional[Set[str]] = None,
    max_depth: int = 10,
) -> List[str]:
    """
    Get all transitive callees, bottom-up order (deepest first).

    Used for building call traces for LLM context.
    """
    if visited is None:
        visited = set()

    if func_name in visited or max_depth <= 0:
        return []
    visited.add(func_name)

    result_set: Set[str] = set()  # O(1) lookup for dedup
    result_order: List[str] = []  # Preserve insertion order
    callees = call_graph.get(func_name, set())

    for callee in callees:
        # Recursively get callee's callees FIRST (no copy - backtrack instead)
        nested = get_transitive_callees(callee, call_graph, visited, max_depth - 1)
        for nested_callee in nested:
            if nested_callee not in result_set:
                result_set.add(nested_callee)
                result_order.append(nested_callee)
        # Then add callee itself
        if callee not in result_set:
            result_set.add(callee)
            result_order.append(callee)

    visited.remove(func_name)  # Backtrack for other call paths
    return result_order


def build_call_graph_from_facts(facts: List[Fact]) -> Dict[str, Set[str]]:
    """Build caller -> callees mapping from Calls facts."""
    call_graph: Dict[str, Set[str]] = {}

    for fact in facts:
        if fact.name == "Calls":
            caller, callee = fact.args
            if caller not in call_graph:
                call_graph[caller] = set()
            call_graph[caller].add(callee)

    return call_graph


def build_global_call_graph(ctx: "ProjectContext") -> Dict[str, Set[str]]:
    """
    Build caller -> callees mapping from ALL Calls facts across ALL files.

    Cross-module call tracking for entry point analysis.
    """
    call_graph: Dict[str, Set[str]] = {}

    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "Calls":
                caller, callee = fact.args
                if caller not in call_graph:
                    call_graph[caller] = set()
                call_graph[caller].add(callee)

    return call_graph


def _build_simple_name_index(call_graph: Dict[str, Set[str]]) -> Dict[str, List[str]]:
    """Build simple_name -> [full_names] index for O(1) lookup."""
    index: Dict[str, List[str]] = {}
    for full_name in call_graph.keys():
        simple = get_simple_name(full_name)
        if simple not in index:
            index[simple] = []
        index[simple].append(full_name)
    return index


def propagate_to_callers(
    seed_funcs: Set[str],
    call_graph: Dict[str, Set[str]],
) -> Set[str]:
    """
    Propagate a property transitively up the call graph.

    Given seed functions with some property, returns all functions that
    transitively call any seed function (i.e., the property propagates up).

    Note: This is a sound over-approximation. If A calls B on one path
    but not another, A still gets the property.

    Args:
        seed_funcs: Functions with the property (e.g., direct sender checks)
        call_graph: caller -> callees mapping

    Returns:
        seed_funcs ∪ all transitive callers
    """
    # Build reverse call graph (callee -> callers)
    reverse_graph: Dict[str, Set[str]] = {}
    for caller, callees in call_graph.items():
        for callee in callees:
            if callee not in reverse_graph:
                reverse_graph[callee] = set()
            reverse_graph[callee].add(caller)

    # Build simple name index for cross-module matching
    name_index = _build_simple_name_index(call_graph)
    # Also index callees
    for callees in call_graph.values():
        for callee in callees:
            simple = get_simple_name(callee)
            if simple not in name_index:
                name_index[simple] = []
            if callee not in name_index[simple]:
                name_index[simple].append(callee)

    # Propagate using worklist
    result = set(seed_funcs)
    worklist = list(seed_funcs)

    while worklist:
        func = worklist.pop()
        func_simple = get_simple_name(func)

        # Find callers (by full name or simple name match)
        callers: Set[str] = set()
        if func in reverse_graph:
            callers.update(reverse_graph[func])
        for full_name in name_index.get(func_simple, []):
            if full_name in reverse_graph:
                callers.update(reverse_graph[full_name])

        for caller in callers:
            if caller not in result:
                result.add(caller)
                worklist.append(caller)

    return result


def is_transitively_called_from(
    func_name: str,
    source_funcs: Set[str],
    call_graph: Dict[str, Set[str]],
    visited: Optional[Set[str]] = None,
    _name_index: Optional[Dict[str, List[str]]] = None,
) -> Optional[str]:
    """
    Check if func_name is called (transitively) from any source function.

    Returns the source function name if found, None otherwise.
    Useful for checking if a function is reachable from init, entry points, etc.
    """
    if visited is None:
        visited = set()

    if _name_index is None:
        _name_index = _build_simple_name_index(call_graph)

    if func_name in source_funcs:
        return func_name

    func_simple = get_simple_name(func_name)

    for source_func in source_funcs:
        if source_func in visited:
            continue
        visited.add(source_func)

        callees = call_graph.get(source_func, set())
        for callee in callees:
            callee_simple = get_simple_name(callee)
            if callee == func_name or callee_simple == func_simple:
                return source_func
            if callee not in visited:
                # O(1) lookup via index instead of O(n) iteration
                for full_name in _name_index.get(callee_simple, []):
                    result = is_transitively_called_from(func_name, {full_name}, call_graph, visited, _name_index)
                    if result:
                        return source_func

    return None
