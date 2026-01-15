from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from analysis.function_index import FunctionIndex

from core.facts import Fact
from core.context import ProjectContext
from core.utils import get_simple_name
from move.extract import (
    extract_function_source,
    extract_struct_source,
    extract_function_docstring,
    extract_function_signature,
    strip_ref_modifiers,
)
from prompts import render as render_prompt


# =============================================================================
# Constants
# =============================================================================

STDLIB_PREFIXES = (
    "sui::",
    "std::",
    "u8",
    "u16",
    "u32",
    "u64",
    "u128",
    "u256",
    "bool",
    "address",
    "vector",
    "string",
    "String",
    "Option",
    "Balance",
    "Coin",
    "UID",
    "ID",
    "TxContext",
    "Clock",
    "Random",
)

SINK_FACT_TYPES = {
    "TransferSink": "transfer",
    "StateWriteSink": "state_write",
    "AmountExtractionSink": "amount_extraction",
    "ObjectDestroySink": "object_destroy",
}

# Sink types to report in structural hints
SLIPPAGE_SINK_FACTS = {"TransferSink", "AmountExtractionSink", "StateWriteSink"}


# =============================================================================
# Helper Functions
# =============================================================================


def _extract_param_types(facts: List[Fact], func_name: str) -> List[str]:
    """Extract parameter types from FormalArg facts."""
    types = []
    for fact in facts:
        if fact.name == "FormalArg" and fact.args[0] == func_name:
            param_type = fact.args[3]
            base_type = strip_ref_modifiers(param_type)
            if "<" in base_type:
                base_type = base_type[: base_type.index("<")]
            types.append(base_type)
    return types


def _find_struct_source(
    struct_name: str,
    source_code: str,
    root,
    ctx: Optional[ProjectContext] = None,
) -> Optional[str]:
    """Find struct source code, searching current file and global index."""
    if any(struct_name.startswith(p) or struct_name == p for p in STDLIB_PREFIXES):
        return None

    result = extract_struct_source(source_code, struct_name, root)
    if result:
        return result

    if ctx and ctx.global_facts_index:
        search_names = [struct_name]
        if "::" in struct_name:
            search_names.append(get_simple_name(struct_name))

        for name in search_names:
            if name in ctx.global_facts_index:
                for file_path, facts in ctx.global_facts_index[name].items():
                    has_struct_fact = any(f.name == "Struct" for f in facts)
                    if has_struct_fact and file_path in ctx.source_files:
                        file_ctx = ctx.source_files[file_path]
                        if file_ctx.source_code is None:
                            continue
                        result = extract_struct_source(file_ctx.source_code, name, file_ctx.root)
                        if result:
                            return result

    return None


def _fetch_callee_sources(
    callees: List[str],
    source_code: str,
    root,
    ctx: Optional[ProjectContext] = None,
    limit: int = 0,
) -> Dict[str, str]:
    """Fetch source code for callees.

    Args:
        callees: List of callee function names
        source_code: Current file source
        root: Current file AST root
        ctx: Project context for cross-file lookup
        limit: Max callees to fetch (0 = unlimited)

    Returns:
        Dict mapping callee name to source code
    """
    result = {}
    count = 0
    for callee in callees:
        if limit and count >= limit:
            break
        if callee.startswith("sui::") or callee.startswith("std::"):
            continue
        callee_source = extract_function_source(source_code, callee, root)
        if not callee_source and ctx and ctx.global_facts_index:
            if callee in ctx.global_facts_index:
                for file_path, _ in ctx.global_facts_index[callee].items():
                    if file_path in ctx.source_files:
                        file_ctx = ctx.source_files[file_path]
                        if file_ctx.source_code is None:
                            continue
                        callee_source = extract_function_source(file_ctx.source_code, callee, file_ctx.root)
                        if callee_source:
                            break
        if callee_source:
            result[callee] = callee_source
            count += 1
    return result


def _get_project_category_hint(ctx: Optional[ProjectContext]) -> str:
    """Get human-readable project category hint for LLM prompts."""
    if not ctx or not hasattr(ctx, "project_facts"):
        return ""
    from core.facts import PROJECT_CATEGORIES

    categories = []
    for fact in ctx.project_facts:
        if fact.name == "ProjectCategory":
            cat_id = fact.args[0]
            if cat_id in PROJECT_CATEGORIES:
                categories.append(PROJECT_CATEGORIES[cat_id])
    if categories:
        return f" (part of {', '.join(categories)} project)"
    return ""


def _get_hidden_structural_hints(
    callees: List[str],
    shown_funcs: Set[str],
    facts: List[Fact],
    ctx: Optional[ProjectContext],
) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
    """Get structural hints for callees not shown in prompt.

    Returns:
        (hidden_sinks, hidden_assertions) where each is list of (info, func_name)
    """
    hidden_sinks: List[Tuple[str, str]] = []
    hidden_assertions: List[Tuple[str, str]] = []

    # Collect facts from hidden callees
    for callee in callees:
        if callee in shown_funcs:
            continue

        # Get facts for this callee
        callee_facts: List[Fact] = []

        # From current file facts
        for f in facts:
            if f.args and f.args[0] == callee:
                callee_facts.append(f)

        # From global index
        if ctx and ctx.global_facts_index and callee in ctx.global_facts_index:
            for _, file_facts in ctx.global_facts_index[callee].items():
                callee_facts.extend(file_facts)

        # Extract relevant info
        for f in callee_facts:
            if f.name in SLIPPAGE_SINK_FACTS:
                sink_type = f.name.replace("Sink", "").lower()
                if (sink_type, callee) not in hidden_sinks:
                    hidden_sinks.append((sink_type, callee))
            elif f.name == "SanitizedByAssert" and len(f.args) >= 3:
                var = f.args[2]
                if (var, callee) not in hidden_assertions:
                    hidden_assertions.append((var, callee))

    return hidden_sinks, hidden_assertions


def _build_function_context(
    func_name: str,
    callees: List[str],
    source_code: str,
    root,
    facts: List[Fact],
    ctx: Optional[ProjectContext] = None,
    callee_limit: int = 10,
) -> Dict[str, object]:
    """Build common context for LLM prompts: entry function + callees + structural hints.

    Returns dict with template variables:
    - func_name, category_hint, entry_source, entry_docstring
    - callee_sources (dict)
    - hidden_sinks, hidden_assertions (lists of tuples)
    """
    # Project category hint
    category_hint = _get_project_category_hint(ctx)

    # Entry function
    entry_source = extract_function_source(source_code, func_name, root)
    entry_docstring = extract_function_docstring(source_code, func_name, root)

    # Callees
    callee_sources = _fetch_callee_sources(callees, source_code, root, ctx, limit=callee_limit)

    # Structural hints for callees not shown
    shown_funcs = {func_name} | set(callee_sources.keys())
    hidden_sinks, hidden_assertions = _get_hidden_structural_hints(callees, shown_funcs, facts, ctx)

    return {
        "func_name": func_name,
        "category_hint": category_hint,
        "entry_source": entry_source,
        "entry_docstring": entry_docstring,
        "callee_sources": callee_sources,
        "hidden_sinks": hidden_sinks,
        "hidden_assertions": hidden_assertions,
    }


def _extract_base_type(param_type: str) -> str:
    """Extract base type name from param type string.

    Strips:
    - Reference modifiers (&, &mut)
    - Generics (Type<T> -> Type)

    Does NOT strip module qualifiers - returns full path for accurate matching.
    """
    base = strip_ref_modifiers(param_type)
    if "<" in base:
        base = base[: base.index("<")]
    return base.strip()


def _types_match(type_a: str, type_b: str) -> bool:
    """Check if two type names match (full or simple name match)."""
    if type_a == type_b:
        return True
    return get_simple_name(type_a) == get_simple_name(type_b)


# =============================================================================
# Shared Type Helpers (used by sensitive setter)
# =============================================================================


def get_mutable_param_types(
    func_name: str,
    facts: List[Fact],
    filter_types: Optional[Set[str]] = None,
) -> List[str]:
    """Get base types from &mut parameters of a function.

    Args:
        func_name: Function to check
        facts: Facts list containing FormalArg facts
        filter_types: If provided, only return types that match these (by simple name).
                      If None, return all mutable param types.

    Returns:
        List of base type names (without &mut, without generics)
    """
    result: List[str] = []
    for fact in facts:
        if fact.name == "FormalArg" and fact.args[0] == func_name:
            param_type = fact.args[3]
            if param_type.startswith("&mut "):
                base_type = _extract_base_type(param_type)
                if filter_types is None:
                    result.append(base_type)
                else:
                    # Check if base_type matches any filter type
                    for filter_type in filter_types:
                        if _types_match(base_type, filter_type):
                            result.append(base_type)
                            break
    return result


def get_shared_types_from_facts(facts: List[Fact]) -> Set[str]:
    """Collect all shared object type names from IsSharedObject facts."""
    return {fact.args[0] for fact in facts if fact.name == "IsSharedObject"}


def get_mutable_shared_param_types(func_name: str, facts: List[Fact]) -> List[str]:
    """Get struct types from &mut parameters that are shared objects.

    Convenience function combining get_shared_types_from_facts + get_mutable_param_types.

    Returns list of struct type names that:
    1. Are passed as &mut parameters to this function
    2. Are marked as shared objects (IsSharedObject fact)
    """
    shared_types = get_shared_types_from_facts(facts)
    return get_mutable_param_types(func_name, facts, filter_types=shared_types)


def get_struct_definitions_for_types(
    type_names: List[str],
    facts: List[Fact],
    source_code: str,
    root,
    ctx: Optional[ProjectContext] = None,
) -> Dict[str, str]:
    """Get struct source definitions for given type names."""
    struct_sources: Dict[str, str] = {}
    for type_name in type_names:
        struct_src = _find_struct_source(type_name, source_code, root, ctx)
        if struct_src:
            struct_sources[type_name] = struct_src
    return struct_sources


def get_callees_with_param_types(
    callees: List[str],
    target_types: List[str],
    facts: List[Fact],
    ctx: Optional[ProjectContext] = None,
) -> List[str]:
    """Find callees that receive any of the target types as a parameter.

    Args:
        callees: List of callee function names to check
        target_types: Type names to look for in parameters
        facts: Current file facts
        ctx: Project context for cross-file lookup

    Returns:
        List of callee names that have at least one param matching target_types
    """
    target_set = set(target_types)
    result: List[str] = []

    for callee in callees:
        # Collect callee's facts from current file and global index
        callee_facts: List[Fact] = [f for f in facts if f.args and f.args[0] == callee]
        if ctx and ctx.global_facts_index and callee in ctx.global_facts_index:
            for _, file_facts in ctx.global_facts_index[callee].items():
                callee_facts.extend(file_facts)

        # Check if any param type matches target types
        for f in callee_facts:
            if f.name == "FormalArg":
                param_type = f.args[3]
                base_type = _extract_base_type(param_type)
                if any(_types_match(base_type, t) for t in target_set):
                    if callee not in result:
                        result.append(callee)
                    break

    return result


# =============================================================================
# Function Context Builder (shared by semantic_facts_builder + sensitivity)
# =============================================================================


@dataclass
class FunctionContext:
    """Rich context for a function in prompts."""

    func_name: str
    signature: str  # Compact, with docstring
    ac_flags: List[str] = field(default_factory=list)  # ["init"], ["checks sender"]
    field_snippets: List[Tuple[str, str, int]] = field(default_factory=list)  # (field_path, snippet, line_num)
    priority: int = 5  # For sorting: 0=init, 1=public entry, ..., 5=private


class FunctionContextBuilder:
    """
    Builds rich function context for classification prompts.

    Shared between:
    - semantic_facts_builder.py (struct classification)
    - sensitivity.py (field sensitivity classification)
    """

    def __init__(
        self,
        ctx: ProjectContext,
        func_index: "FunctionIndex",
        facts: List[Fact],
        max_funcs: int = 8,
        max_snippets_per_func: Optional[int] = None,  # None = no limit
    ):
        self.ctx = ctx
        self.func_index = func_index
        self.facts = facts
        self.max_funcs = max_funcs
        self.max_snippets_per_func = max_snippets_per_func

        # Pre-collect facts
        self._field_accesses = self._collect_field_accesses()
        self._event_emitters = self._collect_event_emitters()
        self._event_field_sources = self._collect_event_field_sources()
        self._event_structs = self._collect_event_structs()

    def _collect_event_structs(self) -> Set[str]:
        """Collect structs marked as events (IsEvent facts)."""
        events: Set[str] = set()
        for fact in self.facts:
            if fact.name == "IsEvent":
                events.add(fact.args[0])
        return events

    def _collect_event_emitters(self) -> Dict[str, List[str]]:
        """Collect EventEmitSink facts: {event_type -> [func_names]}"""
        result: Dict[str, List[str]] = {}
        for fact in self.facts:
            if fact.name == "EventEmitSink":
                func_name, _stmt_id, event_type = fact.args
                if func_name not in result.get(event_type, []):
                    result.setdefault(event_type, []).append(func_name)
        return result

    def _collect_event_field_sources(
        self,
    ) -> Dict[str, Dict[str, List[Tuple[str, str, str]]]]:
        """Collect EventFieldFromField: {event_type -> {field -> [(func, source_field, base_var)]}}"""
        result: Dict[str, Dict[str, List[Tuple[str, str, str]]]] = {}
        for fact in self.facts:
            if fact.name == "EventFieldFromField":
                func_name, _stmt_id, event_type, target_field, source_field, base_vars = fact.args
                if event_type not in result:
                    result[event_type] = {}
                base_var = base_vars[0] if base_vars else "?"
                result[event_type].setdefault(target_field, []).append((func_name, source_field, base_var))
        return result

    def _is_event_struct(self, struct_name: str) -> bool:
        """Check if struct is an event (via IsEvent fact or EventEmitSink)."""
        if struct_name in self._event_structs:
            return True
        # Also check by simple name match (FQN vs simple name issues)
        simple = get_simple_name(struct_name)
        for event_type in self._event_emitters:
            if get_simple_name(event_type) == simple:
                return True
        return False

    def _collect_field_accesses(
        self,
    ) -> Dict[str, List[Tuple[str, str, str, int]]]:
        """Collect FieldAccess facts: {struct -> [(func, field, snippet, line)]}"""
        result: Dict[str, List[Tuple[str, str, str, int]]] = {}
        for fact in self.facts:
            if fact.name == "FieldAccess":
                func_name, struct_type, field_path, snippet, line_num = fact.args
                result.setdefault(struct_type, []).append((func_name, field_path, snippet, line_num))
        return result

    def _find_funcs_with_param(self, struct_name: str) -> Set[str]:
        """Find functions that have this struct as a parameter."""
        simple_name = get_simple_name(struct_name)
        funcs: Set[str] = set()
        for fact in self.facts:
            if fact.name == "FormalArg":
                func_name, _, _, param_type = fact.args
                base_type = _extract_base_type(param_type)
                # Match by simple name
                if get_simple_name(base_type) == simple_name:
                    funcs.add(func_name)
        return funcs

    def _group_by_func(self, accesses: List[Tuple[str, str, str, int]]) -> Dict[str, List[Tuple[str, str, int]]]:
        """Group field accesses by function: {func -> [(field, snippet, line)]}"""
        result: Dict[str, List[Tuple[str, str, int]]] = {}
        for func_name, field_path, snippet, line_num in accesses:
            result.setdefault(func_name, []).append((field_path, snippet, line_num))
        return result

    def build_for_struct(self, struct_name: str) -> List[FunctionContext]:
        """Build function contexts for functions using a struct."""
        # For event structs, use event-specific context
        if self._is_event_struct(struct_name):
            return self._build_for_event(struct_name)

        # 1. Collect functions with this struct as param
        funcs_with_param = self._find_funcs_with_param(struct_name)

        # 2. Collect functions with field accesses
        field_accesses = self._field_accesses.get(struct_name, [])
        func_field_map = self._group_by_func(field_accesses)

        # 3. Combine
        all_funcs = funcs_with_param | set(func_field_map.keys())

        # 4. Build contexts with priority sorting
        contexts = []
        for func_name in all_funcs:
            fc = self._build_single_context(func_name, func_field_map)
            if fc:
                contexts.append(fc)

        # 5. Sort by priority, limit
        contexts.sort(key=lambda c: (c.priority, c.func_name))
        return contexts[: self.max_funcs]

    def _build_for_event(self, event_type: str) -> List[FunctionContext]:
        """Build context for event structs - shows emitters and field sources."""
        # Find emitting functions (check both FQN and simple name)
        emitters: List[str] = []
        simple = get_simple_name(event_type)
        for etype, funcs in self._event_emitters.items():
            if etype == event_type or get_simple_name(etype) == simple:
                emitters.extend(funcs)
        # Sort for deterministic prompt generation (subset selection stability)
        emitters.sort()

        # Find field sources (check both FQN and simple name)
        field_sources: Dict[str, List[Tuple[str, str, str]]] = {}
        for etype, fields in self._event_field_sources.items():
            if etype == event_type or get_simple_name(etype) == simple:
                for field, sources in fields.items():
                    field_sources.setdefault(field, []).extend(sources)

        contexts = []
        for func_name in emitters[: self.max_funcs]:
            sig = self._get_signature(func_name)
            if not sig:
                continue

            ac_flags = self.func_index.get_ac_flags(func_name)
            priority, _ = self.func_index.get_sort_key(func_name)

            # Build "snippets" showing field sources
            snippets: List[Tuple[str, str, int]] = []
            for field, sources in field_sources.items():
                for src_func, src_field, base_var in sources:
                    if src_func == func_name:
                        # Show as: "event.field ← base_var.source_field"
                        snippet = f"{simple}.{field} ← {base_var}.{src_field}"
                        snippets.append((field, snippet, 0))

            contexts.append(
                FunctionContext(
                    func_name=func_name,
                    signature=sig,
                    ac_flags=ac_flags,
                    field_snippets=snippets[: self.max_snippets_per_func],
                    priority=priority,
                )
            )

        contexts.sort(key=lambda c: (c.priority, c.func_name))
        return contexts

    def _build_single_context(
        self, func_name: str, func_field_map: Dict[str, List[Tuple[str, str, int]]]
    ) -> Optional[FunctionContext]:
        """Build context for a single function."""
        # Get signature
        sig = self._get_signature(func_name)
        if not sig:
            return None

        # Get AC flags
        ac_flags = self.func_index.get_ac_flags(func_name)

        # Get priority
        priority, _ = self.func_index.get_sort_key(func_name)

        # Get field snippets
        snippets = func_field_map.get(func_name, [])[: self.max_snippets_per_func]

        return FunctionContext(
            func_name=func_name,
            signature=sig,
            ac_flags=ac_flags,
            field_snippets=snippets,
            priority=priority,
        )

    def _get_signature(self, func_name: str) -> Optional[str]:
        """Get compact function signature with docstring."""
        for file_ctx in self.ctx.source_files.values():
            if file_ctx.source_code is None:
                continue
            sig = extract_function_signature(file_ctx.source_code, func_name, file_ctx.root)
            if sig:
                # Compact to ~single line
                lines = sig.strip().split("\n")
                return " ".join(line.strip() for line in lines)
        return None

    @staticmethod
    def format_contexts(contexts: List[FunctionContext]) -> str:
        """Format function contexts into prompt text."""
        if not contexts:
            return "(No functions use this struct)"

        lines = []
        for fc in contexts:
            # Header with signature and flags
            header = f"{fc.signature} {{"
            if fc.ac_flags:
                header += " " + " ".join(f"[{f}]" for f in fc.ac_flags)
            lines.append(header)

            # Field snippets or "no field access"
            if fc.field_snippets:
                lines.append("  // ...")
                for field_path, snippet, line_num in fc.field_snippets:
                    lines.append(f"  {snippet}")
                lines.append("  // ...")
            else:
                lines.append("  // no field access")
            lines.append("}")
            lines.append("")

        return "\n".join(lines)


# =============================================================================
# Prompt Builders
# =============================================================================


def build_access_control_prompt(
    func_name: str,
    call_trace: List[str],
    sink_types: Set[str],
    source_code: str,
    root,
    facts: List[Fact],
    ctx: Optional[ProjectContext] = None,
) -> str:
    """Build LLM prompt for access control classification."""
    # Struct definitions for parameter types
    struct_sources = {}
    param_types = _extract_param_types(facts, func_name)
    for param_type in param_types:
        if param_type not in struct_sources:
            struct_src = _find_struct_source(param_type, source_code, root, ctx)
            if struct_src:
                struct_sources[param_type] = struct_src

    # Entry function with docstring
    entry_source = extract_function_source(source_code, func_name, root)
    entry_docstring = extract_function_docstring(source_code, func_name, root)

    # Callees
    callee_sources = _fetch_callee_sources(call_trace, source_code, root, ctx)

    return render_prompt(
        "vuln/access_control.j2",
        func_name=func_name,
        struct_sources=struct_sources,
        entry_source=entry_source,
        entry_docstring=entry_docstring,
        callee_sources=callee_sources,
        sink_types=sink_types,
    )


def build_unlock_prompt(
    func_name: str,
    callees: List[str],
    source_code: str,
    root,
    facts: List[Fact],
    ctx: Optional[ProjectContext] = None,
) -> str:
    """Build prompt for missing unlock classification."""
    context = _build_function_context(func_name, callees, source_code, root, facts, ctx)
    return render_prompt("vuln/unlock.j2", **context)


def build_drain_prompt(
    func_name: str,
    callees: List[str],
    source_code: str,
    root,
    facts: List[Fact],
    ctx: Optional[ProjectContext] = None,
) -> str:
    """Build prompt for arbitrary recipient drain classification."""
    context = _build_function_context(func_name, callees, source_code, root, facts, ctx)
    return render_prompt("vuln/drain.j2", **context)


def build_transfer_prompt(
    func_name: str,
    callees: List[str],
    source_code: str,
    root,
    facts: List[Fact],
    ctx: Optional[ProjectContext] = None,
) -> str:
    """Build prompt for missing transfer classification."""
    context = _build_function_context(func_name, callees, source_code, root, facts, ctx)
    return render_prompt("vuln/transfer.j2", **context)


def build_sensitive_setter_prompt(
    func_name: str,
    callees: List[str],
    mutable_shared_types: List[str],
    struct_sources: Dict[str, str],
    source_code: str,
    root,
    facts: List[Fact],
    ctx: Optional[ProjectContext] = None,
) -> str:
    """Build prompt for sensitive setter classification."""
    # Entry function
    entry_source = extract_function_source(source_code, func_name, root)
    entry_docstring = extract_function_docstring(source_code, func_name, root)
    visibility = "public entry" if any(f.name == "IsEntry" and f.args[0] == func_name for f in facts) else "public"

    # Callees that take the mutable struct
    relevant_callees = get_callees_with_param_types(callees, mutable_shared_types, facts, ctx)
    callee_sources = {}
    if relevant_callees:
        callee_sources = _fetch_callee_sources(relevant_callees, source_code, root, ctx, limit=5)

    return render_prompt(
        "vuln/sensitive_setter.j2",
        func_name=func_name,
        visibility=visibility,
        struct_sources=struct_sources,
        entry_source=entry_source,
        entry_docstring=entry_docstring,
        callee_sources=callee_sources,
    )
