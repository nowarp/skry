import json
import os
import re
from enum import Enum
from typing import Any, Dict, List, Tuple, Optional, TextIO, Union

from rules.ir import Rule, Severity
from rules.hy_loader import HyRule
from rules.ir import Binding
from core.context import ProjectContext
from core.facts import (
    find_fact,
    find_facts,
    collect_facts_from_all_files,
)


_USE_COLOR = not os.environ.get("SKRY_NO_COLORS")


class _C:
    """ANSI color codes."""

    RESET = "\033[0m" if _USE_COLOR else ""
    BOLD = "\033[1m" if _USE_COLOR else ""
    DIM = "\033[2m" if _USE_COLOR else ""
    # Colors
    RED = "\033[31m" if _USE_COLOR else ""
    GREEN = "\033[32m" if _USE_COLOR else ""
    YELLOW = "\033[33m" if _USE_COLOR else ""
    BLUE = "\033[34m" if _USE_COLOR else ""
    MAGENTA = "\033[35m" if _USE_COLOR else ""
    CYAN = "\033[36m" if _USE_COLOR else ""
    WHITE = "\033[37m" if _USE_COLOR else ""
    # Bright variants
    BRIGHT_RED = "\033[91m" if _USE_COLOR else ""
    BRIGHT_YELLOW = "\033[93m" if _USE_COLOR else ""


def _severity_color(severity: Severity) -> str:
    """Get color code for severity level."""
    colors = {
        Severity.CRITICAL: f"{_C.BOLD}{_C.BRIGHT_RED}",
        Severity.HIGH: _C.RED,
        Severity.MEDIUM: _C.YELLOW,
        Severity.LOW: _C.CYAN,
        Severity.INFO: _C.DIM,
    }
    return colors.get(severity, "")


# Union type for both rule types
AnyRule = Union[Rule, HyRule]

# Maximum context items to show (prevents verbose output)
MAX_CONTEXT_ITEMS = 3

# Debug mode for context extraction (set SKRY_DEBUG=1)
_DEBUG = os.environ.get("SKRY_DEBUG", "0") == "1"


def _debug(msg: str) -> None:
    """Print debug message if SKRY_DEBUG=1."""
    if _DEBUG:
        print(f"[reporter] {msg}")


class OutputMode(Enum):
    """Violation output verbosity modes."""

    SHORT = "short"  # Just rule name, location, function
    FULL = "full"  # + severity, description
    CONTEXT = "context"  # + examples, function source code, LLM debug context
    JSON = "json"  # Machine-readable JSON output


def report_violations(
    violations: List[Tuple[AnyRule, Binding]],
    ctx: ProjectContext,
    output_mode: OutputMode = OutputMode.SHORT,
    output_file: Optional[TextIO] = None,
) -> int:
    """
    Report violations with configurable verbosity.

    Args:
        violations: List of (Rule, Binding) tuples
        ctx: Project context with source files and location maps
        output_mode: SHORT (default), FULL, CONTEXT, or JSON
        output_file: Optional file handle to write output to (in addition to stdout)

    Returns: Number of violations found
    """
    # Dispatch to JSON reporter
    if output_mode == OutputMode.JSON:
        return report_violations_json(violations, ctx, output_file)

    def _print(msg: str = ""):
        print(msg)
        if output_file:
            print(msg, file=output_file)

    if not violations:
        _print("No violations found")
        return 0

    _print(f"\nFound {len(violations)} violation(s):\n")

    for rule, binding in violations:
        _report_single_violation(rule, binding, ctx, output_mode, output_file)

    return len(violations)


def _simplify_name(fqn: str) -> str:
    """Extract simple name from FQN (e.g., 'module::Config' -> 'Config').

    See module docstring for FQN simplification strategy rationale.
    """
    return fqn.split("::")[-1] if "::" in fqn else fqn


def _get_all_unused_args(func_name: str, ctx: ProjectContext) -> List[Tuple[str, int]]:
    """Look up all UnusedArg facts for a function.

    Returns list of (param_name, 1-indexed_param_idx) tuples, sorted by param index.
    """
    facts = find_facts(func_name, "UnusedArg", ctx)
    if not facts:
        return []
    # UnusedArg(func_name, param_name, param_idx)
    # Deduplicate by (param_name, idx) to avoid duplicates from multiple files
    seen = set()
    result = []
    for f in facts:
        key = (f.args[1], f.args[2])
        if key not in seen:
            seen.add(key)
            result.append((f.args[1], f.args[2] + 1))  # +1 for 1-indexed
    return sorted(result, key=lambda x: x[1])  # Sort by param index


def _get_rule_context(rule_name: str, func_name: str, ctx: ProjectContext) -> Optional[str]:
    """Get human-readable context for a rule violation.

    Returns a short string like "writes Config.fee_rate" or "tainted write from param 'data'".
    """
    context = None
    if rule_name == "tainted-state-modification":
        context = _get_tainted_write_context(func_name, ctx)
    elif rule_name == "tainted-amount-drain":
        context = _get_tainted_amount_context(func_name, ctx)
    elif rule_name == "weak-randomness":
        context = _get_weak_randomness_context(func_name, ctx)
    elif rule_name == "config-write-without-privileged":
        context = _get_config_write_context(func_name, ctx)
    elif rule_name == "missing-authorization":
        context = _get_auth_sink_context(func_name, ctx)
    elif rule_name == "missing-admin-event":
        context = _get_missing_admin_event_context(func_name, ctx)
    elif rule_name == "user-asset-write-without-ownership":
        context = _get_user_asset_write_context(func_name, ctx)

    if context is None and rule_name in (
        "tainted-state-modification",
        "tainted-amount-drain",
        "weak-randomness",
        "config-write-without-privileged",
        "missing-authorization",
        "missing-admin-event",
        "user-asset-write-without-ownership",
    ):
        _debug(f"_get_rule_context: no context found for {rule_name} on {func_name}")

    return context


def _get_tainted_write_context(func_name: str, ctx: ProjectContext) -> Optional[str]:
    """Get context for tainted-state-modification rule.

    Uses O(1) indexed lookup for TaintedAtSink facts with sink_type='state_write'.
    """
    facts = find_facts(func_name, "TaintedAtSink", ctx)
    for fact in facts:
        # TaintedAtSink(func_name, source, stmt_id, sink_type, cap)
        if len(fact.args) > 3 and fact.args[3] == "state_write":
            source = fact.args[1]
            param_name = _resolve_source_to_param(func_name, source, ctx)
            if param_name:
                return f"tainted write from param '{param_name}'"
            return f"tainted write from '{source}'"
    return None


def _get_tainted_amount_context(func_name: str, ctx: ProjectContext) -> Optional[str]:
    """Get context for tainted-amount-drain rule.

    Returns format: "tainted 'param_name' → callee"
    """
    facts = find_facts(func_name, "TaintedAtSink", ctx)
    for fact in facts:
        # TaintedAtSink(func_name, source, stmt_id, sink_type, cap)
        if len(fact.args) > 3 and fact.args[3] == "amount_extraction":
            source = fact.args[1]
            stmt_id = fact.args[2]

            # Resolve source to param name
            param_name = _resolve_source_to_param(func_name, source, ctx)
            display_source = param_name or source

            # Find matching AmountExtractionSink to get callee
            sink_facts = find_facts(func_name, "AmountExtractionSink", ctx)
            for sf in sink_facts:
                if sf.args[1] == stmt_id:
                    callee = _simplify_name(sf.args[2])
                    return f"tainted '{display_source}' → {callee}"

            # Fallback: no callee found
            return f"tainted '{display_source}' in amount extraction"
    return None


def _resolve_source_to_param(func_name: str, source: str, ctx: ProjectContext) -> Optional[str]:
    """Resolve a taint source like 'param_0' to the actual parameter name.

    Uses O(1) indexed lookup for TaintSource facts.
    """
    taint_sources = find_facts(func_name, "TaintSource", ctx)
    for fact in taint_sources:
        # TaintSource(func_name, param_name, param_idx)
        if fact.args[1] == source or f"param_{fact.args[2]}" == source:
            return fact.args[1]
    return None


def _get_weak_randomness_context(func_name: str, ctx: ProjectContext) -> Optional[str]:
    """Get context for weak-randomness rule.

    Uses O(1) indexed lookup for TrackedSource/TrackedDerivedFrom facts.
    """
    sources = set()

    # TrackedSource(func_name, stmt_id, result_var, source_type, callee)
    for fact in find_facts(func_name, "TrackedSource", ctx):
        if fact.args[3] == "weak_random":
            callee = fact.args[4]
            sources.add(_simplify_name(callee))

    # TrackedDerivedFrom(func_name, var, source_type, callee)
    for fact in find_facts(func_name, "TrackedDerivedFrom", ctx):
        if fact.args[2] == "weak_random":
            callee = fact.args[3]
            sources.add(_simplify_name(callee))

    if sources:
        sorted_sources = sorted(sources)[:MAX_CONTEXT_ITEMS]
        return f"uses {', '.join(sorted_sources)} for randomness"
    return None


def _get_config_write_context(func_name: str, ctx: ProjectContext) -> Optional[str]:
    """Get context for config-write-without-privileged rule.

    Uses O(1) indexed lookup for WritesField facts.
    If no mutable_config FieldClassification facts exist (LLM not run), shows all WritesField facts.
    """
    # Collect FieldClassification facts with category="mutable_config" (struct-level, requires full scan)
    mutable_config_fields = set()
    for fact in collect_facts_from_all_files("FieldClassification", ctx):
        # FieldClassification(struct_type, field_path, category, negative, confidence, reason)
        if len(fact.args) == 6 and fact.args[2] == "mutable_config" and not fact.args[3]:
            mutable_config_fields.add((fact.args[0], fact.args[1]))

    # Find WritesField facts for this function (O(1) lookup)
    config_writes = []
    for fact in find_facts(func_name, "WritesField", ctx):
        # WritesField(func_name, struct_type, field_path)
        struct_type, field_path = fact.args[1], fact.args[2]
        # Include if: known mutable config field, OR no config classification available
        if (struct_type, field_path) in mutable_config_fields or not mutable_config_fields:
            simple_struct = _simplify_name(struct_type)
            config_writes.append(f"{simple_struct}.{field_path}")

    if config_writes:
        return f"writes {', '.join(config_writes[:MAX_CONTEXT_ITEMS])}"
    return None


def _get_user_asset_write_context(func_name: str, ctx: ProjectContext) -> Optional[str]:
    """Get context for user-asset-write-without-ownership rule.

    Returns the user asset container(s) being written to.
    """
    containers = []
    for fact in find_facts(func_name, "WritesUserAsset", ctx):
        # WritesUserAsset(func_name, struct_type)
        struct_type = fact.args[1]
        containers.append(_simplify_name(struct_type))

    if containers:
        return f"writes {', '.join(sorted(set(containers))[:MAX_CONTEXT_ITEMS])}"
    return None


# Priority order for sink facts: tainted (more specific) before base sinks
# For TaintedAtSink, we use tuples: (fact_name, sink_type_filter, priority, description)
_SINK_PRIORITY = [
    ("TaintedAtSink", "transfer_recipient", 1, "transfer to tainted recipient"),
    ("TaintedAtSink", "transfer_value", 2, "transfer of tainted value"),
    ("TaintedAtSink", "state_write", 3, "tainted state write"),
    ("TaintedAtSink", "amount_extraction", 4, "tainted amount extraction"),
    ("TaintedAtSink", "object_destroy", 5, "tainted object destruction"),
    ("TransferSink", None, 10, "transfer"),
    ("StateWriteSink", None, 11, "state write"),
    ("AmountExtractionSink", None, 12, "amount extraction"),
]


def _get_auth_sink_context(func_name: str, ctx: ProjectContext) -> Optional[str]:
    """Get context for missing-authorization rule.

    Returns the most specific sink description (tainted facts have higher priority).
    Uses O(1) indexed lookup for each sink type.
    """
    best_priority = 999
    best_description = None

    # Check each sink type using indexed lookup
    for entry in _SINK_PRIORITY:
        fact_name, sink_type_filter, priority, description = entry

        if priority >= best_priority:
            continue  # Skip if we already have a better match

        # For TaintedAtSink, filter by sink_type
        if fact_name == "TaintedAtSink" and sink_type_filter:
            facts = find_facts(func_name, fact_name, ctx)
            for fact in facts:
                if len(fact.args) > 3 and fact.args[3] == sink_type_filter:
                    best_priority = priority
                    best_description = description
                    break
        else:
            # For other fact types, use simple lookup
            fact = find_fact(func_name, fact_name, ctx)
            if fact:
                best_priority = priority
                best_description = description

    return best_description


def _get_missing_admin_event_context(func_name: str, ctx: ProjectContext) -> Optional[str]:
    """Get context for missing-admin-event rule."""
    reasons = []
    suggestions = []

    if find_fact(func_name, "HasValueExtraction", ctx):
        reasons.append("extracts value")
        suggestions.append("amount")

    for fact in find_facts(func_name, "TaintedAtSink", ctx):
        if len(fact.args) > 3 and fact.args[3] == "transfer_recipient":
            reasons.append("transfers to user-controlled address")
            suggestions.append("recipient")
            break

    if not reasons:
        return None

    result = ", ".join(reasons)
    if suggestions:
        result += f". Emit event with: {', '.join(suggestions)}"
    return result


def _report_single_violation(
    rule: AnyRule,
    binding: Binding,
    ctx: ProjectContext,
    output_mode: OutputMode,
    output_file: Optional[TextIO] = None,
) -> None:
    """Report a single violation with the specified verbosity."""

    def _print(msg: str = ""):
        print(msg)
        if output_file:
            print(msg, file=output_file)

    # Determine primary binding: function ('f'), role ('r'), event ('e'), or struct-field tuple
    func_name = binding.get("f")
    role_name = binding.get("r")
    event_name = binding.get("e")

    # Handle struct-field tuple bindings (from mutable-config-field pattern)
    if isinstance(func_name, tuple) and len(func_name) == 2:
        struct_name, field_name = func_name
        primary_name = struct_name
        primary_type = "struct-field"
        field_display = field_name
    # Handle func-struct-field triple bindings (from writes-protocol-invariant pattern)
    elif isinstance(func_name, tuple) and len(func_name) == 3:
        fn_name, struct_name, field_name = func_name
        primary_name = fn_name
        primary_type = "protocol-invariant-write"
        field_display = f"{struct_name}.{field_name}"
    else:
        primary_name = func_name or role_name or event_name or "unknown"
        primary_type = "function" if func_name else ("role" if role_name else ("event" if event_name else "unknown"))
        field_display = None

    # Find location for this entity
    location_str = ""
    for file_path, location_map in ctx.all_location_maps.items():
        if primary_name in location_map:
            location_str = f"{location_map[primary_name]}"
            break

    # === SHORT mode (always shown) ===
    sev = rule.severity
    sev_color = _severity_color(sev)
    sev_tag = f"{sev_color}{sev.value.upper()}{_C.RESET}"
    rule_tag = f"{_C.BOLD}{rule.name}{_C.RESET}"

    if primary_type == "struct-field":
        _print(f"[{sev_tag}][{rule_tag}][{location_str}] field '{primary_name}.{field_display}'")
    elif primary_type == "protocol-invariant-write":
        _print(
            f"[{sev_tag}][{rule_tag}][{location_str}] in function '{primary_name}' writes to invariant '{field_display}'"
        )
    elif primary_type == "role":
        _print(f"[{sev_tag}][{rule_tag}][{location_str}] role '{primary_name}'")
    elif primary_type == "event":
        _print(f"[{sev_tag}][{rule_tag}][{location_str}] event '{primary_name}'")
    else:
        if rule.name == "unused-arg":
            # Special handling: print one line per unused parameter
            unused_args = _get_all_unused_args(primary_name, ctx)
            if unused_args:
                for param_name, _ in unused_args:
                    _print(
                        f"[{sev_tag}][{rule_tag}][{location_str}] in function '{primary_name}' - unused parameter '{param_name}'"
                    )
            else:
                _print(f"[{sev_tag}][{rule_tag}][{location_str}] in function '{primary_name}'")
        else:
            # Look up context for other rules
            context_suffix = ""
            context = _get_rule_context(rule.name, primary_name, ctx)
            if context:
                context_suffix = f" - {context}"
            _print(f"[{sev_tag}][{rule_tag}][{location_str}] in function '{primary_name}'{context_suffix}")

    # Show relevant bindings (exclude primary binding keys)
    relevant_bindings = {k: v for k, v in binding.items() if k not in ("f", "r", "e") and not k.endswith("_type")}
    if relevant_bindings:
        for key, value in relevant_bindings.items():
            binding_location = None
            for file_path, location_map in ctx.all_location_maps.items():
                if value in location_map:
                    binding_location = location_map[value]
                    break

            if binding_location:
                _print(f"  {key}: {value} ({binding_location})")
            else:
                _print(f"  {key}: {value}")

    # === FULL mode: add description (severity already shown in header) ===
    if output_mode in (OutputMode.FULL, OutputMode.CONTEXT):
        if rule.description:
            _print(f"  {_C.DIM}Description:{_C.RESET} {rule.description}")

    # === CONTEXT mode: add examples + function source + LLM debug context ===
    if output_mode == OutputMode.CONTEXT:
        # Examples only available for traditional Rule, not HyRule
        example_bad = getattr(rule, "example_bad", None)
        example_fixed = getattr(rule, "example_fixed", None)

        if example_bad:
            _print("  Example (vulnerable):")
            for line in example_bad.strip().split("\n"):
                _print(f"    {line}")

        if example_fixed:
            _print("  Example (fixed):")
            for line in example_fixed.strip().split("\n"):
                _print(f"    {line}")

        # Show LLM debug context if available (only for function-based rules)
        if func_name:
            _print_llm_debug_context(func_name, _print)

    _print()


def _print_llm_debug_context(func_name: str, _print) -> None:
    """Print LLM debug context if available for this function.

    First checks in-memory context (populated during current run with SKRY_LLM_DEBUG=1),
    then falls back to cached context from previous runs.
    """
    try:
        from llm.classify import get_vulnerability_context, get_cached_llm_context

        # Try in-memory context first (richer, from debug mode)
        vuln_ctx = get_vulnerability_context(func_name)
        if vuln_ctx:
            _print("")
            _print("  === LLM Analysis Context ===")

            if vuln_ctx.reasoning:
                _print(f"  Classification: {vuln_ctx.classification}")
                _print(f"  Reasoning: {vuln_ctx.reasoning}")

            if vuln_ctx.call_trace:
                trace_str = " -> ".join([vuln_ctx.entry_point] + vuln_ctx.call_trace[:5])
                if len(vuln_ctx.call_trace) > 5:
                    trace_str += f" ... (+{len(vuln_ctx.call_trace) - 5} more)"
                _print(f"  Call trace: {trace_str}")

            if vuln_ctx.sink_types:
                _print(f"  Dangerous operations: {', '.join(sorted(vuln_ctx.sink_types))}")

            if vuln_ctx.attack_scenario:
                _print("")
                _print("  Attack Scenario:")
                for line in vuln_ctx.attack_scenario.split("\n"):
                    _print(f"    {line}")

            if vuln_ctx.missing_checks:
                _print("")
                _print("  Missing Checks:")
                for line in vuln_ctx.missing_checks.split("\n"):
                    _print(f"    {line}")

            if vuln_ctx.suggested_fix:
                _print("")
                _print("  Suggested Fix:")
                for line in vuln_ctx.suggested_fix.split("\n"):
                    _print(f"    {line}")

            _print("  === End LLM Context ===")
            return

        # Fallback: try to load from cache
        cached = get_cached_llm_context(func_name)
        if cached:
            _print("")
            _print("  === LLM Analysis Context (cached) ===")

            reason = cached.get("reason", "")
            if reason:
                _print(f"  Reasoning: {reason}")

            call_trace = cached.get("call_trace", [])
            if call_trace:
                trace_str = " -> ".join([func_name] + call_trace[:5])
                if len(call_trace) > 5:
                    trace_str += f" ... (+{len(call_trace) - 5} more)"
                _print(f"  Call trace: {trace_str}")

            sink_types = cached.get("sink_types", [])
            if sink_types:
                _print(f"  Dangerous operations: {', '.join(sorted(sink_types))}")

            _print("  === End LLM Context ===")

    except ImportError:
        # llm module not available
        pass


# =============================================================================
# JSON Output
# =============================================================================


def _parse_location(location: Any) -> Dict[str, Any]:
    """Parse location (SourceLocation or string) into components."""
    if not location:
        return {"file": "", "line": 0, "column": 0}

    # Handle SourceLocation dataclass
    if hasattr(location, "file") and hasattr(location, "line"):
        return {
            "file": location.file,
            "line": location.line,
            "column": getattr(location, "column", 0),
        }

    # Handle string format: file:line:col
    location_str = str(location)
    match = re.match(r"^(.+):(\d+):(\d+)$", location_str)
    if match:
        return {
            "file": match.group(1),
            "line": int(match.group(2)),
            "column": int(match.group(3)),
        }

    # Pattern: file:line (no column)
    match = re.match(r"^(.+):(\d+)$", location_str)
    if match:
        return {
            "file": match.group(1),
            "line": int(match.group(2)),
            "column": 0,
        }

    return {"file": location_str, "line": 0, "column": 0}


def _violation_to_dict(
    rule: AnyRule,
    binding: Binding,
    ctx: ProjectContext,
) -> Dict[str, Any]:
    """Convert a violation to a JSON-serializable dict."""
    result: Dict[str, Any] = {
        "rule": rule.name,
        "severity": rule.severity.value,
    }

    # Determine primary binding and entity type
    func_name = binding.get("f")
    role_name = binding.get("r")
    event_name = binding.get("e")

    # Handle struct-field tuple bindings
    if isinstance(func_name, tuple) and len(func_name) == 2:
        struct_name, field_name = func_name
        result["struct"] = struct_name
        result["field"] = field_name
        primary_name = struct_name
    # Handle func-struct-field triple bindings
    elif isinstance(func_name, tuple) and len(func_name) == 3:
        fn_name, struct_name, field_name = func_name
        result["function"] = fn_name
        result["struct"] = struct_name
        result["field"] = field_name
        primary_name = fn_name
    elif func_name:
        result["function"] = func_name
        primary_name = func_name
    elif role_name:
        result["role"] = role_name
        primary_name = role_name
    elif event_name:
        result["event"] = event_name
        primary_name = event_name
    else:
        primary_name = "unknown"

    # Find location
    location_str = ""
    for file_path, location_map in ctx.all_location_maps.items():
        if primary_name in location_map:
            location_str = location_map[primary_name]
            break
    result["location"] = _parse_location(location_str)

    # Add context hint
    if func_name and not isinstance(func_name, tuple):
        context = _get_rule_context(rule.name, func_name, ctx)
        if context:
            result["context"] = context

    return result


def report_violations_json(
    violations: List[Tuple[AnyRule, Binding]],
    ctx: ProjectContext,
    output_file: Optional[TextIO] = None,
) -> int:
    """Report violations in JSON format."""
    violation_dicts = [_violation_to_dict(rule, binding, ctx) for rule, binding in violations]

    output = {
        "violations": violation_dicts,
        "total": len(violations),
    }

    json_str = json.dumps(output, indent=2)
    print(json_str)
    if output_file:
        print(json_str, file=output_file)

    return len(violations)
