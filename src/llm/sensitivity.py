"""
LLM-based sensitive field classification.
"""

from typing import Dict, List, Set, Optional, Tuple, TYPE_CHECKING
from dataclasses import dataclass, field

if TYPE_CHECKING:
    from core.context import ProjectContext
    from llm.prompts import FunctionContextBuilder

from core.facts import Fact
from core.utils import debug, warn, get_simple_name
from llm.client import call_llm_batch
from move.types import extract_base_type, get_module_path
from move.sui_patterns import MOVE_PRIMITIVE_TYPES
from prompts import render as render_prompt


# Maximum fields per LLM query to avoid token limits and improve accuracy
MAX_FIELDS_PER_QUERY = 15


@dataclass
class FieldInfo:
    """Information about a single struct field."""

    struct_name: str  # Fully qualified struct name
    field_idx: int
    field_name: str
    field_type: str
    field_comment: Optional[str] = None  # Comment on the field itself


@dataclass
class StructInfo:
    """Information about a struct for sensitivity analysis."""

    name: str  # Fully qualified name
    fields: List[FieldInfo] = field(default_factory=list)
    struct_comment: Optional[str] = None  # Comment on the struct
    is_role: bool = False  # Skip capability structs
    is_event: bool = False  # Events themselves aren't sensitive, but their fields might be


def _collect_emitted_struct_names(facts: List[Fact]) -> Set[str]:
    """
    Find all struct names that are actually emitted in events.

    Looks for EventEmitSink(func_name, stmt_id, struct_name) facts.
    Only these structs need sensitivity analysis - the rest are irrelevant.
    """
    emitted = set()
    for fact in facts:
        if fact.name == "EventEmitSink":
            # EventEmitSink(func_name, stmt_id, struct_name)
            struct_name = fact.args[2]
            emitted.add(struct_name)
    return emitted


def _collect_source_struct_types(facts: List[Fact]) -> Set[str]:
    """
    Collect struct types that are sources in EventFieldFromField facts.

    These are source structs whose fields are copied into events.
    We need to analyze them for sensitivity to properly detect leaks.
    """
    # Find functions with EventFieldFromField facts and their base_vars
    func_vars: Dict[str, Set[str]] = {}
    for fact in facts:
        if fact.name == "EventFieldFromField":
            func_name = fact.args[0]
            base_vars = fact.args[5]
            if base_vars:
                func_vars.setdefault(func_name, set()).add(base_vars[0])

    # Resolve var names to struct types via FormalArg
    source_types: Set[str] = set()
    for fact in facts:
        if fact.name == "FormalArg":
            func_name = fact.args[0]
            param_name = fact.args[2]
            param_type = fact.args[3]
            if func_name in func_vars and param_name in func_vars[func_name]:
                base_type = extract_base_type(param_type, keep_fqn=True)
                # Qualify simple names with module path from function name
                if base_type and "::" not in base_type and "::" in func_name:
                    module_path = get_module_path(func_name)
                    base_type = f"{module_path}::{base_type}"
                source_types.add(base_type)

    return source_types


def collect_structs_for_analysis(facts: List[Fact], only_emitted: bool = True) -> List[StructInfo]:
    """
    Collect structs that need sensitivity analysis.

    Args:
        facts: All facts from the project
        only_emitted: If True, only analyze structs that are emitted in events

    Excludes:
    - Role/capability structs (IsCapability) - auto-marked sensitive, no LLM needed
    - Structs with no fields or only UID field
    - Structs NOT emitted in events (if only_emitted=True)
    """
    # First, find which structs are actually emitted
    emitted_structs = _collect_emitted_struct_names(facts) if only_emitted else None

    # Also collect source structs whose fields are copied into events
    source_structs = _collect_source_struct_types(facts) if only_emitted else None

    # Combine both sets for the filter
    structs_to_analyze = set()
    if emitted_structs:
        structs_to_analyze.update(emitted_structs)
    if source_structs:
        structs_to_analyze.update(source_structs)

    # Build a map of struct fields for nested type resolution
    struct_field_map: Dict[str, List[Tuple[str, str]]] = {}  # struct -> [(field_name, field_type)]
    for fact in facts:
        if fact.name == "StructField":
            struct_name = fact.args[0]
            field_name = fact.args[2]
            field_type = fact.args[3]
            if struct_name not in struct_field_map:
                struct_field_map[struct_name] = []
            struct_field_map[struct_name].append((field_name, field_type))

    # Add nested struct types (e.g., if UserAccount has field profile: Profile, add Profile)
    if source_structs:
        nested_types = set()
        for struct_name in source_structs:
            if struct_name in struct_field_map:
                module_path = get_module_path(struct_name)
                for _, field_type in struct_field_map[struct_name]:
                    base_type = extract_base_type(field_type, keep_fqn=True)
                    if base_type and base_type not in MOVE_PRIMITIVE_TYPES:
                        # Qualify simple names with module path
                        if "::" not in base_type and module_path:
                            base_type = f"{module_path}::{base_type}"
                        nested_types.add(base_type)
        structs_to_analyze.update(nested_types)
        if nested_types:
            debug(f"Added {len(nested_types)} nested struct types for sensitivity analysis: {nested_types}")

    if only_emitted and not structs_to_analyze:
        debug("No event emissions found - skipping sensitivity analysis")
        return []

    if only_emitted and structs_to_analyze:
        debug(f"Found {len(structs_to_analyze)} struct types for sensitivity analysis: {structs_to_analyze}")

    # Group struct fields
    struct_fields: Dict[str, List[Tuple[int, str, str]]] = {}
    struct_comments: Dict[str, str] = {}
    field_comments: Dict[str, Dict[str, str]] = {}  # struct_name -> field_name -> comment
    roles: Set[str] = set()
    events: Set[str] = set()

    for fact in facts:
        if fact.name == "StructField":
            # StructField(struct_name, field_idx, field_name, field_type)
            struct_name = fact.args[0]
            field_idx = fact.args[1]
            field_name = fact.args[2]
            field_type = fact.args[3]
            if struct_name not in struct_fields:
                struct_fields[struct_name] = []
            struct_fields[struct_name].append((field_idx, field_name, field_type))
        elif fact.name == "StructComment":
            # StructComment(struct_name, comment)
            struct_comments[fact.args[0]] = fact.args[1]
        elif fact.name == "FieldComment":
            # FieldComment(struct_name, field_name, comment)
            struct_name = fact.args[0]
            field_name = fact.args[1]
            comment = fact.args[2]
            if struct_name not in field_comments:
                field_comments[struct_name] = {}
            field_comments[struct_name][field_name] = comment
        elif fact.name == "IsCapability":
            roles.add(fact.args[0])
        elif fact.name == "IsEvent":
            events.add(fact.args[0])

    result = []
    for struct_name, fields in struct_fields.items():
        # Skip role/capability structs - they're auto-marked sensitive
        if struct_name in roles:
            continue

        # Skip structs NOT in the analysis set (if filtering enabled)
        if only_emitted and structs_to_analyze and struct_name not in structs_to_analyze:
            continue

        # Skip structs with no meaningful fields (just UID)
        if len(fields) <= 1:
            has_only_uid = all(ft.endswith("UID") or ft == "UID" for _, _, ft in fields)
            if has_only_uid:
                continue

        # Sort fields by index
        fields.sort(key=lambda x: x[0])

        # Build FieldInfo list with comments
        field_infos = []
        for field_idx, field_name, field_type in fields:
            comment = None
            if struct_name in field_comments:
                comment = field_comments[struct_name].get(field_name)
            field_infos.append(
                FieldInfo(
                    struct_name=struct_name,
                    field_idx=field_idx,
                    field_name=field_name,
                    field_type=field_type,
                    field_comment=comment,
                )
            )

        result.append(
            StructInfo(
                name=struct_name,
                fields=field_infos,
                struct_comment=struct_comments.get(struct_name),
                is_role=struct_name in roles,
                is_event=struct_name in events,
            )
        )

    # Sort for deterministic prompt generation (cache key stability)
    return sorted(result, key=lambda s: s.name)


def _collect_all_fields(structs: List[StructInfo]) -> List[FieldInfo]:
    """Flatten all fields from all structs into a single list."""
    all_fields = []
    for struct in structs:
        all_fields.extend(struct.fields)
    return all_fields


def _get_struct_comment_for_field(field: FieldInfo, structs: List[StructInfo]) -> Optional[str]:
    """Get the struct comment for a given field."""
    for struct in structs:
        if struct.name == field.struct_name:
            return struct.struct_comment
    return None


def build_sensitivity_prompt_for_batch(
    fields: List[FieldInfo],
    structs: List[StructInfo],
    context_builder: Optional["FunctionContextBuilder"] = None,
) -> Tuple[str, List[str]]:
    """
    Build a prompt asking LLM to identify sensitive fields with reason and confidence.

    Args:
        fields: List of fields to classify (max ~15)
        structs: All structs (for struct-level comments)
        context_builder: Optional builder for adding function usage context

    Returns:
        Tuple of (prompt_text, list_of_field_keys)

    Response format: JSON array with reason categories and confidence scores.
    """
    field_keys = []

    # Group fields by struct for better context
    fields_by_struct: Dict[str, List[FieldInfo]] = {}
    for f in fields:
        if f.struct_name not in fields_by_struct:
            fields_by_struct[f.struct_name] = []
        fields_by_struct[f.struct_name].append(f)
        field_keys.append(f"{f.struct_name}::{f.field_name}")

    # Sort for deterministic prompt generation (cache key stability)
    fields_by_struct = dict(sorted(fields_by_struct.items()))

    # Build struct comments dict
    struct_comments: Dict[str, str] = {}
    for struct_name in fields_by_struct:
        comment = _get_struct_comment_for_field(fields_by_struct[struct_name][0], structs)
        if comment:
            struct_comments[struct_name] = comment

    # Build function contexts if available
    func_contexts: Dict[str, str] = {}
    if context_builder:
        for struct_name in fields_by_struct:
            contexts = context_builder.build_for_struct(struct_name)
            if contexts:
                func_contexts[get_simple_name(struct_name)] = context_builder.format_contexts(contexts[:3])
        # Sort for deterministic prompt generation (cache key stability)
        func_contexts = dict(sorted(func_contexts.items()))

    prompt = render_prompt(
        "classify/sensitivity_batch.j2",
        fields_by_struct=fields_by_struct,
        struct_comments=struct_comments,
        func_contexts=func_contexts,
    )

    return prompt, field_keys


def _collect_role_sensitive_facts(facts: List[Fact]) -> List[Fact]:
    """
    Auto-mark all fields in role/capability structs as sensitive.

    Role structs (IsCapability) are access control objects - their fields
    should NEVER be exposed in events. No need to ask LLM.

    Returns list of facts:
    - FieldClassification(struct_name, field_name, "sensitive", negative=False, confidence=1.0, reason="trust")
    """
    # Collect role struct names
    roles: Set[str] = set()
    for fact in facts:
        if fact.name == "IsCapability":
            roles.add(fact.args[0])

    if not roles:
        return []

    # Mark all fields in role structs as sensitive with trust reason
    sensitive_facts = []
    for fact in facts:
        if fact.name == "StructField":
            struct_name = fact.args[0]
            field_name = fact.args[2]
            if struct_name in roles:
                sensitive_facts.append(
                    Fact("FieldClassification", (struct_name, field_name, "sensitive", False, 1.0, "trust"))
                )
                debug(f"  FieldClassification({struct_name}, {field_name}, sensitive) [auto: role struct]")

    return sensitive_facts


def analyze_sensitivity(
    facts: List[Fact],
    ctx: Optional["ProjectContext"] = None,
    api_key: Optional[str] = None,
) -> List[Fact]:
    """
    Analyze struct fields for sensitivity using LLM.

    OPTIMIZATION: Only analyzes structs that are actually emitted in events.
    No point asking about 100 structs when only 5 are ever emitted.

    Flow:
    1. Find EventEmitSink facts -> which structs are emitted
    2. Auto-mark role struct fields as sensitive (no LLM)
    3. Ask LLM ONLY about emitted non-role structs

    Batches queries to ~15 fields per call for efficiency.
    LLM returns JSON array with reason and confidence for each sensitive field.

    Args:
        facts: All facts from the project
        ctx: Optional project context for function usage analysis
        api_key: Optional API key for LLM calls

    Returns:
        List of FieldClassification facts with category="sensitive"
    """
    # First, auto-mark role struct fields as sensitive (no LLM needed)
    result_facts = _collect_role_sensitive_facts(facts)
    if result_facts:
        debug(f"Auto-marked {len(result_facts)} role struct fields as sensitive")

    # Then analyze ONLY structs that are emitted in events
    structs = collect_structs_for_analysis(facts, only_emitted=True)

    if not structs:
        debug("No additional structs to analyze for sensitivity (no event emissions or all filtered)")
        return result_facts

    all_fields = _collect_all_fields(structs)
    total_fields = len(all_fields)
    debug(f"Analyzing {total_fields} fields across {len(structs)} EMITTED structs for sensitivity")

    if total_fields == 0:
        return result_facts

    # Build shared context builder if we have project context
    context_builder = None
    if ctx:
        from analysis.function_index import FunctionIndex
        from llm.prompts import FunctionContextBuilder

        func_index = FunctionIndex(ctx)
        context_builder = FunctionContextBuilder(
            ctx=ctx,
            func_index=func_index,
            facts=facts,
            max_funcs=3,  # Fewer for sensitivity (smaller prompts)
        )
        debug("Built FunctionContextBuilder for sensitivity prompts")

    # Batch fields into chunks of MAX_FIELDS_PER_QUERY
    batch_num = 0

    for i in range(0, total_fields, MAX_FIELDS_PER_QUERY):
        batch_fields = all_fields[i : i + MAX_FIELDS_PER_QUERY]
        batch_num += 1
        debug(f"  Sensitivity batch {batch_num}: {len(batch_fields)} fields")

        # Build prompt for this batch
        prompt, field_keys = build_sensitivity_prompt_for_batch(batch_fields, structs, context_builder)

        # Call LLM - expects JSON array response
        response = call_llm_batch(prompt, api_key, context="SensitivityAnalysis")
        results = response.get("results", [])

        # Parse response - format with reason and confidence
        sensitive_fields: Dict[str, Dict] = {}  # field_key -> {reason, confidence}

        if isinstance(results, list):
            for item in results:
                if isinstance(item, dict) and "field" in item:
                    field_key = item["field"]
                    sensitive_fields[field_key] = {
                        "reason": item.get("reason", "trust"),
                        "confidence": float(item.get("confidence", 0.8)),
                    }
        else:
            warn(f"LLM returned unexpected format for batch {batch_num}: {type(results)}")
            continue

        # Emit facts for ALL fields in this batch - both sensitive and non-sensitive
        for f in batch_fields:
            field_key = f"{f.struct_name}::{f.field_name}"
            is_sensitive = field_key in sensitive_fields

            if is_sensitive:
                info = sensitive_fields[field_key]
                reason = info.get("reason", "trust")
                confidence = info.get("confidence", 0.8)
                # Emit positive classification: field IS sensitive
                result_facts.append(
                    Fact("FieldClassification", (f.struct_name, f.field_name, "sensitive", False, confidence, reason))
                )
                debug(
                    f"    FieldClassification({f.struct_name}, {f.field_name}, sensitive) reason={reason} conf={confidence:.2f}"
                )
            else:
                # Emit negative classification: field is NOT sensitive
                result_facts.append(
                    Fact("FieldClassification", (f.struct_name, f.field_name, "sensitive", True, 1.0, ""))
                )
                debug(f"    FieldClassification({f.struct_name}, {f.field_name}, NOT sensitive)")

    sensitive_count = sum(
        1
        for f in result_facts
        if f.name == "FieldClassification" and len(f.args) == 6 and f.args[2] == "sensitive" and not f.args[3]
    )
    debug(f"Analyzed {len(all_fields)} fields, {sensitive_count} marked sensitive")
    return result_facts
