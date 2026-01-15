"""
Generic field-based check derivation (direct only, no propagation).

Pattern: LLM classifies field → track reads → derive "checks" fact if field value flows to condition.
Reusable for pause, frozen, enabled, and similar field-based guards.

Per-sink guards are tracked via GuardedSink facts instead of call graph propagation.

Two main functions:
1. derive_field_check_facts() - for multiple fields from classification (IsLockField → ChecksLock)
2. find_functions_checking_field() - for single specific (struct, field) pair with strict type matching
"""

from typing import Set, Dict, List, Tuple, Optional

from core.context import ProjectContext
from core.facts import Fact
from core.utils import debug, get_simple_name


def find_functions_checking_field(
    ctx: ProjectContext,
    struct_type: str,
    field_name: str,
    debug_prefix: str = "field",
) -> Set[str]:
    """
    Find functions that check a specific (struct_type, field_name) in conditions.

    Unlike derive_field_check_facts which matches by field name only,
    this uses FieldAccess (which has struct type) to ensure we match
    the exact struct.field combination. Prevents collisions when multiple
    structs have fields with the same name.

    Args:
        ctx: Project context
        struct_type: Fully qualified struct type (e.g., "pkg::Config")
        field_name: Field name (e.g., "paused")
        debug_prefix: Prefix for debug messages

    Returns:
        Set of function names that check this specific field in conditions
    """
    simple_struct = get_simple_name(struct_type)
    target_pairs = {(struct_type, field_name), (simple_struct, field_name)}

    debug(f"[{debug_prefix}] Finding functions checking {struct_type}.{field_name}")

    # Step 1: Find functions that access this specific struct.field via FieldAccess
    # FieldAccess(func_name, struct_type, field, full_expr, line)
    funcs_accessing_field: Set[str] = set()

    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "FieldAccess":
                func_name, access_struct, access_field, _, _ = fact.args
                access_simple = get_simple_name(access_struct)

                if (access_struct, access_field) in target_pairs or (access_simple, access_field) in target_pairs:
                    funcs_accessing_field.add(func_name)

    if not funcs_accessing_field:
        debug(f"[{debug_prefix}] No functions access {struct_type}.{field_name}")
        return set()

    debug(f"[{debug_prefix}] {len(funcs_accessing_field)} functions access field: {funcs_accessing_field}")

    # Step 2: Track which variables hold this field's value
    # Only for functions that actually access the target struct.field
    func_field_vars: Dict[str, Set[str]] = {}

    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "FieldAssign":
                func_name, _, target_var, _, field = fact.args
                # Only track if this function accesses our target struct.field
                if func_name in funcs_accessing_field and field == field_name:
                    if func_name not in func_field_vars:
                        func_field_vars[func_name] = set()
                    func_field_vars[func_name].add(target_var)

    # Step 3: Propagate through assignments
    changed = True
    while changed:
        changed = False
        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name == "Assigns":
                    func_name, _, target_var, source_vars = fact.args
                    if func_name in func_field_vars:
                        for source_var in source_vars:
                            if source_var in func_field_vars[func_name]:
                                if target_var not in func_field_vars[func_name]:
                                    func_field_vars[func_name].add(target_var)
                                    changed = True

    # Step 4: Find functions that check this field in conditions
    direct_checks: Set[str] = set()

    # 4a: ConditionFieldAccess - but only if function accesses our target struct
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "ConditionFieldAccess":
                func_name, _, _, field = fact.args
                # Only count if function accesses our specific struct.field
                if func_name in funcs_accessing_field and field == field_name:
                    direct_checks.add(func_name)
                    debug(f"  {func_name}: direct condition access on '{field}'")

    # 4b: ConditionCheck with variable holding field value
    # TODO: while conditions not tracked - only if/assert/abort
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "ConditionCheck":
                func_name, _, cond_vars = fact.args
                if func_name in func_field_vars:
                    for cond_var in cond_vars:
                        if cond_var in func_field_vars[func_name]:
                            if func_name not in direct_checks:
                                direct_checks.add(func_name)
                                debug(f"  {func_name}: condition uses var '{cond_var}' holding field")

    debug(f"[{debug_prefix}] {len(direct_checks)} functions directly check field: {direct_checks}")

    return direct_checks


def _is_classified_field(field: str, classified_fields: Set[str]) -> bool:
    """Check if a field name matches any classified field."""
    # Direct match
    if field in classified_fields:
        return True
    # Nested field match: settings.paused matches classified "paused"
    for classified_field in classified_fields:
        if field.endswith(f".{classified_field}") or field == classified_field:
            return True
    return False


def derive_field_check_facts(
    ctx: ProjectContext,
    field_category: str,
    checks_fact_name: str,
    infrastructure_fact_name: Optional[str] = None,
    debug_prefix: str = "field_check",
) -> int:
    """
    Generic derivation of field-based check facts with proper taint tracking.

    Pattern:
    1. Collect fields from FieldClassification with matching category
    2. Match ReadsField facts to those fields (using ReadsField from parse.py)
    3. Track field value flow to conditions:
       - Direct: ConditionFieldAccess with classified field
       - Indirect: FieldAssign + variable used in ConditionCheck
       - Transitive: Assigns propagation
    4. Propagate checks to callers
    5. Optionally generate infrastructure_fact_name(True) if any fields exist

    Args:
        ctx: Project context
        field_category: Category to match in FieldClassification (e.g., "lock")
        checks_fact_name: Fact name for checks (e.g., "ChecksLock")
        infrastructure_fact_name: Optional project-level fact (e.g., "HasLockInfrastructure")
        debug_prefix: Prefix for debug messages

    Returns:
        Total number of checks_fact_name facts generated
    """
    # Step 1: Collect all classified field names (just the field part)
    classified_fields: Set[str] = set()
    classified_struct_fields: Set[Tuple[str, str]] = set()

    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "FieldClassification" and len(fact.args) == 6:
                # FieldClassification(struct_type, field_path, category, negative, confidence, reason)
                struct_type, field_path, category, negative = fact.args[0], fact.args[1], fact.args[2], fact.args[3]
                # Only include positive classifications (negative=False) matching our category
                if category == field_category and not negative:
                    classified_fields.add(field_path)
                    classified_struct_fields.add((struct_type, field_path))
                    # Also add simple name variant for cross-module matching
                    simple_struct = get_simple_name(struct_type)
                    classified_struct_fields.add((simple_struct, field_path))

    if not classified_fields:
        debug(f"[{debug_prefix}] No FieldClassification facts with category={field_category} found")
        return 0

    debug(f"[{debug_prefix}] Found {len(classified_fields)} classified fields: {classified_fields}")

    # Step 2: Generate infrastructure fact if requested
    if infrastructure_fact_name:
        infra_fact = Fact(infrastructure_fact_name, (True,))
        ctx.project_facts.append(infra_fact)
        debug(f"[{debug_prefix}] {infrastructure_fact_name}(True)")

    # Step 3: Find functions that read classified fields using ReadsField facts
    funcs_reading_field: Dict[str, List[Tuple[str, str]]] = {}

    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "ReadsField":
                func_name, struct_type, field_path = fact.args
                simple_struct = get_simple_name(struct_type)

                # Direct match
                if (struct_type, field_path) in classified_struct_fields or (
                    simple_struct,
                    field_path,
                ) in classified_struct_fields:
                    if func_name not in funcs_reading_field:
                        funcs_reading_field[func_name] = []
                    funcs_reading_field[func_name].append((struct_type, field_path))
                    continue

                # Nested field match: only for truly nested paths like "settings.paused"
                # Skip if no dot - direct struct match should have handled it
                if "." in field_path and _is_classified_field(field_path, classified_fields):
                    if func_name not in funcs_reading_field:
                        funcs_reading_field[func_name] = []
                    funcs_reading_field[func_name].append((struct_type, field_path))

    if funcs_reading_field:
        debug(f"[{debug_prefix}] Found {len(funcs_reading_field)} functions reading classified fields")

    # Step 4: Track field value flow to conditions
    # 4a: Direct condition field access: ConditionFieldAccess(func, _, _, field) where field is classified
    direct_checks: Set[str] = set()

    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "ConditionFieldAccess":
                func_name, _, _, field = fact.args
                if _is_classified_field(field, classified_fields):
                    direct_checks.add(func_name)
                    debug(f"  {func_name}: direct condition field access on '{field}'")

    # 4b: Collect field assignments - which vars hold classified field values
    # func -> {var: field}
    func_field_vars: Dict[str, Dict[str, str]] = {}

    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "FieldAssign":
                func_name, _, target_var, _, field = fact.args
                if _is_classified_field(field, classified_fields):
                    if func_name not in func_field_vars:
                        func_field_vars[func_name] = {}
                    func_field_vars[func_name][target_var] = field

    # 4b2+4b3: Interprocedural return value tracking with iteration
    # Track functions that return classified field values and propagate via CallResult
    # Iterate until no changes to handle transitive chains (A calls B calls C)
    funcs_returning_field: Dict[str, str] = {}

    # Collect all ReturnsFieldValue facts
    returns_field_facts: List[Tuple[str, str]] = []
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "ReturnsFieldValue":
                func_name, field = fact.args
                if _is_classified_field(field, classified_fields):
                    returns_field_facts.append((func_name, field))

    changed = True
    while changed:
        changed = False

        # Update funcs_returning_field: trust ReturnsFieldValue if function reads field
        # OR has a variable holding the classified field value (from prior call)
        for func_name, field in returns_field_facts:
            if func_name not in funcs_returning_field:
                # Trust if function directly reads the field
                if func_name in funcs_reading_field:
                    funcs_returning_field[func_name] = field
                    changed = True
                # Or trust if function has a var holding the classified field value
                elif func_name in func_field_vars:
                    for var_field in func_field_vars[func_name].values():
                        if _is_classified_field(var_field, classified_fields):
                            funcs_returning_field[func_name] = field
                            changed = True
                            break

        # Propagate via CallResult: if callee returns classified field, mark caller's result var
        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name == "CallResult":
                    caller_func, _, result_var, callee = fact.args
                    callee_simple = get_simple_name(callee)
                    returned_field = funcs_returning_field.get(callee) or funcs_returning_field.get(callee_simple)
                    if returned_field:
                        if caller_func not in func_field_vars:
                            func_field_vars[caller_func] = {}
                        if result_var not in func_field_vars[caller_func]:
                            func_field_vars[caller_func][result_var] = returned_field
                            debug(f"  {caller_func}: var '{result_var}' holds '{returned_field}' from call to {callee}")
                            changed = True

    # 4b4: Interprocedural - track classified field values passed as arguments
    # CallArg(caller, stmt_id, callee, arg_idx, arg_vars)
    # FormalArg(callee, param_idx, param_name, param_type)

    # First, collect formal parameters for all functions: func -> {idx: param_name}
    func_params: Dict[str, Dict[int, str]] = {}
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "FormalArg":
                func_name, param_idx, param_name, _ = fact.args
                if func_name not in func_params:
                    func_params[func_name] = {}
                func_params[func_name][param_idx] = param_name

    # Now track which callee parameters receive classified field values
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "CallArg":
                caller_func, _, callee, arg_idx, arg_vars = fact.args
                # Check if any arg_var holds a classified field value
                if caller_func in func_field_vars:
                    for arg_var in arg_vars:
                        if arg_var in func_field_vars[caller_func]:
                            field = func_field_vars[caller_func][arg_var]
                            # Find the callee's parameter name at this index
                            callee_simple = get_simple_name(callee)
                            param_name = None
                            if callee in func_params and arg_idx in func_params[callee]:
                                param_name = func_params[callee][arg_idx]
                            elif callee_simple in func_params and arg_idx in func_params[callee_simple]:
                                param_name = func_params[callee_simple][arg_idx]

                            if param_name:
                                # Mark callee's parameter as holding classified field value
                                if callee not in func_field_vars:
                                    func_field_vars[callee] = {}
                                if param_name not in func_field_vars[callee]:
                                    func_field_vars[callee][param_name] = field
                                    debug(f"  {callee}: param '{param_name}' receives '{field}' from {caller_func}")

    # 4c: Propagate through assignments (transitive)
    # If var1 holds field value, and let var2 = var1, then var2 also holds field value
    changed = True
    while changed:
        changed = False
        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name == "Assigns":
                    func_name, _, target_var, source_vars = fact.args
                    if func_name in func_field_vars:
                        for source_var in source_vars:
                            if source_var in func_field_vars[func_name]:
                                if target_var not in func_field_vars[func_name]:
                                    func_field_vars[func_name][target_var] = func_field_vars[func_name][source_var]
                                    changed = True

    # 4d: Check if any field-holding variable is used in a condition
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "ConditionCheck":
                func_name, _, cond_vars = fact.args
                if func_name in func_field_vars:
                    for cond_var in cond_vars:
                        if cond_var in func_field_vars[func_name]:
                            if func_name not in direct_checks:
                                direct_checks.add(func_name)
                                field = func_field_vars[func_name][cond_var]
                                debug(f"  {func_name}: condition uses var '{cond_var}' holding '{field}'")

    # Step 5: Generate checks facts (direct only, no propagation)
    count = 0

    for file_ctx in ctx.source_files.values():
        for func_name in direct_checks:
            if not any(f.name == "Fun" and f.args[0] == func_name for f in file_ctx.facts):
                continue

            if any(f.name == checks_fact_name and f.args[0] == func_name for f in file_ctx.facts):
                continue

            checks_fact = Fact(checks_fact_name, (func_name,))
            file_ctx.facts.append(checks_fact)
            count += 1

    if count > 0:
        debug(f"[{debug_prefix}] Generated {count} {checks_fact_name} facts (direct only)")

    return count
