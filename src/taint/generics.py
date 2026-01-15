"""
Generic type validation analysis - taint-style tracking.

This module implements precise generic type parameter validation tracking:
1. Detects which type params are validated via type_name::get<T>()
2. Tracks which type params reach sinks (coin::take<T>, balance::split<T>)
3. Generates UnvalidatedTypeAtSink / ValidatedTypeAtSink facts

Key concepts:
- Validation: type_name::get<T>() validates type parameter T
- Sinks: Generic extraction functions that operate on type T
- Mapping: Caller's type param T -> Callee's type param position

This replaces the old call graph-based approach with precise dataflow tracking.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional

from core.facts import Fact, add_fact, names_match
from core.utils import debug
from core.context import ProjectContext
from move.sui_patterns import TYPE_NAME_GET_CALLEES, GENERIC_EXTRACTION_SINKS, is_stdlib_type


@dataclass
class GenericTypeState:
    """Tracks generic type validation state for a function."""

    # Which type params are validated (after type_name::get<T>)
    validated_types: Set[str] = field(default_factory=set)

    # Which type params reach which sinks: type_var -> [(stmt_id, callee)]
    type_to_sinks: Dict[str, List[Tuple[str, str]]] = field(default_factory=dict)


@dataclass
class GenericTypeSummary:
    """Summary of generic type behavior for a function."""

    func_name: str

    # Type param name -> True if validated in this function or transitively
    type_param_validated: Dict[str, bool] = field(default_factory=dict)

    # Type param name -> set of sink callees reached if NOT validated
    type_param_to_sinks: Dict[str, Set[str]] = field(default_factory=dict)

    # Type params that are validated but don't reach sinks (pure validator helpers)
    # Callers of this function should inherit validation for these type params
    functions_validates: Set[str] = field(default_factory=set)


def _parse_generic_type(param_type: str) -> Tuple[Optional[str], List[str]]:
    """
    Parse a generic type parameter to extract struct name and type arguments.

    Examples:
        "Pool<T>" -> ("Pool", ["T"])
        "&mut LiquidStakingInfo<P>" -> ("LiquidStakingInfo", ["P"])
        "Pair<A, B>" -> ("Pair", ["A", "B"])
        "u64" -> (None, [])

    Returns:
        (struct_name, type_args) - struct_name is None if not a generic type
    """
    # Strip reference modifiers
    param_type = param_type.strip()
    if param_type.startswith("&mut "):
        param_type = param_type[5:].strip()
    elif param_type.startswith("&"):
        param_type = param_type[1:].strip()

    # Check if it has generic params
    if "<" not in param_type or ">" not in param_type:
        return (None, [])

    # Extract struct name and type args
    try:
        open_idx = param_type.index("<")
        close_idx = param_type.rindex(">")
        struct_name = param_type[:open_idx].strip()
        type_args_str = param_type[open_idx + 1 : close_idx].strip()

        # Parse type arguments (simple comma-split, doesn't handle nested generics)
        type_args = [arg.strip() for arg in type_args_str.split(",") if arg.strip()]

        return (struct_name, type_args)
    except (ValueError, IndexError):
        return (None, [])


def infer_generic_call_args_from_fields(func_name: str, facts: List[Fact]) -> List[Fact]:
    """
    Infer GenericCallArg facts from field accesses and parameter types in extraction sink calls.

    When a generic extraction sink like coin::take is called with a field access
    (e.g., coin::take(&mut pool.balance, ...)) or a parameter with generic type
    (e.g., coin::take(balance, ...) where balance: &mut Balance<T>), the type
    parameter is inferred rather than being explicit in the call.

    This function generates GenericCallArg facts for such inferred type arguments.

    Examples:
        1. Field access:
           struct Mixed<phantom T, U> { balance_u: Balance<U> }
           fun extract_u<T, U>(mixed: &mut Mixed<T, U>) {
               coin::take(&mut mixed.balance_u, ...)  // U is inferred from balance_u
           }
           -> GenericCallArg(extract_u, stmt_id, coin::take, 0, U)

        2. Parameter type:
           fun withdraw<T>(balance: &mut Balance<T>, ...) {
               coin::take(balance, ...)  // T is inferred from balance param type
           }
           -> GenericCallArg(withdraw, stmt_id, coin::take, 0, T)
    """
    derived: List[Fact] = []

    # Get function's type parameters
    func_type_params: Set[str] = set()
    for fact in facts:
        if fact.name == "HasGenericParam" and fact.args[0] == func_name:
            func_type_params.add(fact.args[2])

    if not func_type_params:
        return derived

    # Build struct field type index: (struct_simple_name, field_name) -> field_type
    struct_field_types: Dict[Tuple[str, str], str] = {}
    for fact in facts:
        if fact.name == "StructField" and len(fact.args) >= 4:
            struct_name, _, field_name, field_type = fact.args
            # Use simple name for matching
            simple_struct = struct_name.split("::")[-1] if "::" in struct_name else struct_name
            struct_field_types[(simple_struct, field_name)] = field_type

    # Build parameter name -> type index for this function
    param_types: Dict[str, str] = {}  # param_name -> param_type
    for fact in facts:
        if fact.name == "FormalArg" and fact.args[0] == func_name:
            _, _, param_name, param_type = fact.args
            param_types[param_name] = param_type

    # Find extraction sink calls and their stmt_ids
    # AmountExtractionSink(func, stmt_id, callee) or CallResult(func, stmt_id, var, callee)
    sink_calls: Dict[str, str] = {}  # stmt_id -> callee
    for fact in facts:
        if fact.name == "AmountExtractionSink" and fact.args[0] == func_name:
            _, stmt_id, callee = fact.args
            sink_calls[stmt_id] = callee
        elif fact.name == "CallResult" and fact.args[0] == func_name:
            _, stmt_id, _, callee = fact.args
            if callee in GENERIC_EXTRACTION_SINKS:
                sink_calls[stmt_id] = callee

    # Check existing GenericCallArg facts to avoid duplicates
    existing_generic_args: Set[Tuple[str, str, int]] = set()  # (stmt_id, callee, type_idx)
    for fact in facts:
        if fact.name == "GenericCallArg" and fact.args[0] == func_name:
            _, stmt_id, callee, type_idx, _ = fact.args
            existing_generic_args.add((stmt_id, callee, type_idx))

    # Build CallArg index: (stmt_id, callee, arg_idx) -> [arg_var_names]
    call_args: Dict[Tuple[str, str, int], List[str]] = {}
    for fact in facts:
        if fact.name == "CallArg" and fact.args[0] == func_name:
            _, stmt_id, callee, arg_idx, arg_vars = fact.args
            call_args[(stmt_id, callee, arg_idx)] = list(arg_vars)

    # Strategy 1: Infer from field accesses
    # FieldAccess(func, struct_type, field, code, line)
    for fact in facts:
        if fact.name != "FieldAccess" or fact.args[0] != func_name:
            continue

        _, struct_type_with_params, field_name, code, _ = fact.args

        # Check if this field access is in an extraction sink call
        matching_sink_stmt = None
        matching_callee = None
        for stmt_id, callee in sink_calls.items():
            # Check if the callee appears in the code containing this field access
            callee_simple = callee.split("::")[-1] if "::" in callee else callee
            if callee_simple in code or callee in code:
                matching_sink_stmt = stmt_id
                matching_callee = callee
                break

        if not matching_sink_stmt or not matching_callee:
            continue

        # Parse struct type to get type params: "Mixed<T, U>" -> ["T", "U"]
        struct_name, struct_type_args = _parse_generic_type(struct_type_with_params)

        # If struct_name is None (no generics in FieldAccess), extract from FQN
        if not struct_name:
            struct_name = (
                struct_type_with_params.split("::")[-1] if "::" in struct_type_with_params else struct_type_with_params
            )

        # If no type args in FieldAccess, look them up from parameter types
        # FieldAccess often has just struct name without generics (e.g., 'Mixed' not 'Mixed<T, U>')
        # but parameter types have the full instantiated type
        if not struct_type_args:
            for param_name, param_type in param_types.items():
                param_struct, param_type_args = _parse_generic_type(param_type)
                if param_struct and names_match(param_struct, struct_name):
                    struct_type_args = param_type_args
                    break
            if not struct_type_args:
                continue

        # Look up field type from StructField facts
        simple_struct = struct_name.split("::")[-1] if "::" in struct_name else struct_name
        field_type = struct_field_types.get((simple_struct, field_name))
        if not field_type:
            continue

        # Parse field type to get type params: "Balance<U>" -> ["U"]
        _, field_type_args = _parse_generic_type(field_type)
        if not field_type_args:
            continue

        # Map field type params back to struct type params, then to function type params
        for field_type_arg in field_type_args:
            # Find this type arg in struct's type args
            if field_type_arg in struct_type_args:
                # This field type arg is one of the struct's type params
                # And since struct_type_args comes from the instantiated type (e.g., Mixed<T, U>),
                # these are already the function's type params
                if field_type_arg in func_type_params:
                    # Generate GenericCallArg for this type param at the sink
                    type_idx = GENERIC_EXTRACTION_SINKS.get(matching_callee, 0)
                    key = (matching_sink_stmt, matching_callee, type_idx)
                    if key not in existing_generic_args:
                        derived.append(
                            Fact(
                                "GenericCallArg",
                                (func_name, matching_sink_stmt, matching_callee, type_idx, field_type_arg),
                            )
                        )
                        existing_generic_args.add(key)
                        debug(
                            f"  GenericCallArg({func_name}, {matching_sink_stmt}, {matching_callee}, {type_idx}, {field_type_arg}) [inferred from field]"
                        )

    # Strategy 2: Infer from parameter types passed to extraction sinks
    # When a parameter with generic type (e.g., balance: &mut Balance<T>) is passed to sink
    for stmt_id, callee in sink_calls.items():
        type_idx = GENERIC_EXTRACTION_SINKS.get(callee, 0)
        key = (stmt_id, callee, type_idx)
        if key in existing_generic_args:
            continue  # Already have a GenericCallArg for this

        # Get the first argument to this sink call
        arg_vars = call_args.get((stmt_id, callee, 0), [])
        for arg_var in arg_vars:
            # Check if this var is a parameter with generic type
            if arg_var in param_types:
                param_type = param_types[arg_var]
                # Parse param type to get type args: "&mut Balance<T>" -> ["T"]
                _, param_type_args = _parse_generic_type(param_type)
                if param_type_args:
                    for type_arg in param_type_args:
                        if type_arg in func_type_params:
                            derived.append(Fact("GenericCallArg", (func_name, stmt_id, callee, type_idx, type_arg)))
                            existing_generic_args.add(key)
                            debug(
                                f"  GenericCallArg({func_name}, {stmt_id}, {callee}, {type_idx}, {type_arg}) [inferred from param]"
                            )
                            break  # Only need one type arg per sink call

    # Strategy 3: Infer for ALL generic function calls (not just sinks)
    # This enables IPA propagation when caller calls a generic function
    # Build index of callee generic params: callee_name -> {type_param_name -> idx}
    callee_type_params: Dict[str, Dict[str, int]] = {}
    for fact in facts:
        if fact.name == "HasGenericParam":
            callee_name, param_idx, type_var = fact.args
            if callee_name != func_name:  # Only for callees, not the current function
                if callee_name not in callee_type_params:
                    callee_type_params[callee_name] = {}
                callee_type_params[callee_name][type_var] = param_idx

    # Find all calls from this function
    # Calls(caller, callee)
    for fact in facts:
        if fact.name == "Calls" and fact.args[0] == func_name:
            callee = fact.args[1]
            if callee not in callee_type_params:
                continue  # Callee has no generic params

            # Find CallArg facts for this call
            for (stmt_id, call_callee, arg_idx), arg_vars in call_args.items():
                if call_callee != callee:
                    continue

                # Check if any argument's type contains a type param that matches callee's
                for arg_var in arg_vars:
                    if arg_var in param_types:
                        param_type = param_types[arg_var]
                        _, param_type_args = _parse_generic_type(param_type)
                        if param_type_args:
                            for type_arg in param_type_args:
                                if type_arg in func_type_params and type_arg in callee_type_params[callee]:
                                    callee_type_idx = callee_type_params[callee][type_arg]
                                    key = (stmt_id, callee, callee_type_idx)
                                    if key not in existing_generic_args:
                                        derived.append(
                                            Fact(
                                                "GenericCallArg",
                                                (func_name, stmt_id, callee, callee_type_idx, type_arg),
                                            )
                                        )
                                        existing_generic_args.add(key)
                                        debug(
                                            f"  GenericCallArg({func_name}, {stmt_id}, {callee}, {callee_type_idx}, {type_arg}) [inferred for IPA]"
                                        )

    return derived


def _get_func_type_params(func_name: str, facts: List[Fact]) -> Set[str]:
    """Get type parameters for a function from HasGenericParam facts."""
    type_params: Set[str] = set()
    for fact in facts:
        if fact.name == "HasGenericParam" and fact.args[0] == func_name:
            type_params.add(fact.args[2])
    return type_params


def _call_result_used_in_assertion(func_name: str, stmt_id: str, facts: List[Fact]) -> bool:
    """
    Check if type_name::get result is used in an assertion (actual validation).

    Returns True ONLY if the call's result flows to an assertion context:
    1. Same stmt has ConditionCheck (inline assert with get inside)
    2. Result variable appears in ConditionCheck vars
    3. Chained into_string result appears in ConditionCheck

    Returns False for logging/event emission usage.
    """
    # Collect all ConditionCheck vars for this function
    condition_stmts: Set[str] = set()
    condition_vars: Set[str] = set()
    for fact in facts:
        if fact.name == "ConditionCheck" and fact.args[0] == func_name:
            condition_stmts.add(fact.args[1])
            if len(fact.args) > 2 and fact.args[2]:
                condition_vars.update(fact.args[2])

    if not condition_stmts:
        # No assertions in this function at all
        return False

    # Strategy 1: Check if this stmt_id has a ConditionCheck (inline assert)
    if stmt_id in condition_stmts:
        return True

    # Strategy 2: Get result variable and check if in condition vars
    result_var = None
    for fact in facts:
        if fact.name == "CallResult" and fact.args[0] == func_name and fact.args[1] == stmt_id:
            result_var = fact.args[2]
            break

    if result_var and result_var in condition_vars:
        return True

    # Strategy 3: Check if any into_string result (that could wrap our get call) is in condition
    # Track into_string calls that use our result or appear near our call
    for fact in facts:
        if fact.name == "CallResult" and fact.args[0] == func_name:
            _, _, call_result, callee = fact.args
            if ("into_string" in callee or callee.endswith("into_string")) and call_result in condition_vars:
                return True

    return False


def _is_extraction_sink(callee: str) -> bool:
    """Check if callee is an extraction sink (handles FQN vs simple name)."""
    for sink_fqn in GENERIC_EXTRACTION_SINKS:
        if names_match(callee, sink_fqn):
            return True
    return False


def _detect_direct_extraction_returned(
    func_name: str,
    facts: List[Fact],
    func_type_params: Set[str],
    extraction_result_vars: Set[str],
    transferred_vars: Set[str],
    returns_asset: bool,
) -> List[Fact]:
    """
    Detect direct extractions where result is returned (not transferred).

    Pattern: coin::take() result is NOT transferred to any sink.
    """
    derived: List[Fact] = []

    # Get type params that reach extraction sinks
    type_params_at_extraction: Set[str] = set()
    for fact in facts:
        if fact.name == "GenericCallArg" and fact.args[0] == func_name:
            _, _, callee, _, type_var = fact.args
            if _is_extraction_sink(callee) and type_var in func_type_params:
                type_params_at_extraction.add(type_var)

    for type_var in type_params_at_extraction:
        any_transferred = any(var in transferred_vars for var in extraction_result_vars)
        if not any_transferred and (returns_asset or not transferred_vars):
            derived.append(Fact("ExtractedValueReturned", (func_name, type_var)))
            debug(f"  ExtractedValueReturned({func_name}, {type_var})")

    return derived


def _detect_ipa_wrapper_extraction_returned(
    func_name: str,
    func_type_params: Set[str],
    transferred_vars: Set[str],
    returns_asset: bool,
    return_type: str,
    already_derived: List[Fact],
) -> List[Fact]:
    """
    Detect IPA wrapper functions where extraction result is returned.

    Pattern: Function returns Coin/Balance and has no transfer sinks.
    This handles utility wrappers that call extraction helpers and return result.
    """
    derived: List[Fact] = []

    if not returns_asset or transferred_vars:
        return derived

    already_returned = {f.args[1] for f in already_derived if f.name == "ExtractedValueReturned"}

    for type_var in func_type_params:
        if type_var in return_type and type_var not in already_returned:
            derived.append(Fact("ExtractedValueReturned", (func_name, type_var)))
            debug(f"  ExtractedValueReturned({func_name}, {type_var}) [IPA wrapper]")

    return derived


def detect_extracted_value_returned(func_name: str, facts: List[Fact]) -> List[Fact]:
    """
    Detect when extracted value is returned (not transferred to a sink).

    Two strategies:
    1. Direct extraction: coin::take() result flows to return, not to transfer sink
    2. IPA wrapper: Function returns Coin/Balance with no transfer sinks (calls helper)

    Safe utility pattern:
        public fun extract<T>(balance: &mut Balance<T>): Coin<T> {
            coin::take(balance, amount, ctx)  // returned, not transferred
        }

    Args:
        func_name: Function to analyze
        facts: All facts

    Returns:
        List of ExtractedValueReturned facts for type params whose extraction is returned
    """
    func_type_params = _get_func_type_params(func_name, facts)
    if not func_type_params:
        return []

    # Get extraction sink stmt_ids from AmountExtractionSink facts
    extraction_stmt_ids: Set[str] = set()
    for fact in facts:
        if fact.name == "AmountExtractionSink" and fact.args[0] == func_name:
            extraction_stmt_ids.add(fact.args[1])

    # Get result variables from extraction calls
    extraction_result_vars: Set[str] = set()
    for fact in facts:
        if fact.name == "CallResult" and fact.args[0] == func_name:
            _, stmt_id, result_var, _ = fact.args
            if stmt_id in extraction_stmt_ids:
                extraction_result_vars.add(result_var)

    # Get variables that are transferred
    transferred_vars: Set[str] = set()
    for fact in facts:
        if fact.name == "SinkUsesVar" and fact.args[0] == func_name:
            _, _, var, role = fact.args
            if role == "transfer_value":
                transferred_vars.add(var)

    # Check return type
    returns_asset = False
    return_type = ""
    for fact in facts:
        if fact.name == "FunReturnType" and fact.args[0] == func_name:
            return_type = fact.args[1]
            if "Coin<" in return_type or "Balance<" in return_type:
                returns_asset = True
                break

    # Strategy 1: Direct extraction returned
    derived = _detect_direct_extraction_returned(
        func_name, facts, func_type_params, extraction_result_vars, transferred_vars, returns_asset
    )

    # Strategy 2: IPA wrapper pattern
    derived.extend(
        _detect_ipa_wrapper_extraction_returned(
            func_name, func_type_params, transferred_vars, returns_asset, return_type, derived
        )
    )

    return derived


def detect_phantom_type_bindings(
    func_name: str,
    facts: List[Fact],
    global_phantom_types: Optional[Dict[str, Dict[int, str]]] = None,
) -> List[Fact]:
    """
    Detect when function's type parameters are bound by phantom types in struct parameters.

    Pattern: mint<P>(self: &mut LiquidStakingInfo<P>, ...) where LiquidStakingInfo<phantom P>

    Args:
        func_name: Function to analyze
        facts: All facts
        global_phantom_types: Optional global index of phantom types from all files.
            If provided, used for cross-file phantom type detection.

    Returns:
        List of TypeBoundByPhantom facts
    """
    derived: List[Fact] = []

    # Get function's type parameters
    func_type_params: Dict[str, int] = {}  # type_var -> param_idx
    for fact in facts:
        if fact.name == "HasGenericParam" and fact.args[0] == func_name:
            _, idx, type_var = fact.args
            func_type_params[type_var] = idx

    if not func_type_params:
        return derived  # No generic params

    # Get all phantom type params across all structs: struct_name -> {param_idx -> type_var}
    # First from local facts, then merge with global if provided
    struct_phantoms: Dict[str, Dict[int, str]] = {}
    for fact in facts:
        if fact.name == "StructPhantomTypeParam":
            struct_name, param_idx, type_var = fact.args
            if struct_name not in struct_phantoms:
                struct_phantoms[struct_name] = {}
            struct_phantoms[struct_name][param_idx] = type_var

    # Merge global phantom types (for cross-file detection)
    if global_phantom_types:
        for struct_name, params in global_phantom_types.items():
            if struct_name not in struct_phantoms:
                struct_phantoms[struct_name] = params
            else:
                struct_phantoms[struct_name].update(params)

    if not struct_phantoms:
        return derived  # No phantom types defined

    # Check each function parameter
    for fact in facts:
        if fact.name != "FormalArg" or fact.args[0] != func_name:
            continue

        _, param_idx, param_name, param_type = fact.args
        struct_name, type_args = _parse_generic_type(param_type)

        if not struct_name:
            continue

        # Find matching struct (handle FQN vs simple name)
        matched_struct = None
        for registered_struct in struct_phantoms.keys():
            if names_match(struct_name, registered_struct):
                matched_struct = registered_struct
                break

        if not matched_struct:
            continue

        # Check each type argument position
        for type_arg_idx, type_arg in enumerate(type_args):
            # Check if this type arg is one of function's type params
            if type_arg in func_type_params:
                # Check if this position is phantom in the struct
                if type_arg_idx in struct_phantoms[matched_struct]:
                    derived.append(Fact("TypeBoundByPhantom", (func_name, type_arg, matched_struct, param_name)))
                    debug(f"  TypeBoundByPhantom({func_name}, {type_arg}, {matched_struct}, {param_name})")

    return derived


def propagate_generic_validation(func_name: str, facts: List[Fact]) -> GenericTypeState:
    """
    Intraprocedural generic type validation analysis.

    Tracks:
    1. Which type params are validated by type_name::get<T>() calls
    2. Which type params are bound by phantom types (ownership-constrained)
    3. Which type params reach generic sinks

    Returns:
        GenericTypeState with validated types and type-to-sink mappings
    """
    state = GenericTypeState()

    # Collect HasGenericParam facts for this function
    func_type_params: Set[str] = set()
    for fact in facts:
        if fact.name == "HasGenericParam" and fact.args[0] == func_name:
            type_var = fact.args[2]
            func_type_params.add(type_var)

    if not func_type_params:
        return state  # No generic params

    # Phase 1: Detect type_name::get<T>() calls (direct validation)
    # Note: TypeBoundByPhantom is NOT treated as validation here - it's a separate
    # concept that rules can check directly. Phantom binding doesn't prevent
    # type confusion in shared objects.
    #
    # Track both assertion-validated and all type_name::get<T> calls separately.
    # Pure validator functions (no sinks) get marked even without assertions.
    type_name_get_calls: Set[str] = set()  # Type vars that have type_name::get<T> calls

    for fact in facts:
        if fact.name != "GenericCallArg" or fact.args[0] != func_name:
            continue

        _, stmt_id, callee, type_arg_idx, type_var = fact.args

        # Check if this is a type_name::get call (FQN-only, no name heuristics)
        if callee in TYPE_NAME_GET_CALLEES and type_var in func_type_params:
            type_name_get_calls.add(type_var)

            # Only mark as validated if result is used in assertion
            # (For functions WITH sinks, assertion usage is required)
            if _call_result_used_in_assertion(func_name, stmt_id, facts):
                state.validated_types.add(type_var)
                add_fact(facts, "TypeValidated", (func_name, type_var, stmt_id))
                debug(f"  TypeValidated({func_name}, {type_var}) at {stmt_id} - result in assertion")
            else:
                debug(f"  type_name::get<{type_var}>() at {stmt_id} - not in assertion (pure validator candidate)")

    # Phase 2: Track type params reaching sinks
    for fact in facts:
        if fact.name != "GenericCallArg" or fact.args[0] != func_name:
            continue

        _, stmt_id, callee, type_arg_idx, type_var = fact.args

        # Check if this callee is a sink and the type_arg_idx matches
        if callee in GENERIC_EXTRACTION_SINKS:
            expected_type_idx = GENERIC_EXTRACTION_SINKS[callee]
            if type_arg_idx == expected_type_idx and type_var in func_type_params:
                # This type param reaches a sink
                if type_var not in state.type_to_sinks:
                    state.type_to_sinks[type_var] = []
                state.type_to_sinks[type_var].append((stmt_id, callee))

    # Phase 3: Identify pure validator functions
    # Functions that call type_name::get<T>() but don't have extraction sinks for T
    # These are helper functions whose validation should propagate to callers via IPA
    #
    # For pure functions (no sinks), type_name::get<T> concretizes T - callers can
    # use the returned type info for validation. This is the Aftermath pattern:
    #   type_to_string<T>() -> returns type info
    #   type_to_index<L,C>(pool) -> uses type_to_string<C> for whitelist lookup
    for type_var in type_name_get_calls:
        if type_var not in state.type_to_sinks:
            # This type_var has type_name::get<T>() but no extraction sinks
            # Mark this function as a pure validator for T
            add_fact(facts, "FunctionValidatesType", (func_name, type_var))
            debug(f"  FunctionValidatesType({func_name}, {type_var}) - validates without sinks")

    return state


def compute_generic_summary(func_name: str, facts: List[Fact]) -> GenericTypeSummary:
    """
    Compute generic type summary for a function.

    This captures which type params are validated (intraprocedurally or via IPA)
    and which reach sinks.
    """
    summary = GenericTypeSummary(func_name=func_name)

    # Run intraprocedural analysis
    state = propagate_generic_validation(func_name, facts)

    # Also collect type vars validated via IPA (existing TypeValidated facts)
    ipa_validated: Set[str] = set()
    for fact in facts:
        if fact.name == "TypeValidated" and fact.args[0] == func_name:
            ipa_validated.add(fact.args[1])

    # Collect all type params for this function
    for fact in facts:
        if fact.name == "HasGenericParam" and fact.args[0] == func_name:
            type_var = fact.args[2]
            # Validated if either intraprocedural or IPA
            summary.type_param_validated[type_var] = type_var in state.validated_types or type_var in ipa_validated
            if type_var in state.type_to_sinks:
                summary.type_param_to_sinks[type_var] = {callee for _, callee in state.type_to_sinks[type_var]}

    # Include transitive sinks from UnvalidatedTypeAtSink facts (from IPA propagation)
    # This enables multi-hop propagation: A→B→C where C has the sink
    for fact in facts:
        if fact.name == "UnvalidatedTypeAtSink" and fact.args[0] == func_name:
            _, type_var, _, sink_callee = fact.args
            if type_var not in summary.type_param_to_sinks:
                summary.type_param_to_sinks[type_var] = set()
            summary.type_param_to_sinks[type_var].add(sink_callee)

    # Capture pure validator functions (validate T but no sinks)
    # These should propagate validation to callers via IPA
    for fact in facts:
        if fact.name == "FunctionValidatesType" and fact.args[0] == func_name:
            summary.functions_validates.add(fact.args[1])

    return summary


def apply_generic_summaries(
    func_name: str,
    facts: List[Fact],
    summaries: Dict[str, GenericTypeSummary],
    global_type_params: Dict[str, Dict[int, str]],
) -> List[Fact]:
    """
    Apply callee summaries to propagate validation through call sites.

    Strategy:
    1. For each call with type arguments
    2. Map caller's type param to callee's type param position
    3. If callee summary says that type param reaches sinks, propagate to caller
    4. If callee summary says that type param is validated, mark as validated for caller

    Args:
        func_name: Function being analyzed
        facts: Facts for the current file
        summaries: Function summaries (global)
        global_type_params: Global index of HasGenericParam: func_name -> {param_idx -> type_var}

    Returns:
        List of new facts derived from interprocedural analysis
    """
    derived: List[Fact] = []

    # Collect caller's type params
    caller_type_params: Set[str] = set()
    for fact in facts:
        if fact.name == "HasGenericParam" and fact.args[0] == func_name:
            type_var = fact.args[2]
            caller_type_params.add(type_var)

    if not caller_type_params:
        return derived

    # Track which type params are validated (start with direct validations)
    caller_validated: Set[str] = set()
    for fact in facts:
        if fact.name == "TypeValidated" and fact.args[0] == func_name:
            type_var = fact.args[1]
            caller_validated.add(type_var)

    # Process each call site
    for fact in facts:
        if fact.name != "GenericCallArg" or fact.args[0] != func_name:
            continue

        _, stmt_id, callee, type_arg_idx, type_var = fact.args

        # Check if callee has a summary
        if callee not in summaries:
            continue

        callee_summary = summaries[callee]

        # Get callee's type params from global index (cross-module aware)
        callee_type_params_by_idx = global_type_params.get(callee, {})

        # Get callee's type param for this position
        callee_type_var = callee_type_params_by_idx.get(type_arg_idx)
        if not callee_type_var:
            continue

        # Check if this type param is our caller's type param
        if type_var not in caller_type_params:
            continue

        # Propagate validation: if callee validates this type param, caller's type param is safe
        # This includes both regular validation (with sinks) and pure validators (no sinks)
        callee_validates = (
            callee_summary.type_param_validated.get(callee_type_var, False)
            or callee_type_var in callee_summary.functions_validates
        )
        if callee_validates:
            if type_var not in caller_validated:
                caller_validated.add(type_var)
                # Generate TypeValidated fact (IPA)
                derived.append(Fact("TypeValidated", (func_name, type_var, f"{stmt_id}_via_{callee}")))
                debug(f"  TypeValidated({func_name}, {type_var}) via call to {callee}")

        # Propagate sinks: if callee's type param reaches sinks, caller's type param does too
        if callee_type_var in callee_summary.type_param_to_sinks:
            for sink_callee in callee_summary.type_param_to_sinks[callee_type_var]:
                # Check if type param is validated
                is_validated = type_var in caller_validated
                if is_validated:
                    derived.append(
                        Fact("ValidatedTypeAtSink", (func_name, type_var, f"{stmt_id}_via_{callee}", sink_callee))
                    )
                else:
                    derived.append(
                        Fact("UnvalidatedTypeAtSink", (func_name, type_var, f"{stmt_id}_via_{callee}", sink_callee))
                    )

    return derived


def _propagate_extraction_context_to_callees(ctx: ProjectContext) -> None:
    """
    Propagate extraction context DOWN to callees (reverse IPA).

    When a function F has extraction sinks for type T, and F calls callee V with T,
    V gets "validation responsibility" for T even if V doesn't have extraction itself.

    This enables detection of validation helpers like:
        public fun validate_withdraw<CoinType>(...) { /* no type_name::get */ }
    which are called from extraction contexts but don't validate the type.

    Algorithm:
    1. Collect all functions with UnvalidatedTypeAtSink facts (have extraction)
    2. For each such function F with type T:
       - Find callees V that F calls with type T (via GenericCallArg)
       - Map caller's type param to callee's type param by position
       - For V that doesn't have extraction sinks, generate TypeReachesExtractionInCallers(V, callee_T, F)
    """
    # Collect functions with extraction and their type params
    # func_name -> {type_var}
    funcs_with_extraction: Dict[str, Set[str]] = {}

    for file_ctx in ctx.source_files.values():
        if file_ctx.is_test_only:
            continue
        for fact in file_ctx.facts:
            if fact.name in ("UnvalidatedTypeAtSink", "ValidatedTypeAtSink", "ExtractedValueReturned"):
                func_name, type_var = fact.args[0], fact.args[1]
                if func_name not in funcs_with_extraction:
                    funcs_with_extraction[func_name] = set()
                funcs_with_extraction[func_name].add(type_var)

    if not funcs_with_extraction:
        return

    debug(f"Reverse IPA: {len(funcs_with_extraction)} functions with extraction sinks")

    # Build callee type param map: func -> {type_idx -> type_var}
    # This allows mapping caller's type args to callee's type params by position
    callee_type_params: Dict[str, Dict[int, str]] = {}
    for file_ctx in ctx.source_files.values():
        if file_ctx.is_test_only:
            continue
        for fact in file_ctx.facts:
            if fact.name == "HasGenericParam":
                func_name, param_idx, type_var = fact.args
                if func_name not in callee_type_params:
                    callee_type_params[func_name] = {}
                callee_type_params[func_name][param_idx] = type_var

    # Collect GenericCallArg facts: caller -> [(callee, type_idx, caller_type_var)]
    # GenericCallArg(caller, stmt_id, callee, type_idx, type_var)
    # type_idx is the position in callee's type params, type_var is caller's type param
    caller_to_callees: Dict[str, List[Tuple[str, int, str]]] = {}

    for file_ctx in ctx.source_files.values():
        if file_ctx.is_test_only:
            continue
        for fact in file_ctx.facts:
            if fact.name == "GenericCallArg":
                caller, _, callee, type_idx, caller_type_var = fact.args
                if caller not in caller_to_callees:
                    caller_to_callees[caller] = []
                caller_to_callees[caller].append((callee, type_idx, caller_type_var))

    # Build func_file map for efficient lookup
    func_to_file: Dict[str, str] = {}
    for file_path, file_ctx in ctx.source_files.items():
        if file_ctx.is_test_only:
            continue
        for fact in file_ctx.facts:
            if fact.name == "Fun":
                func_to_file[fact.args[0]] = file_path

    # Fixed-point iteration: propagate transitively through call chain
    # Functions with TypeReachesExtractionInCallers also propagate to their callees
    all_generated: Set[Tuple[str, str, str]] = set()  # (callee, type_var, origin)
    sources: Dict[str, Set[str]] = dict(funcs_with_extraction)  # func -> {type_vars}
    iteration = 0
    max_iterations = 10

    while iteration < max_iterations:
        iteration += 1
        new_in_iteration = 0

        for source_func, source_types in list(sources.items()):
            callees = caller_to_callees.get(source_func, [])

            for callee, type_idx, caller_type_var in callees:
                # Only propagate for types that reach extraction
                if caller_type_var not in source_types:
                    continue

                # Map caller's type var to callee's type var by position
                callee_type_var = callee_type_params.get(callee, {}).get(type_idx)
                if not callee_type_var:
                    continue

                # Skip if callee has its own extraction sinks (already flagged by forward IPA)
                if callee in funcs_with_extraction and callee_type_var in funcs_with_extraction[callee]:
                    continue

                # Skip stdlib functions (use structural check, not name heuristic)
                if is_stdlib_type(callee):
                    continue

                # Skip if already generated
                fact_key = (callee, callee_type_var, source_func)
                if fact_key in all_generated:
                    continue

                # Find file for callee
                callee_file = func_to_file.get(callee)
                if not callee_file:
                    continue

                all_generated.add(fact_key)
                new_in_iteration += 1

                # Add to sources for next iteration (transitive propagation)
                if callee not in sources:
                    sources[callee] = set()
                sources[callee].add(callee_type_var)

                # Generate fact
                new_fact = Fact("TypeReachesExtractionInCallers", (callee, callee_type_var, source_func))
                ctx.source_files[callee_file].facts.append(new_fact)
                debug(f"  [{iteration}] TypeReachesExtractionInCallers({callee}, {callee_type_var}, {source_func})")

        if new_in_iteration == 0:
            break

    if all_generated:
        debug(
            f"Reverse IPA: Generated {len(all_generated)} TypeReachesExtractionInCallers facts in {iteration} iterations"
        )


def generate_generic_type_facts(ctx: ProjectContext) -> None:
    """
    Main entry point for generic type validation analysis.

    Runs in multiple passes:
    1. Intraprocedural: Direct validation detection
    2. Compute summaries for all functions
    3. Fixed-point interprocedural propagation
    4. Generate final UnvalidatedTypeAtSink / ValidatedTypeAtSink facts
    """
    debug("Running generic type validation analysis (taint-style)...")

    # Build global index of HasGenericParam: func_name -> {param_idx -> type_var}
    # This enables cross-module type param lookups
    global_type_params: Dict[str, Dict[int, str]] = {}
    for file_ctx in ctx.source_files.values():
        if file_ctx.is_test_only:
            continue
        for fact in file_ctx.facts:
            if fact.name == "HasGenericParam":
                func_name, param_idx, type_var = fact.args
                if func_name not in global_type_params:
                    global_type_params[func_name] = {}
                global_type_params[func_name][param_idx] = type_var

    # Build global index of StructPhantomTypeParam for cross-file phantom type detection
    # This enables detecting phantom binding when Pool<phantom L> is in a different file
    global_phantom_types: Dict[str, Dict[int, str]] = {}  # struct_name -> {param_idx -> type_var}
    for file_ctx in ctx.source_files.values():
        if file_ctx.is_test_only:
            continue
        for fact in file_ctx.facts:
            if fact.name == "StructPhantomTypeParam":
                struct_name, param_idx, type_var = fact.args
                if struct_name not in global_phantom_types:
                    global_phantom_types[struct_name] = {}
                global_phantom_types[struct_name][param_idx] = type_var

    # Phase 1: Intraprocedural analysis for all functions
    summaries: Dict[str, GenericTypeSummary] = {}

    for file_ctx in ctx.source_files.values():
        if file_ctx.is_test_only:
            continue

        facts = file_ctx.facts

        # Find all functions with generic params
        funcs_with_generics: Set[str] = set()
        for fact in facts:
            if fact.name == "HasGenericParam":
                funcs_with_generics.add(fact.args[0])

        # Detect phantom type bindings for all functions
        # Pass global phantom types for cross-file detection
        for func_name in funcs_with_generics:
            phantom_facts = detect_phantom_type_bindings(func_name, facts, global_phantom_types)
            facts.extend(phantom_facts)

        # Infer GenericCallArg facts from field accesses in extraction sinks
        # This handles cases where type args are inferred rather than explicit
        for func_name in funcs_with_generics:
            inferred_facts = infer_generic_call_args_from_fields(func_name, facts)
            facts.extend(inferred_facts)

        # Run intraprocedural analysis and compute summaries
        for func_name in funcs_with_generics:
            state = propagate_generic_validation(func_name, facts)
            summary = compute_generic_summary(func_name, facts)
            summaries[func_name] = summary

            # Generate initial facts for direct sinks
            for type_var, sink_list in state.type_to_sinks.items():
                is_validated = type_var in state.validated_types
                for stmt_id, sink_callee in sink_list:
                    if is_validated:
                        add_fact(facts, "ValidatedTypeAtSink", (func_name, type_var, stmt_id, sink_callee))
                    else:
                        add_fact(facts, "UnvalidatedTypeAtSink", (func_name, type_var, stmt_id, sink_callee))

        # Detect utility functions where extraction result is returned (not transferred)
        for func_name in funcs_with_generics:
            return_facts = detect_extracted_value_returned(func_name, facts)
            facts.extend(return_facts)

    # Phase 2: Interprocedural propagation (fixed-point)
    changed = True
    iteration = 0
    max_iterations = 10

    while changed and iteration < max_iterations:
        changed = False
        iteration += 1

        for file_ctx in ctx.source_files.values():
            if file_ctx.is_test_only:
                continue

            facts = file_ctx.facts

            # Find all functions with generic params
            funcs_with_generics: Set[str] = set()
            for fact in facts:
                if fact.name == "HasGenericParam":
                    funcs_with_generics.add(fact.args[0])

            for func_name in funcs_with_generics:
                # Apply summaries at call sites
                new_facts = apply_generic_summaries(func_name, facts, summaries, global_type_params)

                if new_facts:
                    facts.extend(new_facts)
                    changed = True

                    # Recompute summary
                    new_summary = compute_generic_summary(func_name, facts)
                    if (
                        new_summary.type_param_validated != summaries[func_name].type_param_validated
                        or new_summary.type_param_to_sinks != summaries[func_name].type_param_to_sinks
                    ):
                        summaries[func_name] = new_summary
                        changed = True

    if iteration > 0:
        debug(f"Generic type validation propagation converged after {iteration} iterations")

    # Phase 3: Reverse propagation - track validation responsibility
    # For callees that are called from extraction contexts but don't have extraction themselves
    _propagate_extraction_context_to_callees(ctx)

    # Count facts for debugging
    total_validated = sum(
        1 for file_ctx in ctx.source_files.values() for fact in file_ctx.facts if fact.name == "ValidatedTypeAtSink"
    )
    total_unvalidated = sum(
        1 for file_ctx in ctx.source_files.values() for fact in file_ctx.facts if fact.name == "UnvalidatedTypeAtSink"
    )

    if total_validated + total_unvalidated > 0:
        debug(f"Generic type analysis: {total_validated} validated sinks, {total_unvalidated} unvalidated sinks")

    # Update global_facts_index with generic type facts
    # These facts need to be in the global index for rule predicates to access them
    GENERIC_FACT_NAMES = {
        "UnvalidatedTypeAtSink",
        "ValidatedTypeAtSink",
        "TypeValidated",
        "TypeBoundByPhantom",
        "ExtractedValueReturned",
        "TypeReachesExtractionInCallers",
    }

    for file_path, file_ctx in ctx.source_files.items():
        if file_ctx.is_test_only:
            continue

        for fact in file_ctx.facts:
            if fact.name not in GENERIC_FACT_NAMES:
                continue

            # Get function name from first arg
            func_name = fact.args[0]

            # Ensure func_name is in global index
            if func_name not in ctx.global_facts_index:
                ctx.global_facts_index[func_name] = {}
            if file_path not in ctx.global_facts_index[func_name]:
                ctx.global_facts_index[func_name][file_path] = []

            # Add fact to global index if not already present
            if fact not in ctx.global_facts_index[func_name][file_path]:
                ctx.global_facts_index[func_name][file_path].append(fact)
