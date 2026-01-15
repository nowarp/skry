"""
Access control fact generation: sender checks, role checks.

Note: These facts are direct-only (no call graph propagation).
Per-sink guards are tracked via GuardedSink facts instead.
"""

from typing import Dict, Set

from core.context import ProjectContext
from core.facts import Fact
from move.extract import strip_ref_modifiers
from move.types import strip_generics
from core.utils import debug
from move.sui_patterns import (
    SUI_CAPABILITY_RETURNING_FUNCTIONS,
    SUI_STDLIB_CAPABILITIES,
    is_privileged_role_name,
    is_stdlib_sender_call,
    is_stdlib_share_call,
    is_stdlib_transfer_call,
)


def generate_calls_sender_facts(ctx: ProjectContext) -> None:
    """
    Generate CallsSender facts (direct only, no propagation).

    Finds functions that directly call tx_context::sender().
    Note: This does NOT imply authorization - use HasSenderEqualityCheck for that.
    Guards are tracked per-sink via GuardedSink facts.
    """
    direct_sender_funcs: Set[str] = set()

    for source_file in ctx.source_files.values():
        func_calls: dict[str, set[str]] = {}

        for fact in source_file.facts:
            if fact.name == "InFun" and "@" in fact.args[1]:
                func_name = fact.args[0]
                call_id = fact.args[1]
                callee = call_id.split("@")[0]
                if func_name not in func_calls:
                    func_calls[func_name] = set()
                func_calls[func_name].add(callee)

        for func_name, callees in func_calls.items():
            for callee in callees:
                if is_stdlib_sender_call(callee):
                    direct_sender_funcs.add(func_name)
                    break

    # Add direct facts only (no propagation)
    count = 0
    for source_file in ctx.source_files.values():
        for func_name in direct_sender_funcs:
            if any(f.name == "Fun" and f.args[0] == func_name for f in source_file.facts):
                fact = Fact("CallsSender", (func_name,))
                if fact not in source_file.facts:
                    source_file.facts.append(fact)
                    count += 1
                    # Update global index
                    if func_name in ctx.global_facts_index:
                        for facts_list in ctx.global_facts_index[func_name].values():
                            if fact not in facts_list:
                                facts_list.append(fact)

    if count > 0:
        debug(f"Generated {count} CallsSender facts (direct only)")


def _resolve_type_to_fqn(
    param_type: str,
    import_map: Dict[str, str],
    module_path: str | None,
    local_structs: Set[str],
) -> str:
    """
    Resolve a parameter type to its fully-qualified name.

    Resolution order:
    1. Already fully qualified -> return as-is
    2. In import_map -> return imported path
    3. Matches a local struct -> qualify with module_path
    4. Fallback -> return as-is (unresolved)
    """
    clean_type = strip_generics(strip_ref_modifiers(param_type))

    # Already qualified
    if "::" in clean_type:
        # Could be partially qualified (e.g., "typus_nft::ManagerCap")
        # Check if first part is an import alias
        parts = clean_type.split("::")
        if parts[0] in import_map:
            return import_map[parts[0]] + "::" + "::".join(parts[1:])
        return clean_type

    # Check import map
    if clean_type in import_map:
        return import_map[clean_type]

    # Check if it's a local struct
    if module_path:
        fqn = f"{module_path}::{clean_type}"
        if fqn in local_structs:
            return fqn

    # Unresolved - return as-is
    return clean_type


def generate_checks_role_facts(ctx: ProjectContext) -> None:
    """
    Generate ChecksCapability facts (direct only, no propagation).

    Finds functions that have a role/capability parameter.
    Guards are tracked per-sink via GuardedSink facts.

    Uses module-aware type resolution to avoid false matches between
    same-named types in different modules (e.g., module_a::ManagerCap vs module_b::ManagerCap).
    """
    # Collect all role types (fully qualified)
    role_types: Set[str] = set()
    for source_file in ctx.source_files.values():
        for fact in source_file.facts:
            if fact.name == "IsCapability":
                role_types.add(fact.args[0])

    # Add Sui stdlib capabilities (external types not parsed from project sources)
    role_types.update(SUI_STDLIB_CAPABILITIES)

    if not role_types:
        debug("No roles found, skipping ChecksCapability generation")
        return
    debug(f"Found {len(role_types)} role types: {role_types}")

    # Collect all struct names for local resolution
    all_structs: Set[str] = set()
    for source_file in ctx.source_files.values():
        for fact in source_file.facts:
            if fact.name == "Struct":
                all_structs.add(fact.args[0])

    # Find direct role checks (functions with role parameter)
    direct_role_checks: Dict[str, Set[str]] = {}

    for source_file in ctx.source_files.values():
        import_map = source_file.import_map
        module_path = source_file.module_path

        for fact in source_file.facts:
            if fact.name == "FormalArg":
                func_name = fact.args[0]
                param_type = fact.args[3]

                # Resolve param type to fully-qualified name
                resolved_type = _resolve_type_to_fqn(param_type, import_map, module_path, all_structs)

                if resolved_type in role_types:
                    # Validate module ownership: role must be from same module, explicitly imported,
                    # or explicitly referenced with FQN in the source code.
                    # This prevents accidental FQN collisions (same simple name in different modules)
                    # while allowing intentional cross-module references.
                    func_module = func_name.rsplit("::", 1)[0] if "::" in func_name else None
                    role_module = resolved_type.rsplit("::", 1)[0] if "::" in resolved_type else None
                    role_simple_name = resolved_type.rsplit("::", 1)[1] if "::" in resolved_type else resolved_type

                    is_same_module = func_module == role_module

                    # Check if imported: either the type itself, its simple name, or its module is imported
                    is_imported = (
                        role_simple_name in import_map  # Simple name in import map
                        or resolved_type in import_map.values()  # FQN in import map values
                        or role_module in import_map.values()  # Module FQN in import map values
                    )

                    if not (is_same_module or is_imported):
                        debug(
                            f"  Skipping ChecksCapability for {func_name} with {resolved_type} (role from different module, not imported)"
                        )
                        continue

                    if func_name not in direct_role_checks:
                        direct_role_checks[func_name] = set()
                    direct_role_checks[func_name].add(resolved_type)

    debug(f"Found {len(direct_role_checks)} functions with direct role checks")

    # Generate IsCapability facts for stdlib capabilities that are actually used
    stdlib_caps_used: Set[str] = set()
    for role_types_set in direct_role_checks.values():
        for role_type in role_types_set:
            if role_type in SUI_STDLIB_CAPABILITIES:
                stdlib_caps_used.add(role_type)

    # Add IsCapability facts for used stdlib capabilities (to any source file)
    if stdlib_caps_used and ctx.source_files:
        first_file = next(iter(ctx.source_files.values()))
        for stdlib_cap in stdlib_caps_used:
            cap_fact = Fact("IsCapability", (stdlib_cap,))
            if cap_fact not in first_file.facts:
                first_file.facts.append(cap_fact)
                debug(f"  Added IsCapability for stdlib: {stdlib_cap}")

    # Add direct facts only (no propagation)
    count = 0
    for source_file in ctx.source_files.values():
        for func_name, role_types_for_func in direct_role_checks.items():
            # Check if function exists in this file
            if not any(f.name == "Fun" and f.args[0] == func_name for f in source_file.facts):
                continue

            for role_type in role_types_for_func:
                checks_role_fact = Fact("ChecksCapability", (role_type, func_name))

                # Skip if already exists
                if any(f.name == "ChecksCapability" and f.args == (role_type, func_name) for f in source_file.facts):
                    continue

                source_file.facts.append(checks_role_fact)
                count += 1

                # Also add to global_facts_index
                if func_name in ctx.global_facts_index:
                    for file_path, func_facts in ctx.global_facts_index[func_name].items():
                        if not any(
                            f.name == "ChecksCapability" and f.args == (role_type, func_name) for f in func_facts
                        ):
                            func_facts.append(checks_role_fact)

    if count > 0:
        debug(f"Generated {count} ChecksCapability facts (direct only)")


def generate_transfer_and_share_facts(ctx: "ProjectContext") -> None:
    """
    Generate TransfersToSender and SharesObject facts with value flow tracking.

    Uses PacksToVar facts to track which variable holds which struct type,
    then matches InFun + ActualArg facts to determine which struct is transferred/shared.

    This correctly handles init functions that pack multiple structs and
    transfer one while sharing another.
    """
    transfer_count = 0
    share_count = 0

    for source_file in ctx.source_files.values():
        if source_file.is_test_only:
            continue

        # Step 1: Build var -> struct_type mapping per function from PacksToVar facts
        func_var_types: Dict[str, Dict[str, str]] = {}
        for fact in source_file.facts:
            if fact.name == "PacksToVar":
                func_name, var_name, struct_type = fact.args
                if func_name not in func_var_types:
                    func_var_types[func_name] = {}
                func_var_types[func_name][var_name] = struct_type

        # Also track parameter types from FormalArg facts
        for fact in source_file.facts:
            if fact.name == "FormalArg":
                func_name, _idx, param_name, param_type = fact.args
                base_type = strip_ref_modifiers(param_type)
                base_type = strip_generics(base_type)
                if func_name not in func_var_types:
                    func_var_types[func_name] = {}
                func_var_types[func_name][param_name] = base_type

        # Step 2: Build call_id -> first arg mapping from ActualArg facts
        call_first_arg: Dict[str, str] = {}
        for fact in source_file.facts:
            if fact.name == "ActualArg":
                call_id, arg_idx, arg_name = fact.args
                if arg_idx == 0:  # First argument (the object being transferred/shared)
                    call_first_arg[call_id] = arg_name

        # Step 3: Check if each function has a sender call (for TransfersToSender)
        func_has_sender: Set[str] = set()
        for fact in source_file.facts:
            if fact.name == "InFun" and "@" in fact.args[1]:
                func_name = fact.args[0]
                callee = fact.args[1].split("@")[0]
                if is_stdlib_sender_call(callee):
                    func_has_sender.add(func_name)

        # Step 4: Find InFun facts for transfer/share calls and match to struct types
        for fact in source_file.facts:
            if fact.name != "InFun" or "@" not in fact.args[1]:
                continue

            func_name = fact.args[0]
            call_id = fact.args[1]
            callee = call_id.split("@")[0]

            is_share_call = is_stdlib_share_call(callee)
            is_transfer_call = is_stdlib_transfer_call(callee)

            if not is_share_call and not is_transfer_call:
                continue

            # Get the first argument (the object being transferred/shared)
            if call_id not in call_first_arg:
                continue
            arg_var = call_first_arg[call_id]

            # Match arg variable to struct type
            if func_name not in func_var_types:
                continue
            var_to_type = func_var_types[func_name]

            if arg_var not in var_to_type:
                continue

            struct_type = var_to_type[arg_var]

            if is_share_call:
                share_fact = Fact("SharesObject", (func_name, struct_type))
                if share_fact not in source_file.facts:
                    source_file.facts.append(share_fact)
                    share_count += 1
                    debug(f"  SharesObject({func_name}, {struct_type}) via var '{arg_var}'")

            elif is_transfer_call and func_name in func_has_sender:
                # TransfersToSender: transfer call + sender call in same function
                transfer_fact = Fact("TransfersToSender", (func_name, struct_type))
                if transfer_fact not in source_file.facts:
                    source_file.facts.append(transfer_fact)
                    transfer_count += 1
                    debug(f"  TransfersToSender({func_name}, {struct_type}) via var '{arg_var}'")

    if transfer_count > 0 or share_count > 0:
        debug(f"Generated {transfer_count} TransfersToSender, {share_count} SharesObject facts")


def generate_stdlib_capability_transfer_facts(ctx: "ProjectContext") -> None:
    """
    Generate TransfersToSender facts for stdlib capability-returning functions.

    Must run AFTER taint analysis (needs CallResult facts).

    Handles cases like:
        let (treasury_cap, metadata) = coin::create_currency<COIN>(...);
        transfer::public_transfer(treasury_cap, tx_context::sender(ctx));
    """
    transfer_count = 0

    for source_file in ctx.source_files.values():
        if source_file.is_test_only:
            continue

        # Step 1: Build var -> cap_type mapping from CallResult + registry
        func_var_types: Dict[str, Dict[str, str]] = {}
        for fact in source_file.facts:
            if fact.name == "CallResult":
                func_name, _stmt_id, var_name, callee = fact.args
                if callee in SUI_CAPABILITY_RETURNING_FUNCTIONS:
                    for _tuple_idx, cap_type in SUI_CAPABILITY_RETURNING_FUNCTIONS[callee]:
                        if func_name not in func_var_types:
                            func_var_types[func_name] = {}
                        func_var_types[func_name][var_name] = cap_type

        if not func_var_types:
            continue

        # Step 2: Build call_id -> first arg mapping
        call_first_arg: Dict[str, str] = {}
        for fact in source_file.facts:
            if fact.name == "ActualArg":
                call_id, arg_idx, arg_name = fact.args
                if arg_idx == 0:
                    call_first_arg[call_id] = arg_name

        # Step 3: Check for sender calls per function
        func_has_sender: Set[str] = set()
        for fact in source_file.facts:
            if fact.name == "InFun" and "@" in fact.args[1]:
                func_name = fact.args[0]
                callee = fact.args[1].split("@")[0]
                if is_stdlib_sender_call(callee):
                    func_has_sender.add(func_name)

        # Step 4: Find transfer calls and match to stdlib capability types
        for fact in source_file.facts:
            if fact.name != "InFun" or "@" not in fact.args[1]:
                continue

            func_name = fact.args[0]
            call_id = fact.args[1]
            callee = call_id.split("@")[0]

            if not is_stdlib_transfer_call(callee):
                continue

            if call_id not in call_first_arg:
                continue
            arg_var = call_first_arg[call_id]

            if func_name not in func_var_types:
                continue
            if arg_var not in func_var_types[func_name]:
                continue

            cap_type = func_var_types[func_name][arg_var]

            if func_name in func_has_sender:
                transfer_fact = Fact("TransfersToSender", (func_name, cap_type))
                if transfer_fact not in source_file.facts:
                    source_file.facts.append(transfer_fact)
                    transfer_count += 1
                    debug(f"  TransfersToSender({func_name}, {cap_type}) via stdlib return var '{arg_var}'")

    if transfer_count > 0:
        debug(f"Generated {transfer_count} stdlib capability TransfersToSender facts")


def generate_is_capability_facts(ctx: "ProjectContext") -> None:
    """
    Generate IsCapability and IsPrivileged facts for privileged capability structs.
    """
    count = 0

    # Collect all single-UID structs with privileged capability names across all files
    single_uid_privileged_structs: Set[str] = set()
    for source_file in ctx.source_files.values():
        for fact in source_file.facts:
            if fact.name == "Struct":
                struct_name = fact.args[0]
                # First check: name must match privileged role pattern
                if not is_privileged_role_name(struct_name):
                    continue
                # Second check: must be single-UID struct
                fields = [f for f in source_file.facts if f.name == "StructField" and f.args[0] == struct_name]
                if len(fields) == 1:
                    field_type = fields[0].args[3]
                    if field_type == "UID" or field_type.endswith("::UID"):
                        single_uid_privileged_structs.add(struct_name)

    debug(f"Found {len(single_uid_privileged_structs)} single-UID privileged-named structs")

    # For each single-UID privileged struct, check if it's created in init and transferred to sender
    for struct_name in single_uid_privileged_structs:
        # Find the module for this struct
        struct_module = struct_name.rsplit("::", 1)[0] if "::" in struct_name else None
        if not struct_module:
            debug(f"  {struct_name}: skipped (no module path)")
            continue

        init_func = f"{struct_module}::init"

        # Check if struct is created in init (or transitive callees)
        created_in_init = _is_created_in_init(ctx, struct_name, init_func)
        if not created_in_init:
            debug(f"  {struct_name}: not created in init")
            continue

        # Check if transferred to sender
        # First try value-flow-aware TransfersToSender fact (precise)
        transferred_to_sender = _has_transfers_to_sender_fact(ctx, struct_name, init_func)

        # If no precise fact, fall back to transitive check (for helper patterns)
        # This handles cases where transfer is in a helper function called by init
        if not transferred_to_sender:
            transferred_to_sender = _is_transferred_to_sender_in_init(ctx, struct_name, init_func)

        # Check if shared using value-flow-aware SharesObject fact
        is_shared = _has_shares_object_fact(ctx, struct_name, init_func)

        debug(f"  {struct_name}: created={created_in_init}, transferred={transferred_to_sender}, shared={is_shared}")

        if transferred_to_sender and not is_shared:
            debug(f"  Detected privileged role: {struct_name}")

            # Generate facts in the appropriate source file
            for source_file in ctx.source_files.values():
                if any(f.name == "Struct" and f.args[0] == struct_name for f in source_file.facts):
                    # Generate IsCapability fact
                    role_fact = Fact("IsCapability", (struct_name,))
                    if role_fact not in source_file.facts:
                        source_file.facts.append(role_fact)
                        count += 1

                        if struct_name in ctx.global_facts_index:
                            for facts_list in ctx.global_facts_index[struct_name].values():
                                if role_fact not in facts_list:
                                    facts_list.append(role_fact)

                    # Generate IsPrivileged fact
                    priv_fact = Fact("IsPrivileged", (struct_name,))
                    if priv_fact not in source_file.facts:
                        source_file.facts.append(priv_fact)
                        count += 1

                        if struct_name in ctx.global_facts_index:
                            for facts_list in ctx.global_facts_index[struct_name].values():
                                if priv_fact not in facts_list:
                                    facts_list.append(priv_fact)
                    break

    if count > 0:
        debug(f"Generated {count} IsCapability/IsPrivileged facts (structural detection)")


def _is_created_in_init(ctx: "ProjectContext", struct_name: str, init_func: str) -> bool:
    """Check if struct is created in init or its transitive callees."""
    # Get simple name for matching
    struct_simple = struct_name.rsplit("::", 1)[1] if "::" in struct_name else struct_name

    # Collect init and transitive callees
    funcs_to_check = {init_func}
    if ctx.call_graph and init_func in ctx.call_graph.transitive_callees:
        funcs_to_check.update(ctx.call_graph.transitive_callees[init_func])

    # Check for PacksStruct facts
    for source_file in ctx.source_files.values():
        for fact in source_file.facts:
            if fact.name == "PacksStruct" and fact.args[0] in funcs_to_check:
                packed_type = fact.args[1]
                # Match FQN or simple name
                if packed_type == struct_name or packed_type == struct_simple:
                    return True
    return False


def _is_transferred_to_sender_in_init(ctx: "ProjectContext", struct_name: str, init_func: str) -> bool:
    """
    Check if struct is transferred to sender in init or its transitive callees.

    This checks if ANY function in the init call chain has BOTH:
    - transfer::transfer call
    - tx_context::sender call

    This is a conservative approximation that doesn't track value flow.
    """
    # Collect init and transitive callees
    funcs_to_check = {init_func}
    if ctx.call_graph and init_func in ctx.call_graph.transitive_callees:
        funcs_to_check.update(ctx.call_graph.transitive_callees[init_func])

    # Check if ANY function in init call chain has transfer + sender
    has_transfer = False
    has_sender = False

    for source_file in ctx.source_files.values():
        for fact in source_file.facts:
            if fact.name == "InFun" and fact.args[0] in funcs_to_check and "@" in fact.args[1]:
                callee = fact.args[1].split("@")[0]

                if is_stdlib_transfer_call(callee):
                    has_transfer = True
                if is_stdlib_sender_call(callee):
                    has_sender = True

    return has_transfer and has_sender


def _has_transfers_to_sender_fact(ctx: "ProjectContext", struct_name: str, init_func: str) -> bool:
    """
    Check if struct has TransfersToSender fact in init or its transitive callees.

    Uses the value-flow-aware TransfersToSender fact generated by generate_transfer_and_share_facts().
    """
    struct_simple = struct_name.rsplit("::", 1)[1] if "::" in struct_name else struct_name

    # Collect init and transitive callees
    funcs_to_check = {init_func}
    if ctx.call_graph and init_func in ctx.call_graph.transitive_callees:
        funcs_to_check.update(ctx.call_graph.transitive_callees[init_func])

    for source_file in ctx.source_files.values():
        for fact in source_file.facts:
            if fact.name == "TransfersToSender" and fact.args[0] in funcs_to_check:
                transferred_type = fact.args[1]
                if transferred_type == struct_name or transferred_type == struct_simple:
                    return True
    return False


def _has_shares_object_fact(ctx: "ProjectContext", struct_name: str, init_func: str) -> bool:
    """
    Check if struct has SharesObject fact in init or its transitive callees.

    Uses the value-flow-aware SharesObject fact generated by generate_transfer_and_share_facts().
    """
    struct_simple = struct_name.rsplit("::", 1)[1] if "::" in struct_name else struct_name

    # Collect init and transitive callees
    funcs_to_check = {init_func}
    if ctx.call_graph and init_func in ctx.call_graph.transitive_callees:
        funcs_to_check.update(ctx.call_graph.transitive_callees[init_func])

    for source_file in ctx.source_files.values():
        for fact in source_file.facts:
            if fact.name == "SharesObject" and fact.args[0] in funcs_to_check:
                shared_type = fact.args[1]
                if shared_type == struct_name or shared_type == struct_simple:
                    return True
    return False


def generate_capability_hierarchy_facts(ctx: "ProjectContext") -> None:
    """
    Detect capability hierarchies via creation patterns.

    Pattern: function requires CapA (via ChecksCapability) and creates CapB (via CreatesCapability)
    -> CapabilityHierarchy(CapA, CapB)

    This identifies which capabilities can grant other capabilities.
    """
    count = 0

    # Collect all role types
    role_types: Set[str] = set()
    for source_file in ctx.source_files.values():
        for fact in source_file.facts:
            if fact.name == "IsCapability":
                role_types.add(fact.args[0])

    if not role_types:
        debug("No roles found, skipping CapabilityHierarchy generation")
        return

    # For each function, check if it requires a role and creates a different role
    for source_file in ctx.source_files.values():
        if source_file.is_test_only:
            continue

        # Group facts by function
        func_checks_role: Dict[str, Set[str]] = {}
        func_creates_capability: Dict[str, Set[str]] = {}

        for fact in source_file.facts:
            if fact.name == "ChecksCapability":
                role_type = fact.args[0]
                func_name = fact.args[1]
                if func_name not in func_checks_role:
                    func_checks_role[func_name] = set()
                func_checks_role[func_name].add(role_type)

            elif fact.name == "CreatesCapability":
                func_name = fact.args[0]
                cap_type = fact.args[1]
                if func_name not in func_creates_capability:
                    func_creates_capability[func_name] = set()
                func_creates_capability[func_name].add(cap_type)

        # Find hierarchy relationships
        for func_name in func_checks_role.keys():
            if func_name not in func_creates_capability:
                continue

            required_roles = func_checks_role[func_name]
            created_caps = func_creates_capability[func_name]

            # For each required role + created cap pair, emit hierarchy
            for required_role in required_roles:
                for created_cap in created_caps:
                    # Skip self-creation (init pattern)
                    if required_role == created_cap:
                        continue

                    hierarchy_fact = Fact("CapabilityHierarchy", (required_role, created_cap))
                    if hierarchy_fact not in source_file.facts:
                        source_file.facts.append(hierarchy_fact)
                        count += 1
                        debug(f"  Hierarchy: {required_role} > {created_cap} (via {func_name})")

    if count > 0:
        debug(f"Generated {count} CapabilityHierarchy facts")


def generate_init_impl_facts(ctx: "ProjectContext") -> None:
    """
    Generate InitImpl facts for init helper functions.

    Detects functions that:
    1. Are transitively called by init
    2. AND perform sensitive operations (have sinks)

    This enables double-init detection to catch patterns like:
        fun init(ctx) { do_init(ctx); }
        public fun reset(ctx) { do_init(ctx); }  // Vulnerable
    """
    # 1. Find all init functions
    init_funcs: set[str] = set()
    for fc in ctx.source_files.values():
        for f in fc.facts:
            if f.name == "IsInit":
                init_funcs.add(f.args[0])

    if not init_funcs:
        return

    # 2. Collect functions with sensitive operations (sinks)
    funcs_with_sinks: set[str] = set()
    for fc in ctx.source_files.values():
        for f in fc.facts:
            if f.name == "Transfers":
                funcs_with_sinks.add(f.args[0])
            elif f.name == "SharesObject":
                funcs_with_sinks.add(f.args[0])
            elif f.name == "CreatesCapability":
                funcs_with_sinks.add(f.args[0])

    if not funcs_with_sinks:
        return

    if not ctx.call_graph:
        debug("[init_impl] No call graph available, skipping InitImpl detection")
        return

    # 3. For each init, mark transitive callees with sinks as InitImpl
    count = 0
    for init_func in init_funcs:
        callees = ctx.call_graph.transitive_callees.get(init_func, set())
        for callee in callees:
            if callee in funcs_with_sinks:
                # Find the file containing this function and add fact
                for fc in ctx.source_files.values():
                    if any(f.name == "Fun" and f.args[0] == callee for f in fc.facts):
                        init_impl_fact = Fact("InitImpl", (callee,))
                        if init_impl_fact not in fc.facts:
                            fc.facts.append(init_impl_fact)
                            count += 1
                            debug(f"  InitImpl({callee}) via {init_func}")
                        break

    if count > 0:
        debug(f"Generated {count} InitImpl facts")


def generate_destroys_capability_facts(ctx: "ProjectContext") -> None:
    """
    Generate DestroysCapability facts for functions that destroy role/capability structs.

    Detection approach:
    1. Find functions with ObjectDestroySink (object::delete, coin::burn, etc.)
    2. Check if function has a capability parameter passed BY VALUE (not reference)
       - By value = capability is being consumed/destroyed
       - By reference = capability is being used for authorization
    3. Emit DestroysCapability for the by-value capability type

    Examples:
        DESTROYS (by value):
            public entry fun burn(cap: AdminCap) { ... }  // cap is consumed

        AUTHORIZES (by reference):
            public entry fun withdraw(_: &AdminCap, amt: u64) { ... }  // cap is proof

    Limitations:
        - Currently intraprocedural only - does not detect delegated destruction
          through helper functions. If `burn(cap)` calls `destroy_helper(cap)`,
          only the helper function will be detected as destroying, not `burn`.
        - Uses simple name fallback for type resolution if FQN fails. However,
          when multiple modules define capabilities with the same simple name
          (e.g., two AdminCap types), simple name fallback is disabled for that
          name to prevent incorrect matching. Same-module references always
          resolve correctly via FQN resolution.

    See also:
        - ObjectDestroySink: sink fact for object destruction
        - IsCapability: marks structs as capabilities/roles
    """
    # Collect all role types (fully qualified)
    role_types: Set[str] = set()
    for source_file in ctx.source_files.values():
        for fact in source_file.facts:
            if fact.name == "IsCapability":
                role_types.add(fact.args[0])

    if not role_types:
        debug("No roles found, skipping DestroysCapability generation")
        return

    # Build simple_name -> set of FQNs mapping for collision detection
    simple_name_to_fqns: Dict[str, Set[str]] = {}
    for role in role_types:
        simple = role.rsplit("::", 1)[1] if "::" in role else role
        if simple not in simple_name_to_fqns:
            simple_name_to_fqns[simple] = set()
        simple_name_to_fqns[simple].add(role)

    # Identify collision simple names (skip these in fallback matching)
    collision_simple_names = {name for name, fqns in simple_name_to_fqns.items() if len(fqns) > 1}
    if collision_simple_names:
        debug(f"[destroys_cap] FQN collisions detected for: {collision_simple_names}")

    debug(f"[destroys_cap] Looking for destruction of roles: {role_types}")

    count = 0
    for source_file in ctx.source_files.values():
        if source_file.is_test_only:
            continue

        # 1. Find functions with ObjectDestroySink
        funcs_with_destroy: Set[str] = set()
        func_to_stmt_id: Dict[str, str] = {}
        for fact in source_file.facts:
            if fact.name == "ObjectDestroySink":
                func_name, stmt_id, _callee = fact.args
                funcs_with_destroy.add(func_name)
                func_to_stmt_id[func_name] = stmt_id  # Use first destroy stmt

        # 2. For each function with destroy, check for capability params by value
        for func_name in funcs_with_destroy:
            for fact in source_file.facts:
                if fact.name != "FormalArg" or fact.args[0] != func_name:
                    continue

                _func, _idx, _param_name, param_type = fact.args

                # Skip reference types - those are for authorization, not destruction
                if param_type.startswith("&"):
                    continue

                # Strip generics for matching
                clean_type = strip_generics(param_type)

                # Resolve to FQN if possible
                resolved_type = _resolve_type_to_fqn(
                    clean_type,
                    source_file.import_map,
                    source_file.module_path,
                    role_types,
                )

                # Check if it's a role
                cap_type = None
                if resolved_type in role_types:
                    cap_type = resolved_type
                else:
                    # Try simple name match, but ONLY if no collision
                    simple_name = clean_type.rsplit("::", 1)[1] if "::" in clean_type else clean_type
                    if simple_name not in collision_simple_names and simple_name in simple_name_to_fqns:
                        fqn_set = simple_name_to_fqns[simple_name]
                        assert len(fqn_set) == 1, f"Invariant: {simple_name} has {len(fqn_set)} FQNs"
                        cap_type = next(iter(fqn_set))

                if cap_type:
                    stmt_id = func_to_stmt_id.get(func_name, "stmt_0")
                    destroy_fact = Fact("DestroysCapability", (func_name, cap_type, stmt_id))
                    if destroy_fact not in source_file.facts:
                        source_file.facts.append(destroy_fact)
                        count += 1
                        debug(f"  DestroysCapability({func_name}, {cap_type}, {stmt_id})")

    if count > 0:
        debug(f"Generated {count} DestroysCapability facts")
