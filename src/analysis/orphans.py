"""
Orphan detection: unused TxContext functions, roles, events.
"""

from typing import Dict, Set

from core.context import ProjectContext
from core.facts import Fact
from core.utils import debug, get_simple_name

# TxContext functions that indicate actual usage
TXCONTEXT_USAGE_FUNCTIONS = {
    "tx_context::sender",
    "sui::tx_context::sender",
    "tx_context::digest",
    "sui::tx_context::digest",
    "tx_context::epoch",
    "sui::tx_context::epoch",
    "tx_context::epoch_timestamp_ms",
    "sui::tx_context::epoch_timestamp_ms",
    "tx_context::sponsor",
    "sui::tx_context::sponsor",
    "tx_context::fresh_object_address",
    "sui::tx_context::fresh_object_address",
    "tx_context::reference_gas_price",
    "sui::tx_context::reference_gas_price",
    "tx_context::gas_price",
    "sui::tx_context::gas_price",
}


def _collect_txcontext_users(ctx: ProjectContext) -> Set[str]:
    """
    Collect functions that actually USE their TxContext parameter.
    A function uses TxContext if it:
    1. Calls any tx_context::* function directly
    2. Passes TxContext parameter to another function (internal or external)
    3. Transitively calls a function that uses TxContext
    """
    direct_users = set()
    transitive_users = set()

    # Collect TxContext parameter names for each function
    func_txcontext_params: Dict[str, Set[str]] = {}
    for source_file in ctx.source_files.values():
        for fact in source_file.facts:
            if fact.name == "FormalArg":
                func_name, _, param_name, param_type = fact.args
                if "TxContext" in param_type:
                    if func_name not in func_txcontext_params:
                        func_txcontext_params[func_name] = set()
                    func_txcontext_params[func_name].add(param_name)

    # First pass: collect direct TxContext users
    for source_file in ctx.source_files.values():
        for fact in source_file.facts:
            if fact.name == "InFun":
                func_name, call_id = fact.args
                if "@" in call_id:
                    callee = call_id.split("@")[0]
                    # Check if this is a TxContext usage function
                    if callee in TXCONTEXT_USAGE_FUNCTIONS:
                        direct_users.add(func_name)
                        debug(f"  Function {func_name} uses TxContext via {callee}")
            # Check if TxContext parameter is passed to any call (CallArg)
            elif fact.name == "CallArg":
                func_name, _, callee, _, arg_vars = fact.args
                if func_name in func_txcontext_params:
                    txcontext_params = func_txcontext_params[func_name]
                    # Check if any TxContext param is passed as argument
                    for arg_var in arg_vars:
                        if arg_var in txcontext_params:
                            if func_name not in direct_users:
                                direct_users.add(func_name)
                                debug(f"  Function {func_name} passes TxContext to {callee}")
                            break

    # Second pass: find functions that pass TxContext to other functions
    # Build a map of function -> functions it calls
    func_calls: Dict[str, Set[str]] = {}
    for source_file in ctx.source_files.values():
        for fact in source_file.facts:
            if fact.name == "InFun":
                func_name, call_id = fact.args
                if "@" in call_id:
                    callee = call_id.split("@")[0]
                    if func_name not in func_calls:
                        func_calls[func_name] = set()
                    func_calls[func_name].add(callee)

    # Fixed-point: propagate "uses TxContext" transitively
    # If function A calls function B, and B uses TxContext, then A uses TxContext
    changed = True
    users = direct_users.copy()
    iterations = 0
    while changed and iterations < 10:
        changed = False
        iterations += 1
        for func_name, callees in func_calls.items():
            if func_name in users:
                continue
            # Check if any callee uses TxContext
            for callee in callees:
                # Match callee with users (handle FQN vs simple name)
                for user in users:
                    user_simple = get_simple_name(user)
                    callee_simple = get_simple_name(callee) if "::" in callee else callee
                    if user == callee or user_simple == callee_simple or callee == user_simple:
                        users.add(func_name)
                        transitive_users.add(func_name)
                        changed = True
                        break
                if changed and func_name in users:
                    break

    if transitive_users:
        debug(f"  Found {len(transitive_users)} functions that transitively use TxContext")

    return users


def detect_orphan_txcontext_functions(ctx: ProjectContext) -> None:
    """
    Detect orphan TxContext functions.

    Pattern 1: public(friend) function has TxContext parameter but is not entry and not called.
    Pattern 2: public(friend) function has TxContext parameter but doesn't use it (orphan param).

    Cross-module tracking: If function A calls function B with TxContext, and B doesn't use it,
    then B is marked as orphan.
    """
    orphan_count = 0

    # First, collect which functions actually USE their TxContext
    txcontext_users = _collect_txcontext_users(ctx)

    for source_file in ctx.source_files.values():
        funcs_with_txcontext: Set[str] = set()
        entry_functions: Set[str] = set()
        test_only_functions: Set[str] = set()
        all_functions: Set[str] = set()
        friend_functions: Set[str] = set()

        for fact in source_file.facts:
            if fact.name == "Fun":
                all_functions.add(fact.args[0])
            elif fact.name == "IsEntry":
                entry_functions.add(fact.args[0])
            elif fact.name == "IsTestOnly":
                test_only_functions.add(fact.args[0])
            elif fact.name == "IsFriend":
                friend_functions.add(fact.args[0])
            elif fact.name == "FormalArg":
                func_name, _, _, param_type = fact.args
                if "TxContext" in param_type:
                    funcs_with_txcontext.add(func_name)

        called_functions: Set[str] = set()

        for fact in source_file.facts:
            if fact.name == "InFun" and "@" in fact.args[1]:
                call_id = fact.args[1]
                callee = call_id.split("@")[0]
                for func in all_functions:
                    if func == callee or func.endswith("::" + callee) or callee.endswith("::" + get_simple_name(func)):
                        called_functions.add(func)

        for other_file in ctx.source_files.values():
            for fact in other_file.facts:
                if fact.name == "InFun" and "@" in fact.args[1]:
                    call_id = fact.args[1]
                    callee = call_id.split("@")[0]
                    for func in all_functions:
                        simple_name = get_simple_name(func)
                        if (
                            func == callee
                            or callee.endswith("::" + simple_name)
                            or func.endswith("::" + get_simple_name(callee))
                        ):
                            called_functions.add(func)

        for func_name in funcs_with_txcontext:
            if func_name not in friend_functions:
                continue
            if func_name in entry_functions:
                continue
            if func_name in test_only_functions:
                continue

            # Check Pattern 1: Not called at all
            # OR Pattern 2: Called but doesn't use TxContext
            is_orphan = False
            reason = ""

            if func_name not in called_functions:
                is_orphan = True
                reason = "has TxContext, not entry, not called"
            elif func_name not in txcontext_users:
                is_orphan = True
                reason = "has TxContext parameter but never uses it"

            if is_orphan:
                orphan_fact = Fact("OrphanTxContextFunction", (func_name,))
                if not any(f.name == "OrphanTxContextFunction" and f.args[0] == func_name for f in source_file.facts):
                    source_file.facts.append(orphan_fact)
                    orphan_count += 1
                    debug(f"  OrphanTxContextFunction({func_name}) [{reason}]")

                    if func_name in ctx.global_facts_index:
                        for file_path, func_facts in ctx.global_facts_index[func_name].items():
                            if not any(
                                f.name == "OrphanTxContextFunction" and f.args[0] == func_name for f in func_facts
                            ):
                                func_facts.append(orphan_fact)

    if orphan_count > 0:
        debug(f"Generated {orphan_count} OrphanTxContextFunction facts")


def detect_orphan_roles(ctx: ProjectContext) -> None:
    """
    Detect orphan role structs.
    Pattern: Role is defined but never used as a function parameter.
    """
    role_types: Set[str] = set()
    role_to_file: Dict[str, str] = {}

    for file_path, source_file in ctx.source_files.items():
        for fact in source_file.facts:
            if fact.name == "IsCapability":
                role_type = fact.args[0]
                role_types.add(role_type)
                role_to_file[role_type] = file_path

    if not role_types:
        return

    # Detect FQN collisions (same simple name, different modules)
    simple_name_to_fqns: Dict[str, Set[str]] = {}
    for role_type in role_types:
        simple_name = get_simple_name(role_type)
        if simple_name not in simple_name_to_fqns:
            simple_name_to_fqns[simple_name] = set()
        simple_name_to_fqns[simple_name].add(role_type)

    # Simple names that have FQN collisions
    collision_simple_names = {name for name, fqns in simple_name_to_fqns.items() if len(fqns) > 1}
    if collision_simple_names:
        debug(f"  FQN collisions detected for: {collision_simple_names}")

    used_roles: Set[str] = set()

    for source_file in ctx.source_files.values():
        for fact in source_file.facts:
            if fact.name == "ChecksCapability":
                role_type = fact.args[0]
                used_roles.add(role_type)
                # Only add simple name if there's no FQN collision
                simple_name = get_simple_name(role_type)
                if simple_name not in collision_simple_names:
                    used_roles.add(simple_name)

    for func_name, file_facts_dict in ctx.global_facts_index.items():
        for file_path, func_facts in file_facts_dict.items():
            for fact in func_facts:
                if fact.name == "ChecksCapability":
                    role_type = fact.args[0]
                    used_roles.add(role_type)
                    # Only add simple name if there's no FQN collision
                    simple_name = get_simple_name(role_type)
                    if simple_name not in collision_simple_names:
                        used_roles.add(simple_name)

    orphan_count = 0
    for role_type in role_types:
        simple_name = get_simple_name(role_type)

        # Check if used: always check FQN, only check simple name if no collision
        is_used = role_type in used_roles
        if not is_used and simple_name not in collision_simple_names:
            is_used = simple_name in used_roles

        if is_used:
            continue

        file_path = role_to_file.get(role_type)
        if file_path and file_path in ctx.source_files:
            source_file = ctx.source_files[file_path]
            orphan_fact = Fact("OrphanCapability", (role_type,))
            if not any(f.name == "OrphanCapability" and f.args[0] == role_type for f in source_file.facts):
                source_file.facts.append(orphan_fact)
                orphan_count += 1
                debug(f"  OrphanCapability({role_type}) [defined but never used as parameter]")

    if orphan_count > 0:
        debug(f"Generated {orphan_count} OrphanCapability facts")


def detect_orphan_events(ctx: ProjectContext) -> None:
    """
    Detect orphan event structs.
    Pattern: Event is defined but never emitted via event::emit().

    Sui's native emit (sui-move-natives/src/event.rs:emit_impl) only checks:
    1. copy+drop abilities, 2. is a struct, 3. size limit.
    No structural distinction from data transfer structs.
    Heuristic: if used in non-emit context (return type, field access) AND never emitted → NOT an event.
    """
    event_types: Set[str] = set()
    event_to_file: Dict[str, str] = {}

    for file_path, source_file in ctx.source_files.items():
        for fact in source_file.facts:
            if fact.name == "IsEvent":
                event_type = fact.args[0]
                event_types.add(event_type)
                event_to_file[event_type] = file_path

    if not event_types:
        return

    # Detect FQN collisions (same simple name, different modules)
    simple_name_to_fqns: Dict[str, Set[str]] = {}
    for event_type in event_types:
        simple_name = get_simple_name(event_type)
        if simple_name not in simple_name_to_fqns:
            simple_name_to_fqns[simple_name] = set()
        simple_name_to_fqns[simple_name].add(event_type)

    # Simple names that have FQN collisions
    collision_simple_names = {name for name, fqns in simple_name_to_fqns.items() if len(fqns) > 1}
    if collision_simple_names:
        debug(f"  FQN collisions detected for events: {collision_simple_names}")

    emitted_events: Set[str] = set()

    for source_file in ctx.source_files.values():
        for fact in source_file.facts:
            # Check EmitsEvent - explicit event::emit() calls
            if fact.name == "EmitsEvent":
                event_type = fact.args[1]
                emitted_events.add(event_type)
                simple_name = get_simple_name(event_type)
                if simple_name not in collision_simple_names:
                    emitted_events.add(simple_name)
            # Check PacksStruct - event instantiated (covers wrapper functions like emit_event(MyEvent {...}))
            elif fact.name == "PacksStruct":
                struct_type = fact.args[1]
                if struct_type in event_types:
                    emitted_events.add(struct_type)
                    simple_name = get_simple_name(struct_type)
                    if simple_name not in collision_simple_names:
                        emitted_events.add(simple_name)

    for func_name, file_facts_dict in ctx.global_facts_index.items():
        for file_path, func_facts in file_facts_dict.items():
            for fact in func_facts:
                if fact.name == "EmitsEvent":
                    event_type = fact.args[1]
                    emitted_events.add(event_type)
                    simple_name = get_simple_name(event_type)
                    if simple_name not in collision_simple_names:
                        emitted_events.add(simple_name)
                elif fact.name == "PacksStruct":
                    struct_type = fact.args[1]
                    if struct_type in event_types:
                        emitted_events.add(struct_type)
                        simple_name = get_simple_name(struct_type)
                        if simple_name not in collision_simple_names:
                            emitted_events.add(simple_name)

    # Collect structs used in non-emit contexts - these are data transfer structs, not events
    non_event_usage: Set[str] = set()
    for source_file in ctx.source_files.values():
        for fact in source_file.facts:
            if fact.name in ("FieldAccess", "ReadsField"):
                struct_type = fact.args[1]
                non_event_usage.add(struct_type)
                non_event_usage.add(get_simple_name(struct_type))
            elif fact.name == "FunReturnType":
                ret_type = fact.args[1]
                non_event_usage.add(ret_type)
                non_event_usage.add(get_simple_name(ret_type))

    orphan_count = 0
    for event_type in event_types:
        simple_name = get_simple_name(event_type)

        # Check if emitted: always check FQN, only check simple name if no collision
        is_emitted = event_type in emitted_events
        if not is_emitted and simple_name not in collision_simple_names:
            is_emitted = simple_name in emitted_events

        if is_emitted:
            continue

        # Skip if used in non-emit context - data transfer struct, not event
        if event_type in non_event_usage or simple_name in non_event_usage:
            continue

        file_path = event_to_file.get(event_type)
        if file_path and file_path in ctx.source_files:
            source_file = ctx.source_files[file_path]
            orphan_fact = Fact("OrphanEvent", (event_type,))
            if not any(f.name == "OrphanEvent" and f.args[0] == event_type for f in source_file.facts):
                source_file.facts.append(orphan_fact)
                orphan_count += 1
                debug(f"  OrphanEvent({event_type}) [defined but never emitted]")

    if orphan_count > 0:
        debug(f"Generated {orphan_count} OrphanEvent facts")
