"""
User asset container detection via usage patterns.

Detects structs that hold user-deposited assets by analyzing how they're used:
1. UserDepositsInto: Public function takes Coin/Balance + &mut SharedStruct, no privileged check
2. UserWithdrawsFrom: Public function transfers to sender + &mut SharedStruct, no privileged check
3. IsUserAssetContainer: Struct has BOTH deposit and withdraw patterns

These facts enable detecting centralization risks (privileged drain) and access control issues.
"""

from typing import Dict, Set, List, Tuple
from core.context import ProjectContext
from core.facts import Fact
from core.utils import debug
from move.extract import get_simple_name, get_simple_type_name, resolve_to_fqn
from analysis.call_graph import build_global_call_graph, get_transitive_callees


# Coin/Balance types that represent user value
VALUE_TYPES = {"Coin", "Balance"}


def detect_user_asset_containers(ctx: ProjectContext) -> None:
    """
    Detect user asset containers via deposit/withdraw usage patterns.

    Must run AFTER:
    - Pass 1 (FormalArg, IsSharedObject, IsPublic, IsEntry, ChecksCapability, HasSenderEqualityCheck)
    - Pass 2 (Transfers - for detecting transfer to sender)

    Generates:
    - UserDepositsInto(func, struct_type)
    - UserWithdrawsFrom(func, struct_type)
    - IsUserAssetContainer(struct_type)
    - WritesUserAsset(func, struct_type)
    - ReadsUserAsset(func, struct_type)
    """
    # Collect shared object types (FQNs only)
    shared_types = _collect_fact_first_args(ctx, "IsSharedObject")

    # Collect privileged role types for filtering (FQNs only)
    privileged_roles = _collect_fact_first_args(ctx, "IsPrivileged")

    # Detect deposit and withdraw patterns with interprocedural analysis (for shared objects only)
    deposits = {}
    withdraws = {}
    if shared_types:
        debug("Analyzing shared object types for user asset patterns (with IPA)...")
        debug(f"  Privileged roles for filtering: {privileged_roles}")
        deposits, withdraws = _analyze_patterns_with_ipa(ctx, shared_types, privileged_roles)
    else:
        debug("No shared objects found, skipping structural pattern analysis")

    # Generate UserDepositsInto facts
    deposit_count = 0
    for struct_type, funcs in deposits.items():
        for func_name in funcs:
            fact = Fact("UserDepositsInto", (func_name, struct_type))
            _add_fact_to_struct_file(ctx, struct_type, fact)
            deposit_count += 1
            debug(f"  UserDepositsInto({func_name}, {struct_type})")

    # Generate UserWithdrawsFrom facts
    withdraw_count = 0
    for struct_type, funcs in withdraws.items():
        for func_name in funcs:
            fact = Fact("UserWithdrawsFrom", (func_name, struct_type))
            _add_fact_to_struct_file(ctx, struct_type, fact)
            withdraw_count += 1
            debug(f"  UserWithdrawsFrom({func_name}, {struct_type})")

    # IsUserAssetContainer: struct has BOTH deposit and withdraw
    user_asset_containers: Set[str] = set()
    for struct_type in deposits.keys():
        if struct_type in withdraws:
            user_asset_containers.add(struct_type)
            fact = Fact("IsUserAssetContainer", (struct_type,))
            _add_fact_to_struct_file(ctx, struct_type, fact)
            debug(f"  IsUserAssetContainer({struct_type})")

    # Also include structs marked as user assets by LLM (Pass 2)
    # This allows detection even for owned objects (not just shared)
    llm_user_assets = 0
    for fact in ctx.semantic_facts:
        if fact.name == "IsUserAsset" and len(fact.args) >= 2 and fact.args[1] is True:
            struct_type = fact.args[0]
            if struct_type not in user_asset_containers:
                user_asset_containers.add(struct_type)
                llm_user_assets += 1
                debug(f"  User asset from LLM: {struct_type}")

    if llm_user_assets > 0:
        debug(f"Added {llm_user_assets} LLM-classified user assets")

    if not user_asset_containers:
        debug("No user asset containers found (need both deposit+withdraw patterns or LLM classification)")
        return

    # Generate HasOwnershipField facts for containers with ownership fields
    # This allows rules to distinguish user-owned assets from protocol state
    ownership_fields = {"owner", "authority", "admin", "creator", "user", "sender"}
    for struct_type in user_asset_containers:
        if _has_ownership_field(ctx, struct_type, ownership_fields):
            fact = Fact("HasOwnershipField", (struct_type,))
            _add_fact_to_struct_file(ctx, struct_type, fact)
            debug(f"  HasOwnershipField({struct_type})")

    # Generate WritesUserAsset / ReadsUserAsset
    writes_count, reads_count = _generate_access_facts(ctx, user_asset_containers)

    debug(
        f"User asset detection: {len(user_asset_containers)} containers, "
        f"{deposit_count} deposits, {withdraw_count} withdraws, "
        f"{writes_count} writes, {reads_count} reads"
    )


def _has_ownership_field(ctx: ProjectContext, struct_type: str, ownership_fields: Set[str]) -> bool:
    """
    Check if struct has a field indicating per-user ownership.
    User assets have 'owner', 'authority', etc. Protocol state lacks these.
    """
    simple_name = get_simple_name(struct_type)
    found_fqn_match = False

    # First pass: try exact FQN match
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "StructField":
                fact_struct = fact.args[0]
                field_name = fact.args[2].lower()

                if fact_struct == struct_type:
                    found_fqn_match = True
                    if any(of in field_name for of in ownership_fields):
                        return True

    # Second pass: fall back to simple name match only if no FQN match found
    if not found_fqn_match:
        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name == "StructField":
                    fact_struct = fact.args[0]
                    field_name = fact.args[2].lower()

                    if get_simple_name(fact_struct) == simple_name:
                        if any(of in field_name for of in ownership_fields):
                            return True

    return False


def _collect_fact_first_args(ctx: ProjectContext, fact_name: str) -> Set[str]:
    """
    Collect first argument values from facts.

    Returns set of FQNs (fully-qualified names only).
    """
    values: Set[str] = set()
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == fact_name:
                values.add(fact.args[0])
    return values


def _build_func_info(
    facts: List[Fact],
    shared_types: Set[str],
    privileged_roles: Set[str],
    module_path: str | None,
    import_map: Dict[str, str] | None,
) -> Dict[str, Dict]:
    """
    Build function info dict from facts.

    Returns func_name -> {is_public, is_entry, has_privileged_check, ...}
    """
    func_info: Dict[str, Dict] = {}

    for fact in facts:
        if fact.name == "Fun":
            func_name = fact.args[0]
            if func_name not in func_info:
                func_info[func_name] = {
                    "is_public": False,
                    "is_entry": False,
                    "has_privileged_check": False,
                    "checks_sender": False,
                    "has_transfer": False,
                    "mut_shared_params": [],  # [(param_name, struct_type)]
                    "value_params": [],  # [(param_name, param_type)]
                    "transfers_to_sender": False,
                }

    for fact in facts:
        # ChecksCapability has args (role_type, func_name) - handle specially
        if fact.name == "ChecksCapability":
            role_type = fact.args[0]
            checked_func = fact.args[1]
            if checked_func in func_info:
                resolved_role = resolve_to_fqn(role_type, privileged_roles, module_path, import_map)
                if resolved_role:
                    func_info[checked_func]["has_privileged_check"] = True
            continue

        func_name = fact.args[0] if fact.args else None
        if func_name not in func_info:
            continue

        if fact.name == "IsPublic":
            func_info[func_name]["is_public"] = True
        elif fact.name == "IsEntry":
            func_info[func_name]["is_entry"] = True
        elif fact.name == "FormalArg":
            func_name = fact.args[0]
            param_name = fact.args[2]
            param_type = fact.args[3]

            if func_name not in func_info:
                continue

            if param_type.startswith("&mut "):
                base_type = get_simple_type_name(param_type)
                resolved_type = resolve_to_fqn(base_type, shared_types, module_path, import_map)
                if resolved_type:
                    func_info[func_name]["mut_shared_params"].append((param_name, resolved_type))

            if not param_type.startswith("&"):
                for vt in VALUE_TYPES:
                    if vt in param_type:
                        func_info[func_name]["value_params"].append((param_name, param_type))
                        break

        elif fact.name == "TransfersFromSender":
            if func_name in func_info:
                func_info[func_name]["transfers_to_sender"] = True
        elif fact.name == "CallsSender":
            if func_name in func_info:
                func_info[func_name]["checks_sender"] = True
        elif fact.name == "Transfers":
            if func_name in func_info:
                func_info[func_name]["has_transfer"] = True

    # Also check TrackedDerived for sender + transfer pattern
    sender_vars: Dict[str, Set[str]] = {}
    for fact in facts:
        if fact.name == "TrackedDerived" and fact.args[2] == "sender":
            func_name, var, _ = fact.args
            if func_name not in sender_vars:
                sender_vars[func_name] = set()
            sender_vars[func_name].add(var)

    for fact in facts:
        if fact.name == "SinkUsesVar" and fact.args[3] == "recipient":
            func_name, _, var, _ = fact.args
            if func_name in sender_vars and var in sender_vars[func_name]:
                if func_name in func_info:
                    func_info[func_name]["transfers_to_sender"] = True

    return func_info


def _get_func_patterns(
    func_info: Dict[str, Dict],
) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
    """
    Get deposit/withdraw patterns for ALL functions (regardless of visibility).

    Returns (func_deposits, func_withdraws) where each maps func_name -> {struct_types}
    """
    func_deposits: Dict[str, Set[str]] = {}
    func_withdraws: Dict[str, Set[str]] = {}

    for func_name, info in func_info.items():
        # Deposit pattern: has Coin/Balance param + &mut SharedStruct
        if info["value_params"] and info["mut_shared_params"]:
            func_deposits[func_name] = set()
            for _, struct_type in info["mut_shared_params"]:
                func_deposits[func_name].add(struct_type)

        # Withdraw pattern: transfers to sender + &mut SharedStruct
        transfers_to_sender = info["transfers_to_sender"] or (info["checks_sender"] and info["has_transfer"])
        if transfers_to_sender and info["mut_shared_params"]:
            func_withdraws[func_name] = set()
            for _, struct_type in info["mut_shared_params"]:
                func_withdraws[func_name].add(struct_type)

    return func_deposits, func_withdraws


def _analyze_patterns_with_ipa(
    ctx: ProjectContext,
    shared_types: Set[str],
    privileged_roles: Set[str],
) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
    """
    Analyze deposit/withdraw patterns with interprocedural analysis.

    For each public/entry function, checks if it OR any transitive callee
    has deposit/withdraw patterns. Propagates patterns to entry points.

    Returns (deposits, withdraws) where each maps struct_type -> {entry_func_names}
    """
    # Build global call graph for IPA
    call_graph = build_global_call_graph(ctx)

    # Build func_info and get patterns for ALL functions across all files
    all_func_info: Dict[str, Dict] = {}
    all_func_deposits: Dict[str, Set[str]] = {}
    all_func_withdraws: Dict[str, Set[str]] = {}

    for file_ctx in ctx.source_files.values():
        if file_ctx.is_test_only:
            continue

        func_info = _build_func_info(
            file_ctx.facts, shared_types, privileged_roles, file_ctx.module_path, file_ctx.import_map
        )
        all_func_info.update(func_info)

        func_deposits, func_withdraws = _get_func_patterns(func_info)
        all_func_deposits.update(func_deposits)
        all_func_withdraws.update(func_withdraws)

    # Build simple name index for cross-module matching
    simple_to_fqn: Dict[str, List[str]] = {}
    for func_name in all_func_info:
        simple = get_simple_name(func_name)
        if simple not in simple_to_fqn:
            simple_to_fqn[simple] = []
        simple_to_fqn[simple].append(func_name)

    # For each public/entry function, check if it or callees have patterns
    deposits: Dict[str, Set[str]] = {}  # struct_type -> {entry_func_names}
    withdraws: Dict[str, Set[str]] = {}

    for func_name, info in all_func_info.items():
        # Must be public/entry
        if not (info["is_public"] or info["is_entry"]):
            continue

        # Must NOT have privileged check
        if info["has_privileged_check"]:
            continue

        # Get transitive callees
        callees = get_transitive_callees(func_name, call_graph)
        funcs_to_check = [func_name] + callees

        # Check each function in call chain for patterns
        for callee in funcs_to_check:
            # Try exact match first (FQN)
            callee_deposits = all_func_deposits.get(callee, set())
            callee_withdraws = all_func_withdraws.get(callee, set())

            # Only try simple name match if:
            # 1. No exact match found
            # 2. Callee is NOT in all_func_info (i.e., it's an unresolved/external call)
            # This avoids false positives from same-named functions in different modules
            if not callee_deposits and not callee_withdraws and callee not in all_func_info:
                callee_simple = get_simple_name(callee)
                candidates = simple_to_fqn.get(callee_simple, [])
                # Only use simple name match if there's exactly one candidate
                # Multiple candidates = ambiguous, skip to avoid false positives
                if len(candidates) == 1:
                    fqn = candidates[0]
                    callee_deposits = all_func_deposits.get(fqn, set())
                    callee_withdraws = all_func_withdraws.get(fqn, set())

            # Propagate patterns to entry function
            for struct_type in callee_deposits:
                if struct_type not in deposits:
                    deposits[struct_type] = set()
                deposits[struct_type].add(func_name)

            for struct_type in callee_withdraws:
                if struct_type not in withdraws:
                    withdraws[struct_type] = set()
                withdraws[struct_type].add(func_name)

    return deposits, withdraws


def _add_fact_to_struct_file(ctx: ProjectContext, struct_type: str, fact: Fact) -> None:
    """
    Add fact to file(s) containing the struct definition.

    Prefers FQN match. Falls back to simple name match only if no FQN match found.
    Handles multiple files with same-named structs by preferring exact match.
    """
    simple_name = get_simple_name(struct_type)

    # First pass: try exact FQN match
    for file_ctx in ctx.source_files.values():
        for f in file_ctx.facts:
            if f.name == "Struct" and f.args[0] == struct_type:
                if not any(ef.name == fact.name and ef.args == fact.args for ef in file_ctx.facts):
                    file_ctx.facts.append(fact)
                return  # FQN match found, done

    # Second pass: fall back to simple name match (only if no FQN match)
    for file_ctx in ctx.source_files.values():
        for f in file_ctx.facts:
            if f.name == "Struct" and get_simple_name(f.args[0]) == simple_name:
                if not any(ef.name == fact.name and ef.args == fact.args for ef in file_ctx.facts):
                    file_ctx.facts.append(fact)
                return  # Simple name match found, done


def _generate_access_facts(
    ctx: ProjectContext,
    user_asset_containers: Set[str],
) -> Tuple[int, int]:
    """
    Generate WritesUserAsset / ReadsUserAsset facts.

    Generates direct facts from FormalArg analysis, then propagates to callers.

    Returns (writes_count, reads_count).
    """
    writes_count = 0
    reads_count = 0

    # Step 1: Generate direct facts from FormalArg analysis
    for file_ctx in ctx.source_files.values():
        module_path = file_ctx.module_path
        import_map = file_ctx.import_map

        for fact in file_ctx.facts:
            if fact.name == "FormalArg":
                func_name = fact.args[0]
                param_type = fact.args[3]

                # Try full type first (strip only ref modifiers, keep module path)
                from move.extract import strip_ref_modifiers

                full_type = strip_ref_modifiers(param_type)

                # Try direct FQN match first
                if full_type in user_asset_containers:
                    full_struct_name = full_type
                else:
                    # Fall back to simple name resolution
                    base_type = get_simple_type_name(param_type)
                    full_struct_name = resolve_to_fqn(base_type, user_asset_containers, module_path, import_map)

                if not full_struct_name:
                    continue

                if param_type.startswith("&mut "):
                    write_fact = Fact("WritesUserAsset", (func_name, full_struct_name))
                    if not any(
                        f.name == "WritesUserAsset" and f.args == (func_name, full_struct_name) for f in file_ctx.facts
                    ):
                        file_ctx.facts.append(write_fact)
                        writes_count += 1
                        debug(f"  WritesUserAsset({func_name}, {full_struct_name})")

                elif param_type.startswith("&"):
                    read_fact = Fact("ReadsUserAsset", (func_name, full_struct_name))
                    if not any(
                        f.name == "ReadsUserAsset" and f.args == (func_name, full_struct_name) for f in file_ctx.facts
                    ):
                        file_ctx.facts.append(read_fact)
                        reads_count += 1
                        debug(f"  ReadsUserAsset({func_name}, {full_struct_name})")

    # Step 2: Propagate WritesUserAsset and ReadsUserAsset to callers (fixed-point)
    from analysis.call_graph import build_global_call_graph

    call_graph = build_global_call_graph(ctx)

    # Collect all WritesUserAsset/ReadsUserAsset facts (func -> {struct_types})
    writes_map: Dict[str, Set[str]] = {}
    reads_map: Dict[str, Set[str]] = {}

    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "WritesUserAsset":
                func_name, struct_type = fact.args
                if func_name not in writes_map:
                    writes_map[func_name] = set()
                writes_map[func_name].add(struct_type)
            elif fact.name == "ReadsUserAsset":
                func_name, struct_type = fact.args
                if func_name not in reads_map:
                    reads_map[func_name] = set()
                reads_map[func_name].add(struct_type)

    # Build simple name -> FQN mapping for cross-module lookups
    simple_to_fqn: Dict[str, Set[str]] = {}
    for func_name in set(writes_map.keys()) | set(reads_map.keys()):
        simple = get_simple_name(func_name)
        if simple not in simple_to_fqn:
            simple_to_fqn[simple] = set()
        simple_to_fqn[simple].add(func_name)

    # Fixed-point propagation to callers
    propagated_writes = 0
    propagated_reads = 0
    changed = True
    max_iterations = 10

    iteration = 0
    while changed and iteration < max_iterations:
        changed = False
        iteration += 1

        for caller, callees in call_graph.items():
            for callee in callees:
                callee_writes: Set[str] = set()
                callee_reads: Set[str] = set()

                if callee in writes_map:
                    callee_writes.update(writes_map[callee])
                if callee in reads_map:
                    callee_reads.update(reads_map[callee])

                # Fallback: simple name match for cross-module calls
                if not callee_writes and not callee_reads:
                    callee_simple = get_simple_name(callee)
                    for fqn in simple_to_fqn.get(callee_simple, set()):
                        callee_writes.update(writes_map.get(fqn, set()))
                        callee_reads.update(reads_map.get(fqn, set()))

                for struct_type in callee_writes:
                    if caller not in writes_map:
                        writes_map[caller] = set()
                    if struct_type not in writes_map[caller]:
                        writes_map[caller].add(struct_type)
                        changed = True
                        propagated_writes += 1

                for struct_type in callee_reads:
                    if caller not in reads_map:
                        reads_map[caller] = set()
                    if struct_type not in reads_map[caller]:
                        reads_map[caller].add(struct_type)
                        changed = True
                        propagated_reads += 1

    for file_ctx in ctx.source_files.values():
        func_names_in_file = {f.args[0] for f in file_ctx.facts if f.name == "Fun"}
        for func_name in func_names_in_file:
            for struct_type in writes_map.get(func_name, set()):
                write_fact = Fact("WritesUserAsset", (func_name, struct_type))
                if write_fact not in file_ctx.facts:
                    file_ctx.facts.append(write_fact)
            for struct_type in reads_map.get(func_name, set()):
                read_fact = Fact("ReadsUserAsset", (func_name, struct_type))
                if read_fact not in file_ctx.facts:
                    file_ctx.facts.append(read_fact)

    if propagated_writes > 0 or propagated_reads > 0:
        debug(
            f"Propagated {propagated_writes} WritesUserAsset and {propagated_reads} ReadsUserAsset in {iteration} iterations"
        )

    return writes_count + propagated_writes, reads_count + propagated_reads
