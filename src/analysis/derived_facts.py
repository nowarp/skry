"""
Derived facts computation (Pass 2.5).

Computes facts that require joining base facts from multiple files:
- OperatesOnSharedObject: function has &mut param to shared object type
- OperatesOnOwnedOnly: function has &mut params but all are owned
- TransfersUserProvidedValue: function transfers user-provided Coin/Balance
- TransfersUserAsset: function transfers user-owned asset type
- TransfersFromSharedObject: function extracts value from shared object param

These derived facts enable expressing structural filters as Hy rule predicates
instead of computing them on-the-fly in Python check functions.
"""

from typing import Set, Dict, List, Tuple
from core.context import ProjectContext
from core.facts import Fact
from core.utils import debug, get_simple_name
from analysis.patterns import collect_creation_sites
from analysis.call_graph import build_global_call_graph, propagate_to_callers
from move.types import extract_base_type


def compute_derived_facts(ctx: ProjectContext) -> None:
    """
    Compute derived facts from base facts.

    Must run AFTER:
    - Pass 1 (structural facts including FormalArg, IsSharedObject)
    - Pass 2 (semantic facts including IsUserAsset)

    Adds derived facts to each file's fact list.
    """

    # Collect global IsSharedObject types from ALL files
    shared_types = _collect_shared_types(ctx)
    debug(f"  Shared object types: {shared_types}")

    # Collect IsUserAsset types from semantic facts
    user_asset_types = _collect_user_asset_types(ctx)
    debug(f"  User asset types: {user_asset_types}")

    total_derived = 0

    for file_path, file_ctx in ctx.source_files.items():
        derived = []

        # Compute OperatesOnSharedObject / OperatesOnOwnedOnly
        shared_ops, owned_only_ops = _compute_shared_object_facts(file_ctx.facts, shared_types)
        derived.extend(shared_ops)
        derived.extend(owned_only_ops)

        # Compute TransfersUserProvidedValue
        user_value_facts = _compute_user_provided_value_facts(file_ctx.facts)
        derived.extend(user_value_facts)

        # Compute TransfersUserAsset
        user_asset_facts = _compute_user_asset_transfer_facts(file_ctx.facts, user_asset_types)
        derived.extend(user_asset_facts)

        # Compute TransfersFromSender
        transfers_from_sender_facts = _compute_transfers_from_sender_facts(file_ctx.facts)
        derived.extend(transfers_from_sender_facts)

        # Compute HasSenderEqualityCheck
        has_sender_equality_check_facts = _compute_has_sender_equality_check_facts(file_ctx.facts)
        derived.extend(has_sender_equality_check_facts)

        # Compute TransfersFromSharedObject
        # Pass combined facts to include OperatesOnSharedObject computed earlier
        all_facts = file_ctx.facts + derived
        transfers_from_shared_facts = _compute_transfers_from_shared_object_facts(all_facts, shared_types)
        derived.extend(transfers_from_shared_facts)

        # Compute ValueExchangeFunction
        value_exchange_facts = _compute_value_exchange_facts(file_ctx.facts)
        derived.extend(value_exchange_facts)

        # Add derived facts to file's fact list
        file_ctx.facts.extend(derived)
        total_derived += len(derived)

        # Also update global_facts_index for derived facts
        for fact in derived:
            if len(fact.args) >= 1:
                func_name = fact.args[0]
                if func_name in ctx.global_facts_index:
                    if file_path in ctx.global_facts_index[func_name]:
                        # Only add if not already present
                        if fact not in ctx.global_facts_index[func_name][file_path]:
                            ctx.global_facts_index[func_name][file_path].append(fact)

    # Compute struct creation pattern facts (IsUserCreatable)
    creation_pattern_facts = _compute_creation_pattern_facts(ctx)
    total_derived += len(creation_pattern_facts)

    debug(f"  Generated {total_derived} derived facts")


def recompute_transfers_from_sender(ctx: ProjectContext) -> None:
    """
    Recompute TransfersFromSender facts after cross-module taint propagation.

    Must run AFTER propagate_taint_across_modules() which creates TrackedDerived
    facts for cross-module sender-derived variables.

    This enables Pattern 3 detection (sender-derived var in transfer recipient via CallArg)
    for wrapper functions that call helpers in other modules.
    """
    total_new = 0

    for file_path, file_ctx in ctx.source_files.items():
        # Remove existing TransfersFromSender facts (will regenerate)
        old_tfs = [f for f in file_ctx.facts if f.name == "TransfersFromSender"]
        for f in old_tfs:
            file_ctx.facts.remove(f)

        # Recompute with updated TrackedDerived facts
        transfers_from_sender_facts = _compute_transfers_from_sender_facts(file_ctx.facts)

        file_ctx.facts.extend(transfers_from_sender_facts)
        total_new += len(transfers_from_sender_facts)

        # Update global_facts_index
        for fact in transfers_from_sender_facts:
            func_name = fact.args[0]
            if func_name in ctx.global_facts_index:
                if file_path in ctx.global_facts_index[func_name]:
                    if fact not in ctx.global_facts_index[func_name][file_path]:
                        ctx.global_facts_index[func_name][file_path].append(fact)

    if total_new > 0:
        debug(f"  Recomputed {total_new} TransfersFromSender facts")


def _collect_shared_types(ctx: ProjectContext) -> Set[str]:
    """Collect all shared object type names from IsSharedObject facts.

    Returns FQNs only. Downstream matching handles simple name resolution.
    """
    shared_types: Set[str] = set()

    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "IsSharedObject":
                shared_types.add(fact.args[0])

    return shared_types


def _collect_user_asset_types(ctx: ProjectContext) -> Set[str]:
    """Collect user asset type names from IsUserAsset semantic facts."""
    user_asset_types: Set[str] = set()

    for fact in ctx.semantic_facts:
        if fact.name == "IsUserAsset" and len(fact.args) >= 2 and fact.args[1] is True:
            struct_name = fact.args[0]
            user_asset_types.add(struct_name)
            if "::" in struct_name:
                user_asset_types.add(get_simple_name(struct_name))

    return user_asset_types


def _compute_shared_object_facts(
    facts: List[Fact],
    shared_types: Set[str],
) -> tuple[List[Fact], List[Fact]]:
    """
    Compute OperatesOnSharedObject and OperatesOnOwnedOnly facts.

    Returns (shared_facts, owned_only_facts).
    """
    # Build simple name set for matching (shared_types contains FQNs)
    shared_simple_names: Set[str] = set()
    for fqn in shared_types:
        shared_simple_names.add(get_simple_name(fqn))

    # Collect &mut param types per function
    func_mut_params: Dict[str, List[str]] = {}  # func_name -> [base_types]

    for fact in facts:
        if fact.name == "FormalArg":
            func_name = fact.args[0]
            param_type = fact.args[3]

            if param_type.startswith("&mut "):
                base_type = extract_base_type(param_type)
                if func_name not in func_mut_params:
                    func_mut_params[func_name] = []
                func_mut_params[func_name].append(base_type)

    shared_facts = []
    owned_only_facts = []

    for func_name, mut_types in func_mut_params.items():
        # Match against simple names (base_type is already simple from extract_base_type)
        has_shared = any(t in shared_simple_names for t in mut_types)

        if has_shared:
            shared_facts.append(Fact("OperatesOnSharedObject", (func_name,)))
        else:
            # Has &mut params but none are shared -> operates on owned only
            owned_only_facts.append(Fact("OperatesOnOwnedOnly", (func_name,)))

    return shared_facts, owned_only_facts


def _compute_user_provided_value_facts(facts: List[Fact]) -> List[Fact]:
    """
    Compute TransfersUserProvidedValue facts.

    A function has this property if:
    1. It has TaintedTransferValue or TaintedStateWrite facts
    2. ALL tainted value sources are Coin<T> or Balance<T> owned params

    This includes both transfers AND state writes (e.g., balance::join) where
    the value comes from user's owned coins/balances.
    """
    # Build func -> param_name -> param_type map
    func_params: Dict[str, Dict[str, str]] = {}
    for fact in facts:
        if fact.name == "FormalArg":
            func_name, _, param_name, param_type = fact.args
            if func_name not in func_params:
                func_params[func_name] = {}
            func_params[func_name][param_name] = param_type

    # Collect TaintedAtSink with transfer_value or state_write per function
    func_value_sources: Dict[str, List[str]] = {}  # func_name -> [source_params]
    for fact in facts:
        # TaintedAtSink(func_name, source, stmt_id, sink_type, cap)
        if fact.name == "TaintedAtSink":
            func_name, source_param, _, sink_type, _ = fact.args
            if sink_type in ("transfer_value", "state_write"):
                if func_name not in func_value_sources:
                    func_value_sources[func_name] = []
                func_value_sources[func_name].append(source_param)

    result_facts = []

    for func_name, sources in func_value_sources.items():
        if func_name not in func_params:
            continue

        # Check if ALL sources are owned Coin/Balance params
        all_user_value = True
        for source in sources:
            if source not in func_params[func_name]:
                all_user_value = False
                break

            param_type = func_params[func_name][source]

            # Must be owned (no &)
            if param_type.startswith("&"):
                all_user_value = False
                break

            # Must be Coin or Balance
            if "Coin<" not in param_type and "Balance<" not in param_type:
                all_user_value = False
                break

        if all_user_value and sources:
            result_facts.append(Fact("TransfersUserProvidedValue", (func_name,)))

    return result_facts


def _compute_user_asset_transfer_facts(
    facts: List[Fact],
    user_asset_types: Set[str],
) -> List[Fact]:
    """
    Compute TransfersUserAsset facts.

    A function has this property if:
    1. It has TaintedTransferValue facts
    2. The source param type is in IsUserAsset set
    """
    if not user_asset_types:
        return []

    # Build func -> param_name -> param_type map
    func_params: Dict[str, Dict[str, str]] = {}
    for fact in facts:
        if fact.name == "FormalArg":
            func_name, _, param_name, param_type = fact.args
            if func_name not in func_params:
                func_params[func_name] = {}
            func_params[func_name][param_name] = param_type

    result_facts = []
    seen: Set[tuple] = set()

    for fact in facts:
        # TaintedAtSink(func_name, source, stmt_id, sink_type, cap)
        if fact.name == "TaintedAtSink" and fact.args[3] == "transfer_value":
            func_name, source_param, _, _, _ = fact.args

            if func_name not in func_params:
                continue
            if source_param not in func_params[func_name]:
                continue

            param_type = func_params[func_name][source_param]

            # Must be owned (no &)
            if param_type.startswith("&"):
                continue

            base_type = extract_base_type(param_type)

            if base_type in user_asset_types:
                key = (func_name, base_type)
                if key not in seen:
                    seen.add(key)
                    result_facts.append(Fact("TransfersUserAsset", (func_name, base_type)))

    return result_facts


def _compute_transfers_from_sender_facts(facts: List[Fact]) -> List[Fact]:
    """
    Compute TransfersFromSender facts.

    A function has this property if:
    1. It has DirectSenderInTransfer fact (transfer recipient is direct sender call)
    2. OR sender-derived vars are used in a transfer sink (via SinkUsesVar)
    3. OR sender-derived vars are used as transfer recipient (via CallArg)

    This detects when sender-derived value is used as transfer recipient,
    indicating the function transfers value to the sender's address.
    """
    from move.taint_facts import is_transfer_sink, get_transfer_recipient_arg_index

    result_funcs: Set[str] = set()

    # Pattern 1: Direct sender call in transfer recipient
    # e.g., transfer::public_transfer(coin, tx_context::sender(ctx))
    for fact in facts:
        if fact.name == "DirectSenderInTransfer":
            func_name, _ = fact.args
            result_funcs.add(func_name)

    # Pattern 2: Sender-derived var used in transfer sink
    # e.g., let user = tx_context::sender(ctx); transfer::public_transfer(coin, user)
    sender_derived: Dict[str, Set[str]] = {}  # func_name -> set of sender-derived vars
    for fact in facts:
        if fact.name == "TrackedDerived" and fact.args[2] == "sender":
            func_name, var, _ = fact.args
            if func_name not in sender_derived:
                sender_derived[func_name] = set()
            sender_derived[func_name].add(var)

    if sender_derived:
        # Collect SinkUsesVar facts per function
        func_sink_vars: Dict[str, Set[str]] = {}  # func_name -> set of vars used in sinks
        for fact in facts:
            if fact.name == "SinkUsesVar":
                func_name, _, var_name, _ = fact.args
                if func_name not in func_sink_vars:
                    func_sink_vars[func_name] = set()
                func_sink_vars[func_name].add(var_name)

        for func_name, sender_vars in sender_derived.items():
            if func_name in func_sink_vars:
                if sender_vars & func_sink_vars[func_name]:
                    result_funcs.add(func_name)

        # Pattern 3: Sender-derived var used as transfer recipient via CallArg
        # CallArg is always generated, more reliable than SinkUsesVar for this case
        # e.g., CallArg(func, stmt, "transfer::public_transfer", 1, ("user",))
        for fact in facts:
            if fact.name == "CallArg":
                func_name, _, callee, arg_idx, arg_vars = fact.args
                if is_transfer_sink(callee):
                    recipient_idx = get_transfer_recipient_arg_index(callee)
                    # Check if this is the recipient argument position
                    # recipient_idx is -1 for last arg, -2 for second-to-last
                    is_recipient_arg = False
                    if recipient_idx == -1 and arg_idx == 1:
                        # Last arg for 2-arg transfer (coin, recipient)
                        is_recipient_arg = True
                    elif recipient_idx >= 0 and arg_idx == recipient_idx:
                        is_recipient_arg = True

                    if is_recipient_arg:
                        for var in arg_vars:
                            if func_name in sender_derived and var in sender_derived[func_name]:
                                result_funcs.add(func_name)

    return [Fact("TransfersFromSender", (func_name,)) for func_name in result_funcs]


def _compute_has_sender_equality_check_facts(facts: List[Fact]) -> List[Fact]:
    """
    Compute HasSenderEqualityCheck facts.

    A function has this property if:
    1. It has sender-derived vars (TrackedDerived with source_type="sender")
       AND those vars appear in a SanitizedByAssert or ConditionCheck fact
    2. OR it has SenderCallInAssertion fact (direct tx_context::sender() call in assertion)

    This detects patterns like:
    - assert!(owner == sender, ERR) where sender = tx_context::sender(ctx)
    - assert!(tx_context::sender(ctx) == @admin, 0)  [direct call in assertion]
    - no_permission_error(metadata.owner() == issuer) where issuer = ctx.sender()

    The key insight: if sender appears in a comparison/assertion context,
    it's being used for ownership verification.
    """
    # Track functions with direct sender calls in assertions
    direct_sender_checks: Set[str] = set()
    for fact in facts:
        if fact.name == "SenderCallInAssertion":
            func_name, _ = fact.args
            direct_sender_checks.add(func_name)

    # Collect sender-derived vars per function
    sender_derived: Dict[str, Set[str]] = {}
    for fact in facts:
        if fact.name == "TrackedDerived" and fact.args[2] == "sender":
            func_name, var, _ = fact.args
            if func_name not in sender_derived:
                sender_derived[func_name] = set()
            sender_derived[func_name].add(var)

    # Collect vars that appear in assertions/conditions
    vars_in_checks: Dict[str, Set[str]] = {}  # func_name -> vars in checks
    for fact in facts:
        if fact.name == "SanitizedByAssert":
            # SanitizedByAssert(func_name, stmt_id, var)
            func_name, _, var = fact.args
            if func_name not in vars_in_checks:
                vars_in_checks[func_name] = set()
            vars_in_checks[func_name].add(var)
        elif fact.name == "ConditionCheck":
            if len(fact.args) == 3:
                func_name, _, cond_vars = fact.args
                if func_name not in vars_in_checks:
                    vars_in_checks[func_name] = set()
                if isinstance(cond_vars, (tuple, list)):
                    for v in cond_vars:
                        vars_in_checks[func_name].add(v)

    result_facts = []

    for func_name in direct_sender_checks:
        result_facts.append(Fact("HasSenderEqualityCheck", (func_name,)))

    for func_name, sender_vars in sender_derived.items():
        if func_name in direct_sender_checks:
            continue
        if func_name not in vars_in_checks:
            continue

        # Check if any sender-derived var appears in a check
        if sender_vars & vars_in_checks[func_name]:
            result_facts.append(Fact("HasSenderEqualityCheck", (func_name,)))

    return result_facts


def _compute_transfers_from_shared_object_facts(
    facts: List[Fact],
    shared_types: Set[str],
) -> List[Fact]:
    """
    Compute TransfersFromSharedObject facts.

    TransfersFromSharedObject(func, source_param, shared_type)

    Generated when function extracts value from a shared object param.
    Indicates value is extracted from protocol storage (dangerous for drain).

    Detection methods:
    1. TaintedTransferValue source param is a shared object type
    2. FieldAssign shows value coming from a shared object param's field
    3. HasValueExtraction + OperatesOnSharedObject combination
    """
    # Build simple name set for matching (shared_types contains FQNs)
    shared_simple_names: Set[str] = set()
    for fqn in shared_types:
        shared_simple_names.add(get_simple_name(fqn))

    # Build func -> param_name -> param_type map
    func_params: Dict[str, Dict[str, str]] = {}
    for fact in facts:
        if fact.name == "FormalArg":
            func_name, _, param_name, param_type = fact.args
            if func_name not in func_params:
                func_params[func_name] = {}
            func_params[func_name][param_name] = param_type

    result_facts = []
    seen: Set[tuple] = set()

    def is_shared_type(base_type: str) -> bool:
        """Check if base_type matches any shared type (by simple name)."""
        return base_type in shared_simple_names

    # Collect functions that directly extract value (call coin::take, etc.)
    value_extraction_funcs = {f.args[0] for f in facts if f.name == "HasValueExtraction"}

    # Method 1: TaintedAtSink with transfer_value where source param is shared object
    # ONLY if the function directly extracts value (not via IPA)
    for fact in facts:
        # TaintedAtSink(func_name, source, stmt_id, sink_type, cap)
        if fact.name == "TaintedAtSink" and fact.args[3] == "transfer_value":
            func_name, source_param, _, _, _ = fact.args

            # Skip if extraction happens in callee (not direct)
            if func_name not in value_extraction_funcs:
                continue

            if func_name not in func_params:
                continue
            if source_param not in func_params[func_name]:
                continue

            param_type = func_params[func_name][source_param]

            # Must be borrowed (&mut) - extracting from shared storage
            if not param_type.startswith("&mut "):
                continue

            base_type = extract_base_type(param_type)

            if is_shared_type(base_type):
                key = (func_name, source_param, base_type)
                if key not in seen:
                    seen.add(key)
                    result_facts.append(Fact("TransfersFromSharedObject", (func_name, source_param, base_type)))

    # Method 2: FieldAssign shows value from shared object param
    # FieldAssign(func, stmt, result, source_param, field)
    # ONLY if the function directly extracts value (not via IPA)
    for fact in facts:
        if fact.name == "FieldAssign":
            func_name, _, _, source_param, _ = fact.args

            # Skip if extraction happens in callee (not direct)
            if func_name not in value_extraction_funcs:
                continue

            if func_name not in func_params:
                continue
            if source_param not in func_params[func_name]:
                continue

            param_type = func_params[func_name][source_param]

            # Must be borrowed (&mut) - extracting from shared storage
            if not param_type.startswith("&mut "):
                continue

            base_type = extract_base_type(param_type)

            if is_shared_type(base_type):
                key = (func_name, source_param, base_type)
                if key not in seen:
                    seen.add(key)
                    result_facts.append(Fact("TransfersFromSharedObject", (func_name, source_param, base_type)))

    # Method 3: AmountExtractionSink + OperatesOnSharedObject
    # This catches cases where extraction method isn't directly traceable
    # NOTE: We use AmountExtractionSink (coin::take, balance::split) not HasValueExtraction
    # because HasValueExtraction includes ValueExtractionSink which covers conversions
    # like coin::from_balance that don't actually extract from shared storage.
    direct_extraction_funcs = set()
    operates_on_shared_funcs = set()

    for fact in facts:
        if fact.name == "AmountExtractionSink" and len(fact.args) >= 1:
            direct_extraction_funcs.add(fact.args[0])
        elif fact.name == "OperatesOnSharedObject" and len(fact.args) >= 1:
            operates_on_shared_funcs.add(fact.args[0])

    for func_name in direct_extraction_funcs & operates_on_shared_funcs:
        if func_name in func_params:
            # Find which param is the shared object
            for param_name, param_type in func_params[func_name].items():
                if param_type.startswith("&mut "):
                    base_type = extract_base_type(param_type)
                    if is_shared_type(base_type):
                        key = (func_name, param_name, base_type)
                        if key not in seen:
                            seen.add(key)
                            result_facts.append(Fact("TransfersFromSharedObject", (func_name, param_name, base_type)))

    return result_facts


def _compute_value_exchange_facts(facts: List[Fact]) -> List[Fact]:
    """
    Compute ValueExchangeFunction facts.

    A function has this property if:
    1. It has an owned Coin<T> or Balance<T> parameter (input value)
    2. It returns Coin<T> or Balance<T> (output value)

    This indicates a value exchange/swap pattern where user provides value
    and receives value back (e.g., refund, change, swap). Such functions
    are safe from the returns-coin-without-auth perspective.
    """
    # Build func -> param_types map
    func_params: Dict[str, List[str]] = {}
    for fact in facts:
        if fact.name == "FormalArg":
            func_name, _, _, param_type = fact.args
            if func_name not in func_params:
                func_params[func_name] = []
            func_params[func_name].append(param_type)

    # Build func -> return_type map
    func_returns: Dict[str, str] = {}
    for fact in facts:
        if fact.name == "ReturnsCoinType":
            func_name, return_type = fact.args
            func_returns[func_name] = return_type

    result_facts = []

    for func_name in func_returns:
        if func_name not in func_params:
            continue

        # Check if function has owned Coin<T> or Balance<T> parameter
        has_coin_param = False
        for param_type in func_params[func_name]:
            # Must be owned (no &)
            if param_type.startswith("&"):
                continue
            # Check for Coin or Balance
            if "Coin<" in param_type or "Balance<" in param_type:
                has_coin_param = True
                break

        if has_coin_param:
            result_facts.append(Fact("ValueExchangeFunction", (func_name,)))

    return result_facts


def _compute_creation_pattern_facts(ctx: ProjectContext) -> List[Fact]:
    """
    Compute IsUserCreatable facts for structs created in public non-init functions.

    A struct is user-creatable if ANY creation site is in a public non-init function
    that has no sender/role checks, meaning anyone can mint their own instance.

    If the creator function checks sender or requires a role (directly or transitively),
    it's not user-creatable.
    """
    creation_sites = collect_creation_sites(ctx)
    if not creation_sites:
        return []

    public_funcs: Set[str] = set()
    direct_protected: Set[str] = set()  # Functions with direct HasSenderEqualityCheck or ChecksCapability
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "IsPublic":
                public_funcs.add(fact.args[0])
            elif fact.name in ("HasSenderEqualityCheck", "ChecksCapability"):
                direct_protected.add(fact.args[0] if fact.name == "HasSenderEqualityCheck" else fact.args[1])

    # Compute transitively protected functions (callers of protected functions)
    call_graph = build_global_call_graph(ctx)
    protected_funcs = propagate_to_callers(direct_protected, call_graph)

    new_facts: List[Fact] = []

    for struct_name, sites in creation_sites.items():
        if not sites:
            continue

        # User-creatable: public non-init creator WITHOUT sender/role checks
        has_unprotected_public_creator = any(
            not site.is_init and site.func_name in public_funcs and site.func_name not in protected_funcs
            for site in sites
        )

        if has_unprotected_public_creator:
            fact = Fact("IsUserCreatable", (struct_name,))
            new_facts.append(fact)
            debug(f"  {struct_name} -> IsUserCreatable")

            # Add to the file that defines the struct
            for file_ctx in ctx.source_files.values():
                if any(f.name == "Struct" and f.args[0] == struct_name for f in file_ctx.facts):
                    file_ctx.facts.append(fact)
                    break

    if new_facts:
        debug(f"  Creation patterns: {len(new_facts)} user-creatable")

    return new_facts


def generate_has_privileged_setter_facts(ctx: ProjectContext) -> int:
    """
    Generate HasPrivilegedSetter facts for mutable config fields with proper setters.

    A field has a privileged setter if there exists a non-init function that:
    1. Writes to the field (WritesField)
    2. Is gated by a privileged role (ChecksCapability with IsPrivileged role) OR checks sender

    Returns number of facts generated.
    """
    # Collect privileged roles from ALL files
    privileged_roles: Set[str] = set()
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "IsPrivileged":
                privileged_roles.add(fact.args[0])

    debug(f"  Privileged roles: {privileged_roles}")

    # Collect init functions from ALL files
    init_funcs: Set[str] = set()
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "IsInit":
                init_funcs.add(fact.args[0])

    # Collect ALL ChecksCapability facts globally (keyed by function name)
    checks_role_facts: Dict[str, List[str]] = {}
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "ChecksCapability":
                role_type, checked_func = fact.args
                if checked_func not in checks_role_facts:
                    checks_role_facts[checked_func] = []
                checks_role_facts[checked_func].append(role_type)

    # Collect ALL HasSenderEqualityCheck facts globally
    has_sender_check_funcs: Set[str] = set()
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "HasSenderEqualityCheck":
                has_sender_check_funcs.add(fact.args[0])

    # Track (struct, field) pairs with privileged setters
    has_setter: Set[Tuple[str, str]] = set()

    # Find functions that write to fields (directly or transitively)
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name in ("WritesField", "TransitiveWritesField"):
                if fact.name == "WritesField":
                    func_name, struct_type, field_path = fact.args
                else:  # TransitiveWritesField
                    func_name, struct_type, field_path, _ = fact.args

                # Skip init functions
                if func_name in init_funcs:
                    continue

                # Check if function has privileged role param (using global index)
                has_priv_role = False
                if func_name in checks_role_facts:
                    for role_type in checks_role_facts[func_name]:
                        if role_type in privileged_roles:
                            has_priv_role = True
                            break

                # Check if function checks sender (using global index)
                checks_sender = func_name in has_sender_check_funcs

                if has_priv_role or checks_sender:
                    # Add both the full field path AND the top-level field
                    # This handles nested writes like cfg.settings.inner.set(v)
                    # where IsMutableConfigField("Config", "settings") should match
                    key = (struct_type, field_path)
                    has_setter.add(key)

                    # Also add top-level field for nested paths
                    top_level_field = field_path.split(".")[0]
                    if top_level_field != field_path:
                        has_setter.add((struct_type, top_level_field))

                    via_info = f" via {fact.args[3]}" if fact.name == "TransitiveWritesField" else ""
                    debug(
                        f"  {struct_type}.{field_path} has privileged setter: {func_name}{via_info} "
                        f"(role={has_priv_role}, sender={checks_sender})"
                    )

    # Generate HasPrivilegedSetter facts
    count = 0
    for struct_type, field_path in has_setter:
        # Add fact to the file that defines the struct
        for file_ctx in ctx.source_files.values():
            if any(f.name == "Struct" and f.args[0] == struct_type for f in file_ctx.facts):
                # Avoid duplicates
                if not any(
                    f.name == "HasPrivilegedSetter" and f.args[0] == struct_type and f.args[1] == field_path
                    for f in file_ctx.facts
                ):
                    setter_fact = Fact("HasPrivilegedSetter", (struct_type, field_path))
                    file_ctx.facts.append(setter_fact)
                    count += 1
                break

    if count > 0:
        debug(f"  Generated {count} HasPrivilegedSetter facts")

    return count


def generate_writes_protocol_invariant_facts(ctx: ProjectContext) -> int:
    """
    Generate WritesProtocolInvariant facts for violations of protocol invariants.

    A violation occurs when a non-init function writes to a field marked as
    IsProtocolInvariant. Protocol invariants should only be set during initialization.

    Returns number of facts generated.
    """
    # Collect init functions from ALL files
    init_funcs: Set[str] = set()
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "IsInit":
                init_funcs.add(fact.args[0])

    # Collect protocol invariant fields: (struct_type, field_path)
    invariant_fields: Set[Tuple[str, str]] = set()
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "FieldClassification" and len(fact.args) == 6:
                # FieldClassification(struct_type, field_path, category, negative, confidence, reason)
                struct_type, field_path, category, negative = fact.args[0], fact.args[1], fact.args[2], fact.args[3]
                # Only include positive protocol_invariant classifications
                if category == "protocol_invariant" and not negative:
                    invariant_fields.add((struct_type, field_path))

    if not invariant_fields:
        return 0

    debug(f"  Protocol invariant fields: {invariant_fields}")

    # Find non-init functions that write to invariant fields
    violations: List[Tuple[str, str, str, str]] = []  # (func, struct, field, file_path)

    for file_path, file_ctx in ctx.source_files.items():
        for fact in file_ctx.facts:
            if fact.name == "WritesField":
                func_name, struct_type, field_path = fact.args

                # Skip init functions
                if func_name in init_funcs:
                    continue

                # Check if this is a protocol invariant field
                if (struct_type, field_path) in invariant_fields:
                    violations.append((func_name, struct_type, field_path, file_path))
                    debug(f"  Violation: {func_name} writes to invariant {struct_type}.{field_path}")

    # Generate WritesProtocolInvariant facts
    count = 0
    for func_name, struct_type, field_path, file_path in violations:
        file_ctx = ctx.source_files[file_path]
        # Avoid duplicates
        if not any(
            f.name == "WritesProtocolInvariant"
            and f.args[0] == func_name
            and f.args[1] == struct_type
            and f.args[2] == field_path
            for f in file_ctx.facts
        ):
            violation_fact = Fact("WritesProtocolInvariant", (func_name, struct_type, field_path))
            file_ctx.facts.append(violation_fact)
            count += 1

    if count > 0:
        debug(f"  Generated {count} WritesProtocolInvariant facts")

    return count
