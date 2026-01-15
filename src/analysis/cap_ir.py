"""
Capability IR foundation - Address class computation.

cap_ir is NOT a separate IR - it's derived views computed on-demand from facts.
This module computes AddressSource facts that classify where address values come from,
enabling semantic reasoning about capability ownership and authorization.

AddressClass classification:
- deployer: sender() in init (package deployer)
- tx_sender: sender() at runtime (caller)
- literal: hardcoded @0x... address
- field_of: address stored in object field
- unknown: cannot determine statically
"""

from enum import Enum
from typing import TYPE_CHECKING, Dict, List, Set, Tuple

from core.facts import Fact, names_match
from core.utils import debug

if TYPE_CHECKING:
    from core.context import ProjectContext


class AddressClass(Enum):
    """Classification of address value origin."""

    DEPLOYER = "deployer"  # sender() in init - package deployer
    TX_SENDER = "tx_sender"  # sender() at runtime - caller
    LITERAL = "literal"  # hardcoded @0x... address
    FIELD_OF = "field_of"  # stored in object field
    UNKNOWN = "unknown"  # cannot determine statically


def compute_address_sources(ctx: "ProjectContext") -> None:
    """
    Compute AddressSource facts from taint sources and IR analysis.

    Detection logic:
    1. TrackedSource with source="sender" in init functions -> DEPLOYER
    2. TrackedSource with source="sender" elsewhere -> TX_SENDER
    3. Literal address values from ConstDef -> LITERAL
    4. Field reads from owner/authority fields -> FIELD_OF

    Init context includes both IsInit functions (actual init) and InitImpl
    functions (transitively called from init). Both are considered "deployer
    context" since they execute at package deployment time.

    Examples:
        DEPLOYER:
            fun init(ctx: &mut TxContext) {
                let deployer = tx_context::sender(ctx);  // -> DEPLOYER
            }

        TX_SENDER:
            public entry fun withdraw(ctx: &mut TxContext) {
                let caller = tx_context::sender(ctx);  // -> TX_SENDER
            }

    Limitations:
        - Currently intraprocedural only - does not track address values
          returned from helper functions. If `get_deployer()` returns
          `sender()`, the caller won't see it as DEPLOYER.

    Adds AddressSource facts to file context.
    """
    # Collect init functions
    init_funcs: Set[str] = set()
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "IsInit":
                init_funcs.add(fact.args[0])

    # Collect InitImpl functions (transitively called by init)
    init_impl_funcs: Set[str] = set()
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "InitImpl":
                init_impl_funcs.add(fact.args[0])

    # Combined: init + init_impl are all "deployer context"
    deployer_context_funcs = init_funcs | init_impl_funcs

    count = 0

    for file_path, file_ctx in ctx.source_files.items():
        new_facts = []

        for fact in file_ctx.facts:
            # TrackedSource(func_name, stmt_id, result_var, source_type, callee)
            if fact.name == "TrackedSource" and fact.args[3] == "sender":
                func_name, stmt_id, result_var, _, callee = fact.args

                # Classify: init context -> DEPLOYER, otherwise -> TX_SENDER
                if func_name in deployer_context_funcs:
                    address_class = AddressClass.DEPLOYER.value
                    details = f"sender() in init via {callee}"
                else:
                    address_class = AddressClass.TX_SENDER.value
                    details = f"sender() via {callee}"

                address_fact = Fact(
                    "AddressSource",
                    (func_name, result_var, address_class, details),
                )
                if address_fact not in file_ctx.facts and address_fact not in new_facts:
                    new_facts.append(address_fact)
                    debug(f"  AddressSource({func_name}, {result_var}, {address_class})")

            # ConstDef for address literals
            # ConstDef(qualified_name, simple_name, value, const_type)
            elif fact.name == "ConstDef" and fact.args[3] == "address":
                # This is a module-level constant, not function-scoped
                # We'll track it separately when we see it used
                pass

            # FieldAssign for reading from owner/authority fields
            # FieldAssign(func_name, stmt_id, target_var, base_var, field)
            elif fact.name == "FieldAssign":
                func_name, stmt_id, target_var, base_var, field_name = fact.args

                # Check if field is an owner/authority field (from LLM classification)
                # Look for FieldClassification facts with category="privileged_address"
                is_owner_field = False
                for f in file_ctx.facts:
                    if (
                        f.name == "FieldClassification"
                        and len(f.args) == 6
                        and f.args[2] == "privileged_address"
                        and not f.args[3]
                    ):
                        field_path = f.args[1]
                        if field_path == field_name or field_path.endswith(f".{field_name}"):
                            is_owner_field = True
                            break

                if is_owner_field:
                    address_fact = Fact(
                        "AddressSource",
                        (func_name, target_var, AddressClass.FIELD_OF.value, f"{base_var}.{field_name}"),
                    )
                    if address_fact not in file_ctx.facts and address_fact not in new_facts:
                        new_facts.append(address_fact)
                        debug(f"  AddressSource({func_name}, {target_var}, field_of, {base_var}.{field_name})")

        # Also propagate address class through TrackedDerived
        # If var is derived from a sender var, it inherits the address class
        _propagate_address_class(file_ctx.facts, new_facts, deployer_context_funcs)

        file_ctx.facts.extend(new_facts)
        count += len(new_facts)

    if count > 0:
        debug(f"Generated {count} AddressSource facts")


def _propagate_address_class(
    facts: list,
    new_facts: list,
    deployer_context_funcs: Set[str],
) -> None:
    """Propagate address class through TrackedDerived chains."""
    # Build map: func -> var -> AddressSource
    existing_sources: Dict[str, Dict[str, tuple]] = {}

    for fact in facts + new_facts:
        if fact.name == "AddressSource":
            func_name, var, addr_class, details = fact.args
            if func_name not in existing_sources:
                existing_sources[func_name] = {}
            existing_sources[func_name][var] = (addr_class, details)

    # TrackedDerived(func_name, var, source_type)
    # TrackedDerivedFrom(func_name, var, source_type, callee)
    for fact in facts:
        if fact.name == "TrackedDerived" and fact.args[2] == "sender":
            func_name, var, _ = fact.args

            # Skip if already has AddressSource
            if func_name in existing_sources and var in existing_sources[func_name]:
                continue

            # Determine address class based on function context
            if func_name in deployer_context_funcs:
                address_class = AddressClass.DEPLOYER.value
                details = "derived from sender in init"
            else:
                address_class = AddressClass.TX_SENDER.value
                details = "derived from sender"

            address_fact = Fact("AddressSource", (func_name, var, address_class, details))
            if address_fact not in new_facts:
                new_facts.append(address_fact)


def derive_cap_ownership(ctx: "ProjectContext") -> None:
    """
    Derive CapabilityOwner facts from TransfersToSender + IsInit patterns.

    A capability type is owned by DEPLOYER if:
    1. It's an IsCapability type
    2. It has TransfersToSender in init (transferred to deployer)

    Adds CapabilityOwner facts to file context.
    """
    # Collect roles
    role_types: Set[str] = set()
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "IsCapability":
                role_types.add(fact.args[0])

    if not role_types:
        return

    # Collect init functions
    init_funcs: Set[str] = set()
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "IsInit":
                init_funcs.add(fact.args[0])

    # Collect InitImpl functions
    init_impl_funcs: Set[str] = set()
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "InitImpl":
                init_impl_funcs.add(fact.args[0])

    deployer_context_funcs = init_funcs | init_impl_funcs

    # Collect TransfersToSender in init context
    # TransfersToSender(func_name, struct_type)
    deployer_owned_caps: Set[str] = set()
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "TransfersToSender":
                func_name, struct_type = fact.args
                if func_name in deployer_context_funcs:
                    # Check if struct_type is a role
                    if struct_type in role_types:
                        deployer_owned_caps.add(struct_type)

    # Generate CapabilityOwner facts
    count = 0
    for cap_type in deployer_owned_caps:
        # Find the file that defines this role
        for file_ctx in ctx.source_files.values():
            if any(f.name == "IsCapability" and f.args[0] == cap_type for f in file_ctx.facts):
                owner_fact = Fact("CapabilityOwner", (cap_type, AddressClass.DEPLOYER.value))
                if owner_fact not in file_ctx.facts:
                    file_ctx.facts.append(owner_fact)
                    count += 1
                    debug(f"  CapabilityOwner({cap_type}, deployer)")
                break

    if count > 0:
        debug(f"Generated {count} CapabilityOwner facts")


def detect_capability_takeover(ctx: "ProjectContext") -> None:
    """
    Detect CapabilityTakeover patterns where capabilities can be acquired by unauthorized addresses.

    Attack vector:
        A capability created for Deployer in init can be transferred to TxSender
        through an unguarded public/entry function.

    Detection logic:
    1. Find capabilities owned by Deployer (CapabilityOwner facts)
    2. Find public/entry functions that:
       a. Take a capability by value (consuming it)
       b. Transfer to TxSender (TransfersToSender outside init)
    3. Check if the function is unguarded (no ChecksCapability for the same cap type)

    Example vulnerability:
        fun init(ctx: &mut TxContext) {
            let cap = AdminCap { id: object::new(ctx) };
            transfer::transfer(cap, tx_context::sender(ctx));  // -> Deployer
        }

        public entry fun steal_cap(cap: AdminCap, ctx: &mut TxContext) {
            transfer::transfer(cap, tx_context::sender(ctx));  // -> TxSender!
        }

    Emits CapabilityTakeover(func_name, cap_type, "deployer", "tx_sender") facts.
    """
    # Collect deployer-owned capabilities
    deployer_caps: Set[str] = set()
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "CapabilityOwner" and fact.args[1] == "deployer":
                deployer_caps.add(fact.args[0])

    if not deployer_caps:
        debug("No deployer-owned capabilities found, skipping takeover detection")
        return

    # Collect init functions (to exclude from takeover detection)
    init_funcs: Set[str] = set()
    init_impl_funcs: Set[str] = set()
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "IsInit":
                init_funcs.add(fact.args[0])
            elif fact.name == "InitImpl":
                init_impl_funcs.add(fact.args[0])

    deployer_context = init_funcs | init_impl_funcs

    # Collect public/entry functions
    public_funcs: Set[str] = set()
    entry_funcs: Set[str] = set()
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "IsPublic":
                public_funcs.add(fact.args[0])
            elif fact.name == "IsEntry":
                entry_funcs.add(fact.args[0])

    exposed_funcs = public_funcs | entry_funcs

    # Collect guards (ChecksCapability facts)
    func_guards: Dict[str, Set[str]] = {}  # func -> set of guarded cap types
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "ChecksCapability":
                role_type, func_name = fact.args
                if func_name not in func_guards:
                    func_guards[func_name] = set()
                func_guards[func_name].add(role_type)

    count = 0
    for file_ctx in ctx.source_files.values():
        if file_ctx.is_test_only:
            continue

        # Build map: func -> set of transfer sink stmt_ids
        func_transfer_sinks: Dict[str, Set[str]] = {}
        for fact in file_ctx.facts:
            if fact.name == "TransferSink":
                func_name, stmt_id, callee = fact.args
                if func_name not in func_transfer_sinks:
                    func_transfer_sinks[func_name] = set()
                func_transfer_sinks[func_name].add(stmt_id)

        # Build map: func -> stmt_id -> transferred vars
        sink_transferred_vars: Dict[str, Dict[str, Set[str]]] = {}
        for fact in file_ctx.facts:
            if fact.name == "SinkUsesVar" and fact.args[3] == "transfer_value":
                func_name, stmt_id, var, role = fact.args
                if func_name not in sink_transferred_vars:
                    sink_transferred_vars[func_name] = {}
                if stmt_id not in sink_transferred_vars[func_name]:
                    sink_transferred_vars[func_name][stmt_id] = set()
                sink_transferred_vars[func_name][stmt_id].add(var)

        # Build map: func -> (param_name, param_type) for by-value cap params
        func_cap_params: Dict[str, list] = {}
        for fact in file_ctx.facts:
            if fact.name != "FormalArg":
                continue
            func_name, idx, param_name, param_type = fact.args

            # Skip init context
            if func_name in deployer_context:
                continue

            # Skip non-exposed functions
            if func_name not in exposed_funcs:
                continue

            # Skip reference types
            if param_type.startswith("&"):
                continue

            # Check if param type is a deployer cap
            from move.types import strip_generics

            clean = strip_generics(param_type)
            matched_cap = None
            for cap in deployer_caps:
                if cap.endswith(f"::{clean}") or cap == clean:
                    matched_cap = cap
                    break

            if matched_cap:
                if func_name not in func_cap_params:
                    func_cap_params[func_name] = []
                func_cap_params[func_name].append((param_name, matched_cap))

        # Check each function with by-value cap params
        for func_name, cap_params in func_cap_params.items():
            # Check if function has transfer sinks
            if func_name not in func_transfer_sinks:
                continue

            # Check if function has CallsSender (transfers to sender)
            has_calls_sender = any(f.name == "CallsSender" and f.args[0] == func_name for f in file_ctx.facts)
            if not has_calls_sender:
                continue

            for param_name, cap_type in cap_params:
                # Check if this param is transferred
                is_transferred = False
                for stmt_id in func_transfer_sinks.get(func_name, set()):
                    transferred = sink_transferred_vars.get(func_name, {}).get(stmt_id, set())
                    if param_name in transferred:
                        is_transferred = True
                        break

                if not is_transferred:
                    continue

                # Check if function is guarded by a DIFFERENT capability (ref param)
                # Having the cap by value doesn't count as a guard - that's what we're transferring
                # The function is guarded if it requires a REFERENCE to another cap
                # Check for ref cap params that are NOT the one being transferred
                has_other_ref_guard = False
                for f in file_ctx.facts:
                    if f.name != "FormalArg" or f.args[0] != func_name:
                        continue
                    other_param_type = f.args[3]
                    if not other_param_type.startswith("&"):
                        continue  # Not a reference
                    # Check if it's a cap type
                    stripped = other_param_type
                    if stripped.startswith("&mut "):
                        stripped = stripped[5:]
                    elif stripped.startswith("&"):
                        stripped = stripped[1:]
                    stripped = stripped.strip()
                    clean_other = strip_generics(stripped)
                    for cap in deployer_caps:
                        if cap.endswith(f"::{clean_other}") or cap == clean_other:
                            has_other_ref_guard = True
                            break
                    if has_other_ref_guard:
                        break

                if has_other_ref_guard:
                    continue

                # Emit takeover fact
                takeover_fact = Fact(
                    "CapabilityTakeover",
                    (func_name, cap_type, "deployer", "tx_sender"),
                )
                if takeover_fact not in file_ctx.facts:
                    file_ctx.facts.append(takeover_fact)
                    count += 1
                    debug(f"  CapabilityTakeover({func_name}, {cap_type}, deployer->tx_sender)")

    if count > 0:
        debug(f"Generated {count} CapabilityTakeover facts")


def detect_phantom_type_mismatch(ctx: "ProjectContext") -> None:
    """
    Detect PhantomTypeMismatch patterns where capability guards don't protect targets.

    Attack vector:
        A function takes a capability guard `cap: &Cap<T>` with phantom type T,
        but operates on an object `obj: &mut Obj<U>` with different phantom type U.
        The capability doesn't actually protect the object.

    Example vulnerability:
        // AdminCap<phantom T> - phantom type binds to specific pool
        // Pool<phantom T> - phantom type identifies the pool
        public entry fun admin_action<T, U>(
            cap: &AdminCap<T>,   // Guard for type T
            pool: &mut Pool<U>,  // But operates on type U!
        ) {
            // Attacker with AdminCap<FakeToken> can manipulate Pool<RealToken>
        }

    Detection logic:
    1. Find functions with multiple TypeBoundByPhantom bindings
    2. Identify which params are capability guards (reference to role type)
    3. Identify which params are mutable targets (non-role objects)
    4. Check if guard phantom type differs from target phantom type

    Emits PhantomTypeMismatch facts.
    """
    # Collect role types
    role_types: Set[str] = set()
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "IsCapability":
                role_types.add(fact.args[0])

    if not role_types:
        return

    # Collect phantom type params: struct_name -> set of phantom param indices
    struct_phantoms: Dict[str, Set[int]] = {}
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "StructPhantomTypeParam":
                struct_name, param_idx, type_var = fact.args
                if struct_name not in struct_phantoms:
                    struct_phantoms[struct_name] = set()
                struct_phantoms[struct_name].add(param_idx)

    if not struct_phantoms:
        return

    count = 0
    for file_ctx in ctx.source_files.values():
        if file_ctx.is_test_only:
            continue

        # Collect TypeBoundByPhantom facts grouped by function
        # TypeBoundByPhantom(func_name, type_var, struct_type, param_name)
        func_phantom_bindings: Dict[str, List[Tuple[str, str, str]]] = {}
        for fact in file_ctx.facts:
            if fact.name == "TypeBoundByPhantom":
                func_name, type_var, struct_type, param_name = fact.args
                if func_name not in func_phantom_bindings:
                    func_phantom_bindings[func_name] = []
                func_phantom_bindings[func_name].append((type_var, struct_type, param_name))

        # Skip functions with < 2 phantom bindings (need guard + target)
        for func_name, bindings in func_phantom_bindings.items():
            if len(bindings) < 2:
                continue

            # Get function params
            params: Dict[str, str] = {}  # param_name -> param_type
            for fact in file_ctx.facts:
                if fact.name == "FormalArg" and fact.args[0] == func_name:
                    _, idx, param_name, param_type = fact.args
                    params[param_name] = param_type

            # Categorize bindings into guards (ref to role) and targets (mut ref to non-role)
            guards: List[Tuple[str, str, str, str]] = []  # (param_name, struct_type, type_var, param_type)
            targets: List[Tuple[str, str, str, str]] = []

            for type_var, struct_type, param_name in bindings:
                param_type = params.get(param_name, "")

                # Check if struct_type is a role
                is_role = False
                for role in role_types:
                    if names_match(struct_type, role):
                        is_role = True
                        break

                # Guards: reference to role type
                if is_role and param_type.startswith("&"):
                    guards.append((param_name, struct_type, type_var, param_type))

                # Targets: mutable reference to non-role type
                elif not is_role and param_type.startswith("&mut "):
                    targets.append((param_name, struct_type, type_var, param_type))

            # Check for phantom type mismatches: guard with T, target with U where T != U
            for guard_param, guard_struct, guard_type_var, guard_param_type in guards:
                for target_param, target_struct, target_type_var, target_param_type in targets:
                    if guard_type_var != target_type_var:
                        mismatch_fact = Fact(
                            "PhantomTypeMismatch",
                            (
                                func_name,
                                guard_param,
                                guard_struct,
                                guard_type_var,
                                target_param,
                                target_struct,
                                target_type_var,
                            ),
                        )
                        if mismatch_fact not in file_ctx.facts:
                            file_ctx.facts.append(mismatch_fact)
                            count += 1
                            debug(
                                f"  PhantomTypeMismatch({func_name}: guard {guard_param}<{guard_type_var}> != target {target_param}<{target_type_var}>)"
                            )

    if count > 0:
        debug(f"Generated {count} PhantomTypeMismatch facts")


def detect_capability_leak_via_store(ctx: "ProjectContext") -> None:
    """
    Detect CapabilityLeakViaStore patterns where capabilities are stored
    in shared object fields, making them accessible to anyone.

    Attack vector:
        A capability is stored as a field in a shared object. Since shared
        objects are accessible to anyone, the capability becomes public.

    Example vulnerability:
        public struct SharedVault has key {
            id: UID,
            admin_cap: AdminCap,  // Capability stored in shared object!
        }

        fun init(ctx: &mut TxContext) {
            let vault = SharedVault {
                id: object::new(ctx),
                admin_cap: AdminCap { id: object::new(ctx) },
            };
            transfer::share_object(vault);  // Anyone can now access admin_cap!
        }

    Detection logic:
    1. Find shared objects (IsSharedObject fact)
    2. Get fields of each shared object (StructField facts)
    3. Check if any field type is a role type (IsCapability fact)
    4. Emit CapabilityLeakViaStore for matches

    Emits CapabilityLeakViaStore(shared_struct, field_name, cap_type) facts.
    """
    # Collect all role types
    role_types: Set[str] = set()
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "IsCapability":
                role_types.add(fact.args[0])

    if not role_types:
        return

    # Collect all shared objects
    shared_objects: Set[str] = set()
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "IsSharedObject":
                shared_objects.add(fact.args[0])

    if not shared_objects:
        return

    # Build field index: struct_name -> list of (field_name, field_type)
    struct_fields: Dict[str, List[Tuple[str, str]]] = {}
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "StructField":
                struct_name, field_idx, field_name, field_type = fact.args
                if struct_name not in struct_fields:
                    struct_fields[struct_name] = []
                struct_fields[struct_name].append((field_name, field_type))

    count = 0
    for file_ctx in ctx.source_files.values():
        if file_ctx.is_test_only:
            continue

        # Check each shared object for capability fields
        for shared_struct in shared_objects:
            fields = struct_fields.get(shared_struct, [])

            for field_name, field_type in fields:
                # Check if field type is a role (capability)
                # Handle both FQN and simple name matching
                is_cap_field = False
                matched_role = None

                for role in role_types:
                    # Exact match
                    if field_type == role:
                        is_cap_field = True
                        matched_role = role
                        break
                    # Simple name match (field_type might be simple, role is FQN)
                    role_simple = role.split("::")[-1] if "::" in role else role
                    if field_type == role_simple:
                        is_cap_field = True
                        matched_role = role
                        break
                    # Field might be FQN, role might be simple
                    field_simple = field_type.split("::")[-1] if "::" in field_type else field_type
                    if field_simple == role_simple:
                        is_cap_field = True
                        matched_role = role
                        break

                if is_cap_field and matched_role:
                    leak_fact = Fact(
                        "CapabilityLeakViaStore",
                        (shared_struct, field_name, matched_role),
                    )

                    # Add to the file containing the shared struct
                    for fc in ctx.source_files.values():
                        if any(f.name == "Struct" and f.args[0] == shared_struct for f in fc.facts):
                            if leak_fact not in fc.facts:
                                fc.facts.append(leak_fact)
                                count += 1
                                debug(f"  CapabilityLeakViaStore({shared_struct}.{field_name} stores {matched_role})")
                            break

    if count > 0:
        debug(f"Generated {count} CapabilityLeakViaStore facts")
