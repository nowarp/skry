"""
Sui-specific function patterns for transfer, share, freeze, and sender operations.

These are used by multiple analysis passes to detect:
- Transfer operations (owned object transfers)
- Share operations (making objects shared)
- Freeze operations (making objects immutable)
- Sender calls (tx_context::sender)
- Privileged role/capability structs
"""

from core.utils import get_simple_name

# Exact whitelist for privileged capability struct names.
# These are used as part of structural heuristics for role detection:
#   1. Has exactly one field of type UID (single-UID struct)
#   2. Name matches one of PRIVILEGED_ROLE_NAMES (exact match on simple name)
#   3. Created in module's `init` function
#   4. Transferred to sender (not shared/frozen)
#
# That's the only name heuristics that significantly reduces LLM classification queries.
PRIVILEGED_ROLE_NAMES = {
    "AdminCap",
    "OwnerCap",
    "OperatorCap",
    "TreasuryCap",
}


def is_stdlib_type(type_fqn: str) -> bool:
    """Check if type is from Sui/Move stdlib (not user-defined).

    Uses FQN prefix to avoid false positives when users define structs
    with stdlib names (e.g., myprotocol::Coin should NOT be skipped).
    """
    return (
        type_fqn.startswith("sui::")
        or type_fqn.startswith("std::")
        or type_fqn.startswith("0x1::")  # Move stdlib address
        or type_fqn.startswith("0x2::")  # Sui framework address
    )


# Sui/Move stdlib module names (from third-party/sui/crates/sui-framework/packages/*)
# Used to resolve unqualified types like `object::ID` -> stdlib
SUI_STDLIB_MODULES = {
    # move-stdlib (std::)
    "ascii",
    "bcs",
    "bit_vector",
    "bool",
    "debug",
    "fixed_point32",
    "hash",
    "macros",
    "option",
    "string",
    "type_name",
    "u128",
    "u16",
    "u256",
    "u32",
    "u64",
    "u8",
    "unit_test",
    "uq32_32",
    "uq64_64",
    "vector",
    # sui-framework (sui::)
    "accumulator",
    "accumulator_metadata",
    "accumulator_settlement",
    "address",
    "authenticator_state",
    "bag",
    "balance",
    "bls12381",
    "borrow",
    "clock",
    "coin",
    "coin_registry",
    "config",
    "deny_list",
    "derived_object",
    "display",
    "dynamic_field",
    "dynamic_object_field",
    "ecdsa_k1",
    "ecdsa_r1",
    "ecvrf",
    "ed25519",
    "event",
    "funds_accumulator",
    "groth16",
    "group_ops",
    "hex",
    "hmac",
    "kiosk",
    "kiosk_extension",
    "linked_table",
    "math",
    "nitro_attestation",
    "object",
    "object_bag",
    "object_table",
    "package",
    "party",
    "pay",
    "poseidon",
    "priority_queue",
    "prover",
    "random",
    "sui",
    "table",
    "table_vec",
    "test_scenario",
    "test_utils",
    "token",
    "transfer",
    "transfer_policy",
    "tx_context",
    "types",
    "url",
    "vdf",
    "vec_map",
    "vec_set",
    "versioned",
    "zklogin_verified_id",
    "zklogin_verified_issuer",
    # sui-system (sui_system::)
    "genesis",
    "stake_subsidy",
    "staking_pool",
    "storage_fund",
    "sui_system",
    "sui_system_state_inner",
    "validator",
    "validator_cap",
    "validator_set",
    "validator_wrapper",
    "voting_power",
}


def is_stdlib_module(module_name: str) -> bool:
    """Check if module name is from Sui stdlib (e.g., 'object', 'coin')."""
    return module_name in SUI_STDLIB_MODULES


# Hacks to support stdlib capabilities and their constructors
# TODO Will be removed when the dependencies management (including stdlib parsing) is implemented
SUI_STDLIB_CAPABILITIES = {
    # sui::coin
    "sui::coin::TreasuryCap",
    "sui::coin::DenyCap",
    "sui::coin::DenyCapV2",
    # sui::package
    "sui::package::UpgradeCap",
    # sui::kiosk
    "sui::kiosk::KioskOwnerCap",
    "sui::kiosk::PurchaseCap",
    # sui::transfer_policy
    "sui::transfer_policy::TransferPolicyCap",
    # sui::token
    "sui::token::TokenPolicyCap",
    # sui::coin_registry
    "sui::coin_registry::MetadataCap",
}
SUI_CAPABILITY_RETURNING_FUNCTIONS = {
    # callee -> list of (tuple_index, capability_fqn)
    # tuple_index is 0-indexed position in return tuple.
    "sui::coin::create_currency": [(0, "sui::coin::TreasuryCap")],
    "coin::create_currency": [(0, "sui::coin::TreasuryCap")],
}


def is_privileged_role_name(struct_name: str) -> bool:
    simple = get_simple_name(struct_name)
    return simple in PRIVILEGED_ROLE_NAMES


# Transfer to owned: transfer::transfer, transfer::public_transfer
TRANSFER_CALLEES = {
    "sui::transfer::transfer",
    "sui::transfer::public_transfer",
    "sui::coin::transfer",
    "sui::transfer::party_transfer",
    "sui::transfer::public_party_transfer",
}

# Receive patterns - receiving objects owned by parent
RECEIVE_CALLEES = {
    "sui::transfer::receive",
    "sui::transfer::public_receive",
}

# Share object: makes object shared
SHARE_OBJECT_CALLEES = {
    "sui::transfer::share_object",
    "sui::transfer::public_share_object",
}

# Freeze object: makes object immutable
FREEZE_OBJECT_CALLEES = {
    "sui::transfer::freeze_object",
    "sui::transfer::public_freeze_object",
}

# Sender calls: tx_context::sender
SENDER_CALLEES = {
    "sui::tx_context::sender",
}

# Type name validation: all generic type_name functions that validate/identify type T
TYPE_NAME_GET_CALLEES = {
    "sui::types::type_name::get",
    "std::type_name::get",
    # with_defining_ids<T> - current recommended
    "sui::types::type_name::with_defining_ids",
    "std::type_name::with_defining_ids",
    # with_original_ids<T> - for version-aware validation
    "sui::types::type_name::with_original_ids",
    "std::type_name::with_original_ids",
    "sui::types::type_name::get_with_original_ids",
    "std::type_name::get_with_original_ids",
    # defining_id<T> / original_id<T> - ID extraction for type-based routing
    "sui::types::type_name::defining_id",
    "std::type_name::defining_id",
    "sui::types::type_name::original_id",
    "std::type_name::original_id",
}

# Generic extraction sinks - functions that extract/split value of generic type T
# Format: callee_fqn -> type_param_index (0-indexed)
GENERIC_EXTRACTION_SINKS = {
    "sui::coin::take": 0,
    "sui::balance::split": 0,
    "sui::coin::split": 0,
    "sui::coin::from_balance": 0,
    "sui::balance::value": 0,
    "sui::coin::value": 0,
}

# =============================================================================
# STDLIB CALL MATCHERS - use these instead of inline pattern checks
# =============================================================================
# These match both FQN (sui::transfer::transfer) and short forms (transfer::transfer)
# but reject user code with same names (my_module::transfer)


def is_stdlib_sender_call(callee: str) -> bool:
    """Check if callee is tx_context::sender."""
    if callee in SENDER_CALLEES:
        return True
    if "tx_context::" in callee:
        return get_simple_name(callee) == "sender"
    return False


def is_stdlib_transfer_call(callee: str) -> bool:
    """Check if callee is transfer::transfer or transfer::public_transfer."""
    if callee in TRANSFER_CALLEES:
        return True
    if "transfer::" in callee:
        return get_simple_name(callee) in ("transfer", "public_transfer")
    return False


def is_stdlib_share_call(callee: str) -> bool:
    """Check if callee is transfer::share_object or transfer::public_share_object."""
    if callee in SHARE_OBJECT_CALLEES:
        return True
    if "transfer::" in callee:
        return get_simple_name(callee) in ("share_object", "public_share_object")
    return False


def is_stdlib_freeze_call(callee: str) -> bool:
    """Check if callee is transfer::freeze_object or transfer::public_freeze_object."""
    if callee in FREEZE_OBJECT_CALLEES:
        return True
    if "transfer::" in callee:
        return get_simple_name(callee) in ("freeze_object", "public_freeze_object")
    return False


def is_user_deposit_call(callee: str) -> bool:
    """Check if callee is a user deposit pattern (balance::join, coin::put, coin::join)."""
    if callee in USER_DEPOSIT_CALLEES:
        return True
    simple = get_simple_name(callee)
    if "balance::" in callee and simple == "join":
        return True
    if "coin::" in callee and simple in ("put", "join"):
        return True
    return False


# Value types that represent user-provided assets
VALUE_TYPE_NAMES = {"Coin", "Balance"}


def is_value_type(type_str: str) -> bool:
    """Check if type is Coin or Balance (user value types).

    Uses exact base type matching to avoid false positives like MyCoin, UserCoin.

    Args:
        type_str: Type string (e.g., "sui::coin::Coin<T>", "Coin<SUI>")

    Returns:
        True if base type is exactly "Coin" or "Balance"
    """
    from move.types import extract_base_type

    base = extract_base_type(type_str)
    return base in VALUE_TYPE_NAMES


# FQN patterns for value types (Coin, Balance, Token)
# Used for FQN-only matching to avoid false positives from user-defined types
VALUE_TYPE_FQNS = {
    "sui::coin::Coin",
    "sui::balance::Balance",
    "sui::token::Token",
}


def is_value_type_fqn(type_fqn: str) -> bool:
    """Check if type FQN is a stdlib value type (Coin/Balance/Token).

    Only matches FQN prefixes, NOT simple names.
    Example: "sui::coin::Coin<T>" -> True, "mymodule::Coin" -> False
    """
    for fqn in VALUE_TYPE_FQNS:
        if type_fqn.startswith(fqn):
            return True
    return False


# All transfer-related sinks (for taint analysis)
ALL_TRANSFER_SINKS = TRANSFER_CALLEES | SHARE_OBJECT_CALLEES | FREEZE_OBJECT_CALLEES

# =============================================================================
# TAINT ANALYSIS PATTERNS
# =============================================================================

# Sender sources - tx_context::sender() returns the transaction sender address
SENDER_SOURCES = {
    "sui::tx_context::sender",
    "one::tx_context::sender",  # One framework
}

# Transfer sinks - where value/objects go to an address
TRANSFER_SINKS = {
    "sui::transfer::transfer",
    "sui::transfer::public_transfer",
    "sui::pay::split_and_transfer",
    "sui::coin::mint_and_transfer",
    "sui::coin::split_and_transfer",
}

# Transfer recipient argument positions (default is -1/last arg)
TRANSFER_RECIPIENT_ARG_INDEX = {
    "sui::coin::mint_and_transfer": -2,
    "sui::coin::split_and_transfer": -2,
    "sui::pay::split_and_transfer": -2,
}

# State write patterns - modifying on-chain state
STATE_WRITE_PATTERNS = {
    # Balance operations
    "sui::balance::join",
    "sui::balance::split",
    "sui::balance::withdraw_all",
    # Coin operations
    "sui::coin::take",
    "sui::coin::put",
    "sui::coin::join",
    "sui::coin::split",
    # Dynamic fields
    "sui::dynamic_field::add",
    "sui::dynamic_field::remove",
    "sui::dynamic_field::borrow_mut",
    # Dynamic object fields
    "sui::dynamic_object_field::add",
    "sui::dynamic_object_field::remove",
    "sui::dynamic_object_field::borrow_mut",
    # Table operations
    "sui::table::add",
    "sui::table::remove",
    "sui::table::borrow_mut",
    # LinkedTable
    "sui::linked_table::push_back",
    "sui::linked_table::push_front",
    "sui::linked_table::pop_back",
    "sui::linked_table::pop_front",
    "sui::linked_table::remove",
    "sui::linked_table::borrow_mut",
    # Bag operations
    "sui::bag::add",
    "sui::bag::remove",
    "sui::bag::borrow_mut",
    # Object bag
    "sui::object_bag::add",
    "sui::object_bag::remove",
    "sui::object_bag::borrow_mut",
    # VecMap
    "sui::vec_map::insert",
    "sui::vec_map::remove",
    # VecSet
    "sui::vec_set::insert",
    "sui::vec_set::remove",
    # Priority queue
    "sui::priority_queue::insert",
    "sui::priority_queue::pop_max",
    # ObjectTable
    "sui::object_table::add",
    "sui::object_table::remove",
    "sui::object_table::borrow_mut",
    # TableVec
    "sui::table_vec::push_back",
    "sui::table_vec::pop_back",
    "sui::table_vec::borrow_mut",
    "sui::table_vec::swap",
    "sui::table_vec::swap_remove",
    # Token operations
    "sui::token::join",
}

# Amount extraction patterns - user controls how much is taken
# Maps callee -> argument index of amount parameter
AMOUNT_EXTRACTION_PATTERNS = {
    "sui::coin::take": 1,
    "sui::balance::split": 1,
    "sui::coin::split": 1,
    "sui::pay::split_and_transfer": 1,
    "sui::pay::split": 1,
    "sui::token::split": 1,
    "sui::coin::divide_into_n": 1,
}

# Value extraction patterns - extract ALL value (no amount param)
VALUE_EXTRACTION_PATTERNS = {
    "sui::balance::withdraw_all",
    "sui::coin::from_balance",
    "sui::coin::into_balance",
    "sui::token::to_coin",
    "sui::token::from_coin",
}

# All value extraction callees (FQN only) - used for &mut param deposit detection
# Combines AMOUNT_EXTRACTION_PATTERNS (dict keys) and VALUE_EXTRACTION_PATTERNS (set)
ALL_VALUE_EXTRACTION_CALLEES = set(AMOUNT_EXTRACTION_PATTERNS.keys()) | VALUE_EXTRACTION_PATTERNS


def is_value_extraction_call(callee: str) -> bool:
    """Check if callee extracts value from &mut Coin/Balance/Token.

    FQN-only matching for stdlib extraction patterns.
    Used to detect user deposit patterns with &mut params.
    """
    return callee in ALL_VALUE_EXTRACTION_CALLEES


# User deposit patterns - joining user's Coin/Balance into pool storage
# These are SAFE state writes when taint source is user's by-value Coin/Balance param
USER_DEPOSIT_CALLEES = {
    "sui::balance::join",
    "sui::coin::put",
    "sui::coin::join",
}

# Supply management patterns - minting new tokens
SUPPLY_MINT_PATTERNS = {
    "sui::coin::mint",
    "sui::coin::mint_balance",
    "sui::coin::mint_and_transfer",
    "sui::token::mint",
    "sui::balance::increase_supply",
}

# Object destruction patterns - destroying objects (burning)
OBJECT_DESTROY_PATTERNS = {
    "sui::object::delete",
    "sui::coin::burn",
    "sui::coin::destroy_zero",
    "sui::balance::destroy_zero",
    "sui::balance::decrease_supply",
    "sui::token::burn",
    "sui::token::destroy_zero",
    "sui::bag::destroy_empty",
    "sui::table::destroy_empty",
    "sui::linked_table::destroy_empty",
    "sui::object_bag::destroy_empty",
    "sui::object_table::destroy_empty",
    "sui::table_vec::destroy_empty",
    "sui::vec_map::destroy_empty",
    "sui::vec_set::destroy_empty",
    "sui::versioned::destroy",
    "sui::borrow::destroy",
    "sui::package::burn_publisher",
}

# Collection mutation methods (FQN format for Sui stdlib)
# These are methods that mutate their receiver when called as receiver.method()
COLLECTION_MUTATION_METHODS = frozenset(
    {
        # sui::table
        "sui::table::add",
        "sui::table::remove",
        "sui::table::borrow_mut",
        # sui::bag
        "sui::bag::add",
        "sui::bag::remove",
        "sui::bag::borrow_mut",
        # sui::object_bag
        "sui::object_bag::add",
        "sui::object_bag::remove",
        "sui::object_bag::borrow_mut",
        # sui::object_table
        "sui::object_table::add",
        "sui::object_table::remove",
        "sui::object_table::borrow_mut",
        # sui::vec_map
        "sui::vec_map::insert",
        "sui::vec_map::remove",
        "sui::vec_map::pop",
        "sui::vec_map::get_mut",
        "sui::vec_map::get_entry_by_idx_mut",
        "sui::vec_map::remove_entry_by_idx",
        # sui::vec_set
        "sui::vec_set::insert",
        "sui::vec_set::remove",
        # sui::linked_table
        "sui::linked_table::push_front",
        "sui::linked_table::push_back",
        "sui::linked_table::pop_front",
        "sui::linked_table::pop_back",
        "sui::linked_table::remove",
        "sui::linked_table::borrow_mut",
        # sui::table_vec
        "sui::table_vec::push_back",
        "sui::table_vec::pop_back",
        "sui::table_vec::borrow_mut",
        "sui::table_vec::swap",
        "sui::table_vec::swap_remove",
        # sui::priority_queue
        "sui::priority_queue::pop_max",
        "sui::priority_queue::insert",
    }
)

# Generic setter method names (simple names for user-defined setters)
# These match any method with these names, regardless of module
GENERIC_SETTER_METHOD_NAMES = frozenset(
    {
        "set",
        "put",
        "fill",
        "replace",
    }
)

# Move primitive types - these are not struct types and should be excluded
# from struct analysis (e.g., LLM sensitivity, nested type resolution)
MOVE_PRIMITIVE_TYPES = {
    "UID",
    "ID",
    "u8",
    "u16",
    "u32",
    "u64",
    "u128",
    "u256",
    "bool",
    "address",
    "vector",
}


def detect_transfer_patterns(func_name: str, facts: list) -> tuple[str, bool, bool]:
    """
    Detect transfer patterns in function using InFun facts.

    Args:
        func_name: Function to analyze
        facts: List of Fact objects from the source file

    Returns: (transferred_to, shared, frozen)
        - transferred_to: "sender" | "param" | "none"
        - shared: True if share_object called
        - frozen: True if freeze_object called
    """
    has_sender_call = False
    has_transfer_call = False
    has_share_call = False
    has_freeze_call = False

    for fact in facts:
        if fact.name == "InFun" and fact.args[0] == func_name:
            call_id = fact.args[1]
            callee = call_id.split("@")[0] if "@" in call_id else call_id

            if is_stdlib_sender_call(callee):
                has_sender_call = True
            if is_stdlib_transfer_call(callee):
                has_transfer_call = True
            if is_stdlib_share_call(callee):
                has_share_call = True
            if is_stdlib_freeze_call(callee):
                has_freeze_call = True

    # Determine transferred_to
    if has_transfer_call and has_sender_call:
        transferred_to = "sender"
    elif has_transfer_call:
        transferred_to = "param"
    else:
        transferred_to = "none"

    return transferred_to, has_share_call, has_freeze_call
