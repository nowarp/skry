"""
Fact definitions and registry for Skry.

All facts MUST be defined here. Attempting to create a Fact with an
unregistered name will raise UnregisteredFactError.
"""

from dataclasses import dataclass, field
from typing import Tuple, Any, List, Optional, Dict, Literal

from core.utils import get_simple_name

# =============================================================================
# FACT SCHEMA AND REGISTRY
# =============================================================================

Scope = Literal["struct", "function", "statement", "project"]


@dataclass(frozen=True)
class FactSchema:
    """Schema describing a fact type.

    func_name_arg_idx: For function-scoped facts, which arg index contains func_name.
                       None means not indexed by function (struct/project scope).
                       Default 0 for function/statement scope (most common case).
    """

    name: str
    args: Tuple[Tuple[str, type], ...]  # (arg_name, arg_type) pairs
    description: str
    requires_llm: bool = False
    scope: Scope = "function"
    func_name_arg_idx: Optional[int] = None  # Set by define_fact based on scope

    @property
    def arity(self) -> int:
        return len(self.args)


# The registry - single source of truth for all facts
FACT_REGISTRY: Dict[str, FactSchema] = {}


class UnregisteredFactError(Exception):
    """Raised when attempting to create a Fact with unregistered name."""

    pass


def define_fact(
    name: str,
    args: Tuple[Tuple[str, type], ...],
    description: str,
    requires_llm: bool = False,
    scope: Scope = "function",
    func_name_arg_idx: Optional[int] = None,
) -> FactSchema:
    """Define a fact type and register it.

    func_name_arg_idx: Which arg contains func_name for indexing.
                       - None: auto-detect (0 for function/statement scope, None otherwise)
                       - Explicit int: override for exceptions like ChecksCapability (idx=1)
    """
    if name in FACT_REGISTRY:
        raise ValueError(f"Fact '{name}' already registered")

    # Auto-detect func_name_arg_idx if not specified
    if func_name_arg_idx is None and scope in ("function", "statement"):
        # Default: first arg is func_name for function/statement scoped facts
        func_name_arg_idx = 0

    schema = FactSchema(name, args, description, requires_llm, scope, func_name_arg_idx)
    FACT_REGISTRY[name] = schema
    return schema


# =============================================================================
# FACT DEFINITIONS - Struct scope
# =============================================================================

define_fact("Struct", (("struct_name", str),), "Struct definition", scope="struct")
define_fact("StructComment", (("struct_name", str), ("comment", str)), "Comment on struct definition", scope="struct")
define_fact(
    "StructField",
    (("struct_name", str), ("field_idx", int), ("field_name", str), ("field_type", str)),
    "Struct field definition",
    scope="struct",
)
define_fact(
    "FieldComment",
    (("struct_name", str), ("field_name", str), ("comment", str)),
    "Comment on struct field",
    scope="struct",
)
define_fact("IsCapability", (("struct_name", str),), "Struct represents a capability", scope="struct")
define_fact("IsEvent", (("struct_name", str),), "Struct represents an event for event::emit", scope="struct")
define_fact("HasCopyAbility", (("struct_name", str),), "Struct has copy ability (on-chain object)", scope="struct")
define_fact("HasDropAbility", (("struct_name", str),), "Struct has drop ability (on-chain object)", scope="struct")
define_fact("HasKeyAbility", (("struct_name", str),), "Struct has key ability (on-chain object)", scope="struct")
define_fact("HasStoreAbility", (("struct_name", str),), "Struct has store ability (on-chain object)", scope="struct")
define_fact(
    "IsPrivileged",
    (("struct_name", str),),
    "Struct is privileged: admin/owner capability, or controlled exclusively by privileged users",
    scope="struct",
)
define_fact(
    "NotPrivileged",
    (("struct_name", str),),
    "Struct is NOT a privileged capability, nor controlled exclusively by privileged users",
    scope="struct",
)
define_fact(
    "IsConfig",
    (("struct_name", str),),
    "Struct represents protocol configuration/parameters",
    scope="struct",
)
define_fact(
    "IsStateContainer",
    (("struct_name", str),),
    "Struct holds mutable runtime state (pools, registries, vaults)",
    requires_llm=True,
    scope="struct",
)
define_fact(
    "IsUserAsset",
    (("struct_name", str), ("is_user_asset", bool)),
    "Struct represents user-owned value (receipts, tickets, NFTs), not a protocol asset",
    requires_llm=True,
    scope="struct",
)
define_fact(
    "IsUserAssetContainer",
    (("struct_name", str),),
    "Struct holds user-deposited assets (detected via deposit+withdraw patterns)",
    scope="struct",
)
define_fact(
    "IsExternal",
    (("struct_name", str),),
    "Struct is from external dependency (not defined in this project)",
    scope="struct",
)
define_fact(
    "HasOwnershipField",
    (("struct_name", str),),
    "Struct has ownership field (owner, authority, admin, etc.) indicating per-user ownership",
    scope="struct",
)
define_fact(
    "UserDepositsInto",
    (("func_name", str), ("struct_type", str)),
    "Public function where users deposit Coin/Balance into shared struct",
)
define_fact(
    "UserWithdrawsFrom",
    (("func_name", str), ("struct_type", str)),
    "Public function where users withdraw to sender from shared struct",
)
define_fact(
    "WritesUserAsset",
    (("func_name", str), ("struct_type", str)),
    "Function has &mut param to user asset container struct",
)
define_fact(
    "ReadsUserAsset",
    (("func_name", str), ("struct_type", str)),
    "Function has & param to user asset container struct",
)
define_fact("IsVersion", (("struct_name", str),), "Struct represents version info", scope="struct")
define_fact(
    "IsSharedObject",
    (("struct_name", str),),
    "Struct is shared via transfer::share_object",
    scope="struct",
)
define_fact(
    "FieldAccess",
    (("func_name", str), ("struct_type", str), ("field_path", str), ("code_snippet", str), ("line_number", int)),
    "Field access on struct parameter in function",
    scope="statement",
)
define_fact(
    "FieldClassification",
    (
        ("struct_type", str),
        ("field_path", str),
        ("category", str),
        ("negative", bool),
        ("confidence", float),
        ("reason", str),
    ),
    "Unified field classification fact - category: sensitive|config_value|privileged_address|lock|state|mutable_config|protocol_invariant, negative: True if NOT this category",
    requires_llm=True,
    scope="struct",
)
define_fact(
    "WritesProtocolInvariant",
    (("func_name", str), ("struct_type", str), ("field_path", str)),
    "Non-init function writes to protocol invariant field",
)
define_fact(
    "WritesField",
    (("func_name", str), ("struct_type", str), ("field_path", str)),
    "Function writes to struct field (assignment)",
)
define_fact(
    "ReadsField",
    (("func_name", str), ("struct_type", str), ("field_path", str)),
    "Function reads struct field",
    scope="function",
)
define_fact(
    "TransitiveWritesField",
    (("func_name", str), ("struct_type", str), ("field_path", str), ("via_callee", str)),
    "Function transitively writes to struct field through call chain",
)
define_fact(
    "StructPhantomTypeParam",
    (("struct_name", str), ("param_idx", int), ("type_var", str)),
    "Struct has phantom type parameter",
    scope="struct",
)
define_fact(
    "TypeBoundByPhantom",
    (("func_name", str), ("type_var", str), ("struct_type", str), ("param_name", str)),
    "Type parameter is bound by phantom type in struct parameter",
    scope="function",
)

# Structural capability detection facts
define_fact(
    "PacksStruct",
    (("func_name", str), ("struct_type", str)),
    "Function contains struct pack expression (creation)",
)
define_fact(
    "TransfersToSender",
    (("func_name", str), ("struct_type", str)),
    "Function transfers struct instance to tx_context::sender(ctx)",
)
define_fact(
    "SharesObject",
    (("func_name", str), ("struct_type", str)),
    "Function shares object via transfer::share_object",
)
define_fact(
    "CreatesCapability",
    (("func_name", str), ("cap_type", str)),
    "Function instantiates a capability struct",
)
define_fact(
    "InitImpl",
    (("func_name", str),),
    "Function is an init implementation helper (called by init with sinks)",
)
define_fact(
    "PacksToVar",
    (("func_name", str), ("var_name", str), ("struct_type", str)),
    "Variable receives a packed struct instance (let var = Struct {...})",
)
define_fact(
    "CapabilityHierarchy",
    (("parent_cap", str), ("child_cap", str)),
    "Parent capability can create/grant child capability",
    scope="struct",
)

# Lock infrastructure facts (derived from IsLockField + ReadsField)
define_fact("HasLockInfrastructure", (("has_lock", bool),), "Project has per-object lock fields")
define_fact("ChecksLock", (("func_name", str),), "Function checks lock state before operating")

# Privileged setter facts (derived from WritesField + access control)
define_fact(
    "HasPrivilegedSetter",
    (("struct_type", str), ("field_path", str)),
    "Mutable config field has a privileged setter function (gated by capability or sender check)",
    scope="struct",
)

# Global pause facts (ChecksPause derived from IsGlobalPauseField via PauseDetector)
define_fact(
    "ChecksPause",
    (("func_name", str),),
    "Function checks global pause state before operating (direct only)",
)

# =============================================================================
# FACT DEFINITIONS - Function scope (function-level properties)
# =============================================================================

define_fact("Fun", (("func_name", str),), "Function definition")
define_fact("IsPublic", (("func_name", str),), "Function is public")
define_fact("IsEntry", (("func_name", str),), "Function is entry point")
define_fact("IsInit", (("func_name", str),), "Function is module initializer")
define_fact("IsTestOnly", (("func_name", str),), "Function is test-only")
define_fact("IsFriend", (("func_name", str),), "Function is friend (public(friend))")
define_fact("IsGenericAccessor", (("func_name", str),), "Function is a generic accessor")
define_fact("IsVersionCheckMethod", (("func_name", str),), "Function checks version")
define_fact("FunReturnType", (("func_name", str), ("return_type", str)), "Function return type")
define_fact("ReturnsMutableRef", (("func_name", str), ("return_type", str)), "Function returns mutable reference")
define_fact("ReturnsCoinType", (("func_name", str), ("return_type", str)), "Function returns Coin/Balance/Token type")
define_fact(
    "FormalArg",
    (("func_name", str), ("param_idx", int), ("param_name", str), ("param_type", str)),
    "Function formal parameter",
)
define_fact(
    "ChecksCapability",
    (("cap_type", str), ("func_name", str)),
    "Function checks a capability (direct only)",
    func_name_arg_idx=1,  # Exception: func_name is at args[1]
)
define_fact(
    "CallsSender",
    (("func_name", str),),
    "Function calls tx_context::sender() (direct only, not for authorization)",
)
define_fact(
    "Transfers",
    (("func_name", str), ("transfers", bool)),
    "Function performs transfer (including via callees)",
)
define_fact(
    "HasValueExtraction",
    (("func_name", str), ("has_extraction", bool)),
    "Function extracts value via coin::take/balance::split etc. (including via callees)",
)
define_fact("EmitsEvent", (("func_name", str), ("event_type", str)), "Function emits an event")
define_fact("SelfRecursive", (("func_name", str),), "Function calls itself recursively")
define_fact("SameModule", (("func1", str), ("func2", str)), "Two functions are in the same module")
define_fact("HasVersionCheck", (("func_name", str),), "Function has version check (direct only)")
define_fact("DuplicatedBranchCondition", (("func_name", str), ("condition", str)), "Same condition in if/else-if chain")
define_fact("DuplicatedBranchBody", (("func_name", str), ("body_snippet", str)), "Identical code in branches")
define_fact("OrphanTxContextFunction", (("func_name", str),), "public(friend) with TxContext, never called")
define_fact("OrphanCapability", (("cap_type", str),), "Capability defined but never used as parameter")
define_fact("OrphanEvent", (("event_type", str),), "Event defined but never emitted")
define_fact("UnusedArg", (("func_name", str), ("param_name", str), ("param_idx", int)), "Function argument never used")
define_fact("TransfersToZeroAddress", (("func_name", str), ("stmt_id", str), ("var", str)), "Transfer to zero address")
define_fact(
    "HasGenericParam",
    (("func_name", str), ("param_idx", int), ("type_var", str)),
    "Function has generic type parameter",
)
# Generic type taint analysis
define_fact(
    "GenericCallArg",
    (("func_name", str), ("stmt_id", str), ("callee", str), ("type_arg_idx", int), ("type_var", str)),
    "Type argument at call site maps to caller's type param",
    scope="statement",
)
define_fact(
    "TypeValidated",
    (("func_name", str), ("type_var", str), ("stmt_id", str)),
    "Type variable validated at statement (type_name::get<T>)",
    scope="statement",
)
define_fact(
    "FunctionValidatesType",
    (("func_name", str), ("type_var", str)),
    "Function validates type param (calls type_name::get<T>) without extracting it",
    scope="function",
)
define_fact(
    "UnvalidatedTypeAtSink",
    (("func_name", str), ("type_var", str), ("stmt_id", str), ("sink_callee", str)),
    "Unvalidated type param used at generic sink",
    scope="statement",
)
define_fact(
    "ValidatedTypeAtSink",
    (("func_name", str), ("type_var", str), ("stmt_id", str), ("sink_callee", str)),
    "Validated type param used at generic sink",
    scope="statement",
)
define_fact(
    "ExtractedValueReturned",
    (("func_name", str), ("type_var", str)),
    "Extracted value with type param is returned (not transferred to sink)",
)
define_fact(
    "TypeReachesExtractionInCallers",
    (("func_name", str), ("type_var", str), ("extraction_caller", str)),
    "Generic type param reaches extraction sinks via caller chain (reverse IPA)",
)

# Call graph
define_fact("Calls", (("caller_func", str), ("callee_func", str)), "Direct call edge in call graph")

# Derived facts (computed in second pass from base facts)
define_fact(
    "OperatesOnSharedObject",
    (("func_name", str),),
    "Function has &mut param to shared object type (needs auth)",
)
define_fact(
    "OperatesOnOwnedOnly",
    (("func_name", str),),
    "Function has &mut params but ALL are to owned objects (owner-controlled)",
)
define_fact(
    "TransfersUserProvidedValue",
    (("func_name", str),),
    "Function transfers user-provided Coin/Balance (deposit pattern)",
)
define_fact(
    "TransfersUserAsset",
    (("func_name", str), ("asset_type", str)),
    "Function transfers user-owned asset type (receipt/ticket/NFT)",
)
define_fact(
    "TransfersFromSharedObject",
    (("func_name", str), ("source_param", str), ("shared_type", str)),
    "Function extracts value from shared object param (dangerous for drain)",
)
define_fact(
    "TransfersFromSender",
    (("func_name", str),),
    "Transfer source flows from ctx.sender() - user operates on own assets (direct only)",
)
define_fact(
    "HasSenderEqualityCheck",
    (("func_name", str),),
    "Function checks sender equality in assert/condition (direct only)",
)
define_fact(
    "ValueExchangeFunction",
    (("func_name", str),),
    "Function takes Coin/Balance input and returns Coin/Balance (swap/refund pattern)",
)
# Struct creation pattern facts (derived from CreationSite analysis)
define_fact(
    "IsUserCreatable",
    (("struct_name", str),),
    "Struct can be created by anyone via public function (user-owned instances)",
    scope="struct",
)
# Ownership transfer pattern facts
define_fact(
    "TakesPrivilegedByValue",
    (("func_name", str), ("cap_type", str)),
    "Function takes privileged capability by value (ownership transfer capability)",
)
define_fact(
    "HasTwoStepOwnership",
    (("module_path", str),),
    "Module implements two-step ownership transfer pattern (pending field + offer/claim)",
    scope="project",
)
define_fact(
    "SingleStepOwnershipTransfer",
    (("func_name", str), ("cap_type", str)),
    "Function performs single-step ownership transfer to tainted recipient",
)

# Per-sink guard tracking
# GuardedSink tracks which sinks are protected by which guards
# guard_type: "sender", "cap:<CapType>", "pause", "lock", "version"
define_fact(
    "GuardedSink",
    (("func_name", str), ("stmt_id", str), ("guard_type", str)),
    "Sink at stmt_id is protected by guard_type",
)

# =============================================================================
# FACT DEFINITIONS - LLM Semantic Facts (generated by :classify pass)
# =============================================================================
# Each classifier generates EITHER a positive (safe) OR negative (vulnerable) fact.
# Positive = function has protection/safe pattern
# Negative = function is vulnerable

# Access control classification
define_fact(
    "LLMHasAccessControl",
    (("func_name", str),),
    "LLM: function has access control (safe)",
    requires_llm=True,
)
define_fact(
    "LLMVulnerableAccessControl",
    (("func_name", str),),
    "LLM: function missing access control (vulnerable)",
    requires_llm=True,
)

# Internal helper exposure classification
define_fact(
    "LLMSafeInternalHelper",
    (("func_name", str),),
    "LLM: function is legitimate public API (safe)",
    requires_llm=True,
)
define_fact(
    "LLMInternalHelperExposure",
    (("func_name", str),),
    "LLM: internal helper exposed as public (vulnerable)",
    requires_llm=True,
)

# Unlock/release classification
define_fact(
    "LLMHasUnlockOnAllPaths",
    (("func_name", str),),
    "LLM: lock released on all paths (safe)",
    requires_llm=True,
)
define_fact(
    "LLMMissingUnlock",
    (("func_name", str),),
    "LLM: lock not released on all paths (vulnerable)",
    requires_llm=True,
)

# Arbitrary drain classification
define_fact(
    "LLMCallerOwnsValue",
    (("func_name", str),),
    "LLM: caller owns transferred value (safe)",
    requires_llm=True,
)
define_fact(
    "LLMArbitraryDrain",
    (("func_name", str),),
    "LLM: arbitrary recipient can drain protocol funds (vulnerable)",
    requires_llm=True,
)

# Missing transfer classification
define_fact(
    "LLMValueReachesRecipient",
    (("func_name", str),),
    "LLM: extracted value reaches recipient (safe)",
    requires_llm=True,
)
define_fact(
    "LLMMissingTransfer",
    (("func_name", str),),
    "LLM: extracted value never transferred (vulnerable)",
    requires_llm=True,
)

# Sensitive setter classification
define_fact(
    "LLMHasSetterAuth",
    (("func_name", str),),
    "LLM: sensitive setter has authorization (safe)",
    requires_llm=True,
)
define_fact(
    "LLMSensitiveSetter",
    (("func_name", str),),
    "LLM: sensitive setter missing authorization (vulnerable)",
    requires_llm=True,
)

# =============================================================================
# FACT DEFINITIONS - Statement scope (statement/variable level)
# =============================================================================

define_fact("InFun", (("func_name", str), ("entity_id", str)), "Entity (var/call) is in function", scope="statement")
define_fact("Call", (("call_id", str),), "Call site", scope="statement", func_name_arg_idx=None)
define_fact(
    "IsMethodCall",
    (("call_id", str),),
    "Call uses method syntax (has receiver)",
    scope="statement",
    func_name_arg_idx=None,
)
define_fact(
    "ActualArg",
    (("call_id", str), ("arg_idx", int), ("arg_name", str)),
    "Actual argument at call site",
    scope="statement",
    func_name_arg_idx=None,
)
define_fact(
    "CallResult",
    (("func_name", str), ("stmt_id", str), ("result_var", str), ("callee", str)),
    "Result of a call",
    scope="statement",
)
define_fact(
    "CallArg",
    (("func_name", str), ("stmt_id", str), ("callee", str), ("arg_idx", int), ("arg_vars", tuple)),
    "Argument passed to call",
    scope="statement",
)
define_fact(
    "Assigns",
    (("func_name", str), ("stmt_id", str), ("target_var", str), ("source_vars", tuple)),
    "Assignment statement",
    scope="statement",
)
define_fact(
    "DerefAssigns",
    (("func_name", str), ("stmt_id", str), ("target_var", str), ("source_vars", tuple)),
    "Dereference assignment: *target = source (mutref tainting)",
    scope="statement",
)
define_fact(
    "CastsToInt",
    (("func_name", str), ("stmt_id", str), ("target_var", str), ("source_vars", tuple)),
    "Assignment that casts source to integer type",
    scope="statement",
)
define_fact(
    "ConditionCheck",
    (("func_name", str), ("stmt_id", str), ("cond_vars", tuple)),
    "Condition check in if/assert",
    scope="statement",
)
define_fact(
    "ConditionFieldAccess",
    (("func_name", str), ("stmt_id", str), ("base_var", str), ("field", str)),
    "Field access in condition expression",
    scope="statement",
)
define_fact(
    "FieldAssign",
    (("func_name", str), ("stmt_id", str), ("target_var", str), ("base_var", str), ("field", str)),
    "Field value assigned to variable",
    scope="statement",
)
define_fact(
    "ReturnsFieldValue",
    (("func_name", str), ("field", str)),
    "Function returns a field value",
    scope="function",
)

# Constants
define_fact(
    "ConstDef",
    (("qualified_name", str), ("simple_name", str), ("value", Any), ("const_type", str)),
    "Module constant definition",
    scope="function",
)

# =============================================================================
# FACT DEFINITIONS - Taint sources and sinks
# =============================================================================

define_fact(
    "TaintSource",
    (("func_name", str), ("param_name", str), ("param_idx", int)),
    "Taint source (user input parameter)",
    scope="statement",
)
define_fact("Tainted", (("func_name", str), ("var", str)), "Variable is tainted", scope="statement")
define_fact(
    "TaintedBy",
    (("func_name", str), ("var", str), ("source", str)),
    "Variable is tainted by specific source",
    scope="statement",
)
define_fact("Sanitized", (("func_name", str), ("var", str)), "Variable is sanitized", scope="statement")
define_fact(
    "SanitizedByAssert",
    (("func_name", str), ("stmt_id", str), ("var", str)),
    "Variable sanitized by assert",
    scope="statement",
)
define_fact(
    "SanitizedByAbortCheck",
    (("func_name", str), ("stmt_id", str), ("var", str)),
    "Variable sanitized by abort check",
    scope="statement",
)
define_fact(
    "SanitizedByClamping",
    (("func_name", str), ("stmt_id", str), ("result_var", str), ("source_var", str)),
    "Variable sanitized by clamping (min/max)",
    scope="statement",
)
define_fact(
    "SenderCallInAssertion",
    (("func_name", str), ("stmt_id", str)),
    "Assertion contains tx_context::sender() call in comparison",
    scope="statement",
)
define_fact(
    "DirectSenderInTransfer",
    (("func_name", str), ("stmt_id", str)),
    "Transfer recipient is a direct tx_context::sender() call",
    scope="statement",
)
# Sinks
define_fact(
    "TransferSink",
    (("func_name", str), ("stmt_id", str), ("callee", str)),
    "Transfer sink (transfer call)",
    scope="statement",
)
define_fact(
    "StateWriteSink",
    (("func_name", str), ("stmt_id", str), ("callee", str)),
    "State write sink",
    scope="statement",
)
define_fact(
    "AmountExtractionSink",
    (("func_name", str), ("stmt_id", str), ("callee", str)),
    "Amount extraction sink (coin::take)",
    scope="statement",
)
define_fact(
    "ValueExtractionSink",
    (("func_name", str), ("stmt_id", str), ("callee", str)),
    "Value extraction sink (withdraw_all, from_balance)",
    scope="statement",
)
define_fact(
    "ObjectDestroySink",
    (("func_name", str), ("stmt_id", str), ("callee", str)),
    "Object destroy sink",
    scope="statement",
)
define_fact(
    "DestroysCapability",
    (("func_name", str), ("cap_type", str), ("stmt_id", str)),
    "Function destroys a capability struct",
    scope="statement",
)

# =============================================================================
# FACT DEFINITIONS - Address class tracking (cap_ir foundation)
# =============================================================================
# AddressClass classification for semantic address origin tracking:
# - deployer: sender() in init (package deployer)
# - tx_sender: sender() at runtime (caller)
# - literal: hardcoded @0x... address
# - field_of: address stored in object field
# - unknown: cannot determine statically

define_fact(
    "AddressSource",
    (("func_name", str), ("var", str), ("address_class", str), ("details", str)),
    "Variable holds address from specific source class (deployer/tx_sender/literal/field_of/unknown)",
    scope="statement",
)
define_fact(
    "CapabilityOwner",
    (("cap_type", str), ("address_class", str)),
    "Capability type is owned by address class (determined from init transfer pattern)",
    scope="struct",
)
define_fact(
    "CapabilityTakeover",
    (("func_name", str), ("cap_type", str), ("from_class", str), ("to_class", str)),
    "Function enables capability transfer from one address class to another (potential takeover)",
    scope="function",
)
define_fact(
    "PhantomTypeMismatch",
    (
        ("func_name", str),
        ("guard_param", str),
        ("guard_type", str),
        ("guard_phantom_var", str),
        ("target_param", str),
        ("target_type", str),
        ("target_phantom_var", str),
    ),
    "Function has capability guard with phantom type T but operates on object with different phantom type U",
    scope="function",
)
define_fact(
    "CapabilityLeakViaStore",
    (
        ("shared_struct", str),
        ("field_name", str),
        ("cap_type", str),
    ),
    "Capability stored in shared object field (accessible to anyone)",
    scope="struct",
)
define_fact(
    "EventEmitSink",
    (("func_name", str), ("stmt_id", str), ("event_type", str)),
    "Event emit sink",
    scope="statement",
)
define_fact(
    "LoopBoundSink",
    (("func_name", str), ("stmt_id", str), ("var", str)),
    "Loop bound sink (iteration count)",
    scope="statement",
)
define_fact(
    "SinkUsesVar",
    (("func_name", str), ("stmt_id", str), ("var", str), ("cap", str)),
    "Sink uses variable in specific capability",
    scope="statement",
)
define_fact(
    "EventFieldValue",
    (("func_name", str), ("stmt_id", str), ("event_type", str), ("field_name", str), ("field_vars", tuple)),
    "Field value in event emit",
    scope="statement",
)
define_fact(
    "EventFieldFromField",
    (
        ("func_name", str),
        ("stmt_id", str),
        ("event_type", str),
        ("target_field", str),
        ("source_field", str),
        ("base_vars", tuple),
    ),
    "Event field copied from struct field (potential info leak)",
    scope="statement",
)
define_fact(
    "FieldAccessChain",
    (
        ("func_name", str),
        ("stmt_id", str),
        ("base_var", str),
        ("field_path", tuple),
    ),
    "Nested field access chain: base.field1.field2...",
    scope="statement",
)
define_fact(
    "CallArgFieldAccess",
    (
        ("func_name", str),
        ("stmt_id", str),
        ("callee", str),
        ("arg_idx", int),
        ("base_var", str),
        ("field", str),
    ),
    "Call argument contains field access (obj.field passed to function)",
    scope="statement",
)

# =============================================================================
# FACT DEFINITIONS - Taint reachability (derived facts)
# =============================================================================

define_fact(
    "TaintedAtSink",
    (("func_name", str), ("source", str), ("stmt_id", str), ("sink_type", str), ("cap", str)),
    "Tainted value reaches a sink (sink_type: transfer_recipient|transfer_value|state_write|amount_extraction|object_destroy|loop_bound|event_field|generic)",
    scope="statement",
)

define_fact(
    "SanitizedAtSink",
    (("func_name", str), ("source", str), ("stmt_id", str), ("sink_type", str), ("cap", str)),
    "Sanitized value reaches a sink (sink_type: transfer_recipient|transfer_value|state_write|amount_extraction|object_destroy|loop_bound|event_field|generic)",
    scope="statement",
)

# =============================================================================
# FACT DEFINITIONS - Generic tracked sources
# =============================================================================
# Unified tracking for values derived from specific source types.
# Source types: "sender", "weak_random"

define_fact(
    "TrackedSource",
    (("func_name", str), ("stmt_id", str), ("result_var", str), ("source_type", str), ("callee", str)),
    "Variable assigned from a tracked source (sender, weak_random)",
    scope="statement",
)
define_fact(
    "TrackedDerived",
    (("func_name", str), ("var", str), ("source_type", str)),
    "Variable is derived from a tracked source type",
    scope="statement",
)
define_fact(
    "TrackedDerivedFrom",
    (("func_name", str), ("var", str), ("source_type", str), ("callee", str)),
    "Variable is derived from tracked source with original callee",
    scope="statement",
)
define_fact(
    "SenderDerivedParam",
    (("func_name", str), ("param_idx", int)),
    "Function parameter receives sender value at call sites",
    scope="function",
)

# =============================================================================
# FACT DEFINITIONS - Amount Extraction
# =============================================================================

define_fact(
    "AmountExtraction",
    (("func_name", str), ("stmt_id", str), ("result_var", str), ("source_var", str)),
    "Amount extraction operation",
    scope="statement",
)

# =============================================================================
# FACT DEFINITIONS - Project scope (cross-file features)
# =============================================================================

define_fact(
    "FeatureVersion",
    (("has_feature", bool),),
    "Project uses Sui-style versioning pattern",
    requires_llm=True,
    scope="project",
)

define_fact(
    "FeaturePause",
    (("has_feature", bool),),
    "Project has global pause mechanism",
    requires_llm=True,
    scope="project",
)

define_fact(
    "IsGlobalPauseField",
    (("struct_name", str), ("field_name", str)),
    "Struct and field holding global pause state (from PauseDetector)",
    requires_llm=True,
    scope="project",
)

define_fact(
    "IsPauseControl",
    (("func_name", str),),
    "Function that controls pause state (pause/unpause)",
    requires_llm=True,
    scope="project",
)

# Valid project categories for ProjectCategory fact
# Maps category_id -> human-readable name for LLM prompts
PROJECT_CATEGORIES: Dict[str, str] = {
    "bridge": "cross-chain bridge",
    "gaming": "blockchain game",
    "nft_marketplace": "NFT marketplace",
    "governance": "governance/DAO",
    "oracle": "oracle/price feed",
    "token": "token contract",
    "infrastructure": "infrastructure/library",
}

define_fact(
    "ProjectCategory",
    (("category", str), ("probability", float)),
    "Project category classification (only emitted if probability >= 0.7)",
    requires_llm=True,
    scope="project",
)


# =============================================================================
# FACT CLASS
# =============================================================================


@dataclass
class Fact:
    """
    Single Datalog-style fact.

    IMPORTANT: All facts must be registered in FACT_REGISTRY.
    Attempting to create a Fact with an unregistered name raises UnregisteredFactError.
    """

    name: str
    args: Tuple[Any, ...]
    description: Optional[str] = field(default=None, compare=False)

    def __post_init__(self):
        """Validate fact is registered and has correct argument count."""
        if self.name not in FACT_REGISTRY:
            raise UnregisteredFactError(
                f"Fact '{self.name}' is not registered. Add it to core/facts.py using define_fact()."
            )
        schema = FACT_REGISTRY[self.name]
        expected_count = len(schema.args)
        actual_count = len(self.args)
        if actual_count != expected_count:
            raise ValueError(f"Fact '{self.name}' expects {expected_count} args, got {actual_count}: {self.args}")

    @property
    def schema(self) -> Optional[FactSchema]:
        """Get the schema for this fact type."""
        return FACT_REGISTRY.get(self.name)

    def get_description(self) -> str:
        """Get human-readable description."""
        if self.description:
            return self.description
        schema = self.schema
        return schema.description if schema else ""


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def get_all_fact_schemas() -> List[FactSchema]:
    """Get all registered fact schemas."""
    return list(FACT_REGISTRY.values())


def get_facts_by_scope(scope: Scope) -> List[FactSchema]:
    """Get all fact schemas for a given scope."""
    return [s for s in FACT_REGISTRY.values() if s.scope == scope]


def fact_exists(facts: List[Fact], name: str, args: Tuple[Any, ...]) -> bool:
    """Check if a fact exists (ignoring boolean value for semantic facts)."""
    for fact in facts:
        if fact.name == name:
            if len(fact.args) == len(args) + 1 and isinstance(fact.args[-1], bool):
                if fact.args[:-1] == args:
                    return True
            elif fact.args == args:
                return True
    return False


def get_fact_boolean(facts: List[Fact], name: str, args: Tuple[Any, ...]) -> Optional[bool]:
    """Get the boolean value stored in a semantic fact, or None if not found."""
    for fact in facts:
        if fact.name == name:
            if len(fact.args) == len(args) + 1 and isinstance(fact.args[-1], bool):
                if fact.args[:-1] == args:
                    return fact.args[-1]
            elif fact.args == args:
                return True
    return None


def add_fact(
    facts: List[Fact],
    name: str,
    args: Tuple[Any, ...],
    description: Optional[str] = None,
) -> None:
    """Add a fact to the facts list."""
    facts.append(Fact(name, args, description))


def _get_facts_0(facts: List[Fact], name: str) -> List[str]:
    return [f.args[0] for f in facts if f.name == name]


def _get_facts_2(facts: List[Fact], name: str) -> List[str]:
    return [f.args[0] for f in facts if f.name == name and len(f.args) >= 2 and f.args[1] is True]


def get_all_structs(facts: List[Fact]) -> List[str]:
    return _get_facts_0(facts, "Struct")


def get_caps(facts: List[Fact]) -> List[str]:
    return _get_facts_0(facts, "IsCapability")


def get_events(facts: List[Fact]) -> List[str]:
    return _get_facts_0(facts, "IsEvent")


def names_match(a: str, b: str) -> bool:
    """Match qualified names: full match OR simple name match."""
    if a == b:
        return True
    return get_simple_name(a) == get_simple_name(b)


def has_fact_for_name(facts: List[Fact], fact_name: str, target_name: str) -> bool:
    """Check if fact exists for target_name (handles qualified name matching)."""
    for f in facts:
        if f.name == fact_name and f.args and names_match(f.args[0], target_name):
            return True
    return False


# =============================================================================
# FACT QUERY HELPERS FOR REPORTER CONTEXT
# =============================================================================
# These helpers provide O(1) fact lookups using global_facts_index.
# Used by reporter.py to extract context for violation messages.


def get_facts_for_function(func_name: str, ctx: Any) -> List[Fact]:
    """Get all facts for a function using global_facts_index (O(1) lookup).

    Args:
        func_name: Fully qualified function name
        ctx: ProjectContext instance

    Returns:
        List of facts for this function across all files
    """
    result = []
    if func_name in ctx.global_facts_index:
        for file_facts in ctx.global_facts_index[func_name].values():
            result.extend(file_facts)
    return result


def find_fact(func_name: str, fact_name: str, ctx: Any) -> Optional[Fact]:
    """Find first fact of given type for a function.

    Uses global_facts_index for O(1) lookup instead of iterating all files.
    """
    facts = get_facts_for_function(func_name, ctx)
    for fact in facts:
        if fact.name == fact_name:
            return fact
    return None


def find_facts(func_name: str, fact_name: str, ctx: Any) -> List[Fact]:
    """Find all facts of given type for a function.

    Uses global_facts_index for O(1) lookup.
    """
    facts = get_facts_for_function(func_name, ctx)
    return [f for f in facts if f.name == fact_name]


def collect_facts_from_all_files(fact_name: str, ctx: Any) -> List[Fact]:
    """Collect all facts of given type across all source files.

    Used for non-function-scoped facts (struct-level, project-level).
    """
    result = []
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == fact_name:
                result.append(fact)
    return result
