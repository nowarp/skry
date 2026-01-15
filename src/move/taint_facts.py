from typing import List, Optional

from core.facts import Fact
from core.utils import get_simple_name
from .extract import is_reference_type
from .sui_patterns import (
    SENDER_SOURCES,
    TRANSFER_SINKS,
    TRANSFER_RECIPIENT_ARG_INDEX,
    STATE_WRITE_PATTERNS,
    AMOUNT_EXTRACTION_PATTERNS,
    VALUE_EXTRACTION_PATTERNS,
    OBJECT_DESTROY_PATTERNS,
)
from .ir import (
    Function,
    Stmt,
    LetStmt,
    ExprStmt,
    ReturnStmt,
    IfStmt,
    AbortStmt,
    WhileStmt,
    LoopStmt,
    AssignStmt,
    Call,
    BinOp,
    UnaryOp,
    Borrow,
    Deref,
    VarRef,
    FieldAccess,
    StructPack,
    Cast,
    Expr,
    expr_vars,
    expr_field_accesses,
    expr_field_chain,
    expr_calls,
    stmt_vars,
)


def is_sender_source(callee: str) -> bool:
    """Check if callee returns the transaction sender address.

    Handles both traditional call syntax and method-call syntax:
    - tx_context::sender(ctx) → callee is "tx_context::sender" or "sui::tx_context::sender"
    - ctx.sender() → callee is "module::sender" or just "sender" (method call desugaring)

    Matches the logic in analysis/access_control.py:generate_calls_sender_facts()
    """
    if callee in SENDER_SOURCES:
        return True
    simple_name = get_simple_name(callee)
    # Match any function with simple name "sender" or ending with "::sender"
    # This handles method-call syntax: ctx.sender() → "module::sender" or "sender"
    return simple_name == "sender" or callee.endswith("::sender")


# =============================================================================
# SENDER CAST DETECTION - Upgrade sender tag to weak_random on integer cast
# =============================================================================
# When sender() is cast to an integer type, it signals use as randomness.
# Auth patterns never cast addresses to integers, so this is a strong signal.

INTEGER_TYPES = {"u8", "u16", "u32", "u64", "u128", "u256"}


def _contains_cast_to_int(expr) -> bool:
    """Check if expr contains a cast to integer type anywhere in the tree."""
    if isinstance(expr, Cast) and expr.target_type in INTEGER_TYPES:
        return True
    if isinstance(expr, BinOp):
        return _contains_cast_to_int(expr.left) or _contains_cast_to_int(expr.right)
    if isinstance(expr, UnaryOp):
        return _contains_cast_to_int(expr.operand)
    if isinstance(expr, (Borrow, Deref)):
        return _contains_cast_to_int(expr.inner)
    return False


def _extract_vars_cast_to_int(expr) -> List[str]:
    """Extract variables that are cast to integer types.

    For expr like (sender as u64) % 100, returns ['sender'].
    For expr like ((a as u64) + (b as u128)), returns ['a', 'b'].
    """
    vars_cast = []

    def collect_cast_vars(e):
        if isinstance(e, Cast) and e.target_type in INTEGER_TYPES:
            # Found a cast - extract vars from the inner expression
            vars_cast.extend(expr_vars(e.inner))
        elif isinstance(e, BinOp):
            collect_cast_vars(e.left)
            collect_cast_vars(e.right)
        elif isinstance(e, UnaryOp):
            collect_cast_vars(e.operand)
        elif isinstance(e, (Borrow, Deref)):
            collect_cast_vars(e.inner)

    collect_cast_vars(expr)
    return vars_cast


def _contains_sender_cast(expr) -> bool:
    """Check if expr contains sender() wrapped in integer cast."""
    if isinstance(expr, Cast) and expr.target_type in INTEGER_TYPES:
        return _contains_sender_call(expr.inner)
    if isinstance(expr, BinOp):
        return _contains_sender_cast(expr.left) or _contains_sender_cast(expr.right)
    return False


def _contains_sender_call(expr) -> bool:
    """Check if expr contains a sender() call."""
    if isinstance(expr, Call) and is_sender_source(expr.callee):
        return True
    if isinstance(expr, Cast):
        return _contains_sender_call(expr.inner)
    if isinstance(expr, BinOp):
        return _contains_sender_call(expr.left) or _contains_sender_call(expr.right)
    return False


# =============================================================================
# WEAK RANDOMNESS SOURCES - predictable "random" values
# =============================================================================
# These functions return values that are publicly visible or predictable,
# making them unsuitable for security-critical randomness (gambling, lotteries, etc.)

WEAK_RANDOMNESS_SOURCES = {
    # Clock-based - publicly visible, miner can influence
    "clock::timestamp_ms",
    "sui::clock::timestamp_ms",
    "one::clock::timestamp_ms",  # One framework alias
    # Epoch/block-based - same for entire epoch, predictable
    "tx_context::epoch",
    "sui::tx_context::epoch",
    "one::tx_context::epoch",  # One framework alias
    "tx_context::epoch_timestamp_ms",
    "sui::tx_context::epoch_timestamp_ms",
    "one::tx_context::epoch_timestamp_ms",  # One framework alias
    # UID-based - deterministic from creation order
    "object::uid_to_bytes",
    "sui::object::uid_to_bytes",
    "one::object::uid_to_bytes",  # One framework alias
    "object::uid_to_inner",
    "sui::object::uid_to_inner",
    "one::object::uid_to_inner",  # One framework alias
    "object::uid_to_address",
    "sui::object::uid_to_address",
    "one::object::uid_to_address",  # One framework alias
    # Digest-based - visible after tx submission
    "tx_context::digest",
    "sui::tx_context::digest",
    "one::tx_context::digest",  # One framework alias
    # NOTE: tx_context::sender removed - almost always used for identity/auth, not randomness
}


# =============================================================================
# PRECOMPUTED SUFFIX SETS - O(1) lookup instead of O(n) iteration
# =============================================================================
def _build_suffix_set(patterns) -> frozenset:
    """Build frozenset of simple function names from qualified patterns."""
    return frozenset(get_simple_name(p) for p in patterns)


_WEAK_RANDOMNESS_SUFFIXES = _build_suffix_set(WEAK_RANDOMNESS_SOURCES)


def is_weak_randomness_source(callee: str) -> bool:
    """Check if callee returns predictable/weak randomness."""
    if callee in WEAK_RANDOMNESS_SOURCES:
        return True
    simple_name = get_simple_name(callee)
    return simple_name in _WEAK_RANDOMNESS_SUFFIXES


# =============================================================================
# SANITIZATION PATTERNS - validation checks that make tainted values safe
# =============================================================================

# Comparison operators that indicate bounds checking
COMPARISON_OPS = {"<", "<=", ">", ">=", "==", "!="}

# Functions that clamp/bound values (result is sanitized)
SANITIZING_FUNCTIONS = {
    "math::min",
    "math::max",
    "sui::math::min",
    "sui::math::max",
    "std::u64::min",
    "std::u64::max",
    "std::u128::min",
    "std::u128::max",
}

# Assertion functions used for bounds checking
ASSERT_FUNCTIONS = {"assert!", "assert"}

_SANITIZING_SUFFIXES = _build_suffix_set(SANITIZING_FUNCTIONS)


def is_sanitizing_function(callee: str) -> bool:
    """Check if callee is a sanitizing/clamping function."""
    if callee in SANITIZING_FUNCTIONS:
        return True
    simple_name = get_simple_name(callee)
    return simple_name in _SANITIZING_SUFFIXES


def is_comparison_op(op: str) -> bool:
    """Check if operator is a comparison that could sanitize."""
    return op in COMPARISON_OPS


# Precompute suffix sets for all pattern types
_TRANSFER_SINK_SUFFIXES = _build_suffix_set(TRANSFER_SINKS)
_OBJECT_DESTROY_SUFFIXES = _build_suffix_set(OBJECT_DESTROY_PATTERNS)
_STATE_WRITE_SUFFIXES = _build_suffix_set(STATE_WRITE_PATTERNS)
_VALUE_EXTRACTION_SUFFIXES = _build_suffix_set(VALUE_EXTRACTION_PATTERNS)


def is_transfer_sink(callee: str) -> bool:
    if callee in TRANSFER_SINKS:
        return True
    simple_name = get_simple_name(callee)
    return simple_name in _TRANSFER_SINK_SUFFIXES


def is_object_destroy_sink(callee: str) -> bool:
    if callee in OBJECT_DESTROY_PATTERNS:
        return True
    simple_name = get_simple_name(callee)
    return simple_name in _OBJECT_DESTROY_SUFFIXES


def is_state_write_sink(callee: str) -> bool:
    if callee in STATE_WRITE_PATTERNS:
        return True
    simple_name = get_simple_name(callee)
    return simple_name in _STATE_WRITE_SUFFIXES


def is_value_extraction(callee: str) -> bool:
    """Check if callee is a value extraction function (withdraw_all, from_balance, etc.)."""
    if callee in VALUE_EXTRACTION_PATTERNS:
        return True
    simple_name = get_simple_name(callee)
    return simple_name in _VALUE_EXTRACTION_SUFFIXES


# =============================================================================
# EVENT EMISSION SINKS - where data becomes publicly visible on-chain
# =============================================================================
EVENT_EMIT_PATTERNS = {
    "event::emit",
    "sui::event::emit",
    "0x2::event::emit",
}
_EVENT_EMIT_SUFFIXES = _build_suffix_set(EVENT_EMIT_PATTERNS)


def is_event_emit(callee: str) -> bool:
    """Check if callee is an event emission function."""
    if callee in EVENT_EMIT_PATTERNS:
        return True
    simple_name = get_simple_name(callee)
    # Must have "event::" prefix or be exactly "emit" with event context
    return simple_name == "emit" and ("event::" in callee or callee == "emit")


# Precompute suffix -> index mappings for O(1) lookup
_AMOUNT_SUFFIX_TO_IDX = {get_simple_name(p): idx for p, idx in AMOUNT_EXTRACTION_PATTERNS.items()}


def get_amount_arg_index(callee: str) -> int:
    """Returns the argument index for the amount parameter, or -1 if not an extraction pattern."""
    if callee in AMOUNT_EXTRACTION_PATTERNS:
        return AMOUNT_EXTRACTION_PATTERNS[callee]
    simple_name = get_simple_name(callee)
    return _AMOUNT_SUFFIX_TO_IDX.get(simple_name, -1)


# Precompute suffix -> index mapping for transfer recipient positions
_TRANSFER_RECIPIENT_SUFFIX_TO_IDX = {get_simple_name(p): idx for p, idx in TRANSFER_RECIPIENT_ARG_INDEX.items()}


def get_transfer_recipient_arg_index(callee: str) -> int:
    """Returns the argument index for the recipient parameter in a transfer sink.

    Default is -1 (last arg) for most transfer functions.
    Returns -2 for functions with TxContext as last parameter (mint_and_transfer, etc.)
    """
    # Check exact match first
    if callee in TRANSFER_RECIPIENT_ARG_INDEX:
        return TRANSFER_RECIPIENT_ARG_INDEX[callee]
    # Check simple name match
    simple_name = get_simple_name(callee)
    if simple_name in _TRANSFER_RECIPIENT_SUFFIX_TO_IDX:
        return _TRANSFER_RECIPIENT_SUFFIX_TO_IDX[simple_name]
    # Default: recipient is last argument
    return -1


def generate_taint_base_facts(func: Function) -> List[Fact]:
    """Generate base facts for taint analysis."""
    facts = []

    # TaintSource(func, param_name, param_idx)
    # Skip reference params - they represent object access, not user-provided values
    for param in func.params:
        if not is_reference_type(param.typ):
            facts.append(Fact("TaintSource", (func.name, param.name, param.idx)))

    # Walk statements
    for stmt in func.body:
        facts.extend(generate_stmt_facts(func.name, stmt))

    return facts


def generate_stmt_facts(func_name: str, stmt: Stmt) -> List[Fact]:
    """Generate facts from a single statement."""
    facts = []

    if isinstance(stmt, LetStmt):
        # Assigns(func, stmt_id, lhs_var, [rhs_vars])
        rhs_vars = expr_vars(stmt.value) if stmt.value else []
        facts.append(Fact("Assigns", (func_name, stmt.id, stmt.bindings[0], tuple(rhs_vars))))

        # Track when sender-derived variable is cast to integer (two-step pattern)
        # let sender = sender(ctx);  // tag: "sender"
        # let seed = (sender as u64);  // must upgrade to "weak_random"
        # Also handles: let winner = (sender as u64) % 100;
        if stmt.value and _contains_cast_to_int(stmt.value):
            # Extract which variables are being cast to int
            cast_vars = _extract_vars_cast_to_int(stmt.value)
            if cast_vars:
                # Generate fact indicating this assignment casts to int
                # Will be used to upgrade sender -> weak_random during taint propagation
                facts.append(Fact("CastsToInt", (func_name, stmt.id, stmt.bindings[0], tuple(cast_vars))))

        # Track field value assignments: let x = obj.field
        # FieldAssign(func, stmt_id, target_var, base_var, field)
        field_accesses = expr_field_accesses(stmt.value) if stmt.value else []
        for base_vars, field in field_accesses:
            for base_var in base_vars:
                facts.append(Fact("FieldAssign", (func_name, stmt.id, stmt.bindings[0], base_var, field)))

        # Track calls specially
        if isinstance(stmt.value, Call):
            call = stmt.value
            # CallResult(func, stmt_id, result_var, callee)
            facts.append(Fact("CallResult", (func_name, stmt.id, stmt.bindings[0], call.callee)))

            # Track sender sources (tx_context::sender)
            # Upgrade to "weak_random" tag if sender is cast to integer (randomness pattern)
            if is_sender_source(call.callee):
                tag = "weak_random" if _contains_sender_cast(stmt.value) else "sender"
                facts.append(Fact("TrackedSource", (func_name, stmt.id, stmt.bindings[0], tag, call.callee)))

            # Track weak randomness sources
            if is_weak_randomness_source(call.callee):
                facts.append(Fact("TrackedSource", (func_name, stmt.id, stmt.bindings[0], "weak_random", call.callee)))

            # CallArg(func, stmt_id, callee, arg_idx, [arg_vars])
            for idx, arg in enumerate(call.args):
                arg_vars = expr_vars(arg)
                facts.append(Fact("CallArg", (func_name, stmt.id, call.callee, idx, tuple(arg_vars))))
                # Track field accesses in call arguments for IPA sensitive field detection
                if isinstance(arg, FieldAccess):
                    base_vars = expr_vars(arg.base)
                    if base_vars:
                        facts.append(
                            Fact("CallArgFieldAccess", (func_name, stmt.id, call.callee, idx, base_vars[0], arg.field))
                        )
                # Track casts-to-int within call arguments (for weak randomness detection)
                if _contains_cast_to_int(arg):
                    cast_vars = _extract_vars_cast_to_int(arg)
                    for cv in cast_vars:
                        facts.append(Fact("CastsToInt", (func_name, stmt.id, f"__call_arg_{call.callee}_{idx}", (cv,))))

            # GenericCallArg(func, stmt_id, callee, type_arg_idx, type_var)
            # Track type arguments that correspond to function's own type parameters
            # This is used for precise generic type validation tracking
            for type_idx, type_arg in enumerate(call.type_args):
                # Type argument is just a simple name (e.g., "T", "U") - it's a type parameter reference
                # We don't qualify it since it refers to the caller's type parameter
                facts.append(Fact("GenericCallArg", (func_name, stmt.id, call.callee, type_idx, type_arg)))

            # Track amount extraction: coin::take(balance, AMOUNT, ctx) -> coins
            # The result var inherits "tainted amount" if amount arg is tainted
            amount_idx = get_amount_arg_index(call.callee)
            if amount_idx >= 0 and amount_idx < len(call.args):
                # Mark that this is an extraction sink
                facts.append(Fact("AmountExtractionSink", (func_name, stmt.id, call.callee)))
                amount_vars = expr_vars(call.args[amount_idx])
                for v in amount_vars:
                    # Mark that this extraction's result depends on amount var
                    facts.append(Fact("AmountExtraction", (func_name, stmt.id, stmt.bindings[0], v)))

            # Track value extraction sinks (withdraw_all, from_balance) in let statements
            if is_value_extraction(call.callee):
                facts.append(Fact("ValueExtractionSink", (func_name, stmt.id, call.callee)))

            # StateWriteSink for let bindings: let x = table::borrow_mut(...)
            if is_state_write_sink(call.callee):
                facts.append(Fact("StateWriteSink", (func_name, stmt.id, call.callee)))
                for idx, arg in enumerate(call.args):
                    arg_vars = expr_vars(arg)
                    for v in arg_vars:
                        facts.append(Fact("SinkUsesVar", (func_name, stmt.id, v, f"arg_{idx}")))

            # TransferSink for let bindings: let result = transfer::transfer(...)
            if is_transfer_sink(call.callee):
                facts.append(Fact("TransferSink", (func_name, stmt.id, call.callee)))
                recipient_idx = get_transfer_recipient_arg_index(call.callee)
                if abs(recipient_idx) <= len(call.args):
                    recipient_vars = expr_vars(call.args[recipient_idx])
                    for v in recipient_vars:
                        facts.append(Fact("SinkUsesVar", (func_name, stmt.id, v, "recipient")))
                # Track transfer value (first arg)
                if len(call.args) >= 2:
                    transfer_value_vars = expr_vars(call.args[0])
                    for v in transfer_value_vars:
                        facts.append(Fact("SinkUsesVar", (func_name, stmt.id, v, "transfer_value")))

            # ObjectDestroySink for let bindings: let result = object::delete(...)
            if is_object_destroy_sink(call.callee):
                facts.append(Fact("ObjectDestroySink", (func_name, stmt.id, call.callee)))
                if call.args:
                    destroy_vars = expr_vars(call.args[0])
                    for v in destroy_vars:
                        facts.append(Fact("SinkUsesVar", (func_name, stmt.id, v, "destroyed_object")))

        # Handle nested calls (e.g., inside struct initializers, method chains)
        # let evt = Event { token_type: type_name::get<T>() }
        # let result = type_name::get<T>().into_string()  # receiver call has type args
        # The direct Call case above handles top-level calls; this handles nested ones
        if stmt.value:
            for nested_call in expr_calls(stmt.value):
                # Skip top-level call (already processed above)
                if nested_call is stmt.value:
                    continue
                # GenericCallArg for type arguments
                for type_idx, type_arg in enumerate(nested_call.type_args):
                    facts.append(Fact("GenericCallArg", (func_name, stmt.id, nested_call.callee, type_idx, type_arg)))
                # CallArg for regular arguments (needed for TxContext tracking)
                for idx, arg in enumerate(nested_call.args):
                    arg_vars = expr_vars(arg)
                    facts.append(Fact("CallArg", (func_name, stmt.id, nested_call.callee, idx, tuple(arg_vars))))

        # Track sanitization via clamping functions: let x = min(var, max_val)
        if isinstance(stmt.value, Call) and is_sanitizing_function(stmt.value.callee):
            clamp_call = stmt.value
            # The result of min/max is considered sanitized
            # All input vars are "sanitized" in the sense that the result is bounded
            for arg in clamp_call.args:
                arg_vars = expr_vars(arg)
                for v in arg_vars:
                    facts.append(Fact("SanitizedByClamping", (func_name, stmt.id, stmt.bindings[0], v)))

        # Handle method call syntax: let authority = ctx.sender()
        # This is parsed as FieldAccess with field='sender()' instead of a Call
        if isinstance(stmt.value, FieldAccess) and stmt.value.field.endswith("()"):
            method_name = stmt.value.field[:-2]  # Remove trailing "()"
            if method_name == "sender":
                # This is a sender method call: ctx.sender()
                # Generate TrackedSource for sender tracking
                callee = f"{func_name.rsplit('::', 1)[0]}::sender"  # e.g., "test::iterator::sender"
                facts.append(Fact("TrackedSource", (func_name, stmt.id, stmt.bindings[0], "sender", callee)))

    elif isinstance(stmt, ExprStmt) and isinstance(stmt.expr, Call):
        call = stmt.expr

        # CallArg(func, stmt_id, callee, arg_idx, [arg_vars]) - for ALL calls
        for idx, arg in enumerate(call.args):
            arg_vars = expr_vars(arg)
            facts.append(Fact("CallArg", (func_name, stmt.id, call.callee, idx, tuple(arg_vars))))
            # Track field accesses in call arguments for IPA sensitive field detection
            if isinstance(arg, FieldAccess):
                base_vars = expr_vars(arg.base)
                if base_vars:
                    facts.append(
                        Fact("CallArgFieldAccess", (func_name, stmt.id, call.callee, idx, base_vars[0], arg.field))
                    )

            # Track casts to int in call arguments
            # process_sender((sender as u64)) - the cast upgrades sender -> weak_random
            if _contains_cast_to_int(arg):
                cast_vars = _extract_vars_cast_to_int(arg)
                for cv in cast_vars:
                    facts.append(Fact("CastsToInt", (func_name, stmt.id, f"__call_arg_{call.callee}_{idx}", (cv,))))

        # GenericCallArg(func, stmt_id, callee, type_arg_idx, type_var)
        for type_idx, type_arg in enumerate(call.type_args):
            facts.append(Fact("GenericCallArg", (func_name, stmt.id, call.callee, type_idx, type_arg)))

        # GenericCallArg for nested calls in receiver (method chains: type_name::get<T>().into_string())
        if call.receiver:
            for nested_call in expr_calls(call.receiver):
                for type_idx, type_arg in enumerate(nested_call.type_args):
                    facts.append(Fact("GenericCallArg", (func_name, stmt.id, nested_call.callee, type_idx, type_arg)))
                # CallArg for nested call arguments
                for idx, arg in enumerate(nested_call.args):
                    arg_vars = expr_vars(arg)
                    facts.append(Fact("CallArg", (func_name, stmt.id, nested_call.callee, idx, tuple(arg_vars))))

        # GenericCallArg for nested calls in arguments (e.g., event::emit(Event { f: get<T>() }))
        for arg in call.args:
            for nested_call in expr_calls(arg):
                for type_idx, type_arg in enumerate(nested_call.type_args):
                    facts.append(Fact("GenericCallArg", (func_name, stmt.id, nested_call.callee, type_idx, type_arg)))

        # Track assert! with comparison - indicates bounds checking
        # assert!(amount <= max_amount, ...) sanitizes 'amount'
        if call.callee in ASSERT_FUNCTIONS and len(call.args) >= 1:
            # First arg is the condition
            cond = call.args[0]
            sanitized_vars = _extract_comparison_vars(cond)
            for v in sanitized_vars:
                facts.append(Fact("SanitizedByAssert", (func_name, stmt.id, v)))

            # Track condition check for field-based guards (pause, frozen, etc.)
            # assert!(!config.paused, E_PAUSED) checks the pause field
            cond_vars = expr_vars(cond)
            facts.append(Fact("ConditionCheck", (func_name, stmt.id, tuple(cond_vars))))

            # Track field accesses in assert condition
            cond_field_accesses = expr_field_accesses(cond)
            for base_vars, field in cond_field_accesses:
                for base_var in base_vars:
                    facts.append(Fact("ConditionFieldAccess", (func_name, stmt.id, base_var, field)))

            # Track direct sender() calls in assertions for sender equality checks
            # assert!(tx_context::sender(ctx) == @admin, 0) or assert!(owner == tx_context::sender(ctx), 0)
            if _has_sender_call_in_comparison(cond):
                facts.append(Fact("SenderCallInAssertion", (func_name, stmt.id)))

        # Sink detection
        if is_transfer_sink(call.callee):
            facts.append(Fact("TransferSink", (func_name, stmt.id, call.callee)))
            # Which var goes to recipient? Get correct arg index for this transfer function
            recipient_idx = get_transfer_recipient_arg_index(call.callee)
            if abs(recipient_idx) <= len(call.args):
                recipient_arg = call.args[recipient_idx]
                recipient_vars = expr_vars(recipient_arg)
                for v in recipient_vars:
                    facts.append(Fact("SinkUsesVar", (func_name, stmt.id, v, "recipient")))
                # Track direct sender calls as transfer recipient (e.g., transfer(..., tx_context::sender(ctx)))
                if _has_sender_call(recipient_arg):
                    facts.append(Fact("DirectSenderInTransfer", (func_name, stmt.id)))
            # Which var is being transferred? (first arg - the coin/object)
            if len(call.args) >= 2:
                transfer_value_vars = expr_vars(call.args[0])
                for v in transfer_value_vars:
                    facts.append(Fact("SinkUsesVar", (func_name, stmt.id, v, "transfer_value")))

        if is_state_write_sink(call.callee):
            facts.append(Fact("StateWriteSink", (func_name, stmt.id, call.callee)))
            # Which vars go to state write? All arguments are relevant for state writes.
            for idx, arg in enumerate(call.args):
                arg_vars = expr_vars(arg)
                for v in arg_vars:
                    facts.append(Fact("SinkUsesVar", (func_name, stmt.id, v, f"arg_{idx}")))

        # Track amount extraction sinks (balance::split, coin::take)
        # These are sinks where the AMOUNT argument controls how much is extracted
        amount_idx = get_amount_arg_index(call.callee)
        if amount_idx >= 0 and amount_idx < len(call.args):
            facts.append(Fact("AmountExtractionSink", (func_name, stmt.id, call.callee)))
            amount_vars = expr_vars(call.args[amount_idx])
            for v in amount_vars:
                facts.append(Fact("SinkUsesVar", (func_name, stmt.id, v, "amount")))

        # Track value extraction sinks (withdraw_all, from_balance)
        # These extract value without user-controlled amount parameter
        if is_value_extraction(call.callee):
            facts.append(Fact("ValueExtractionSink", (func_name, stmt.id, call.callee)))

        # Track object destruction sinks (object::delete, coin::burn)
        # If user controls what gets destroyed, they could destroy valuable objects
        if is_object_destroy_sink(call.callee):
            facts.append(Fact("ObjectDestroySink", (func_name, stmt.id, call.callee)))
            # First arg is typically the object being destroyed
            if call.args:
                destroy_vars = expr_vars(call.args[0])
                for v in destroy_vars:
                    facts.append(Fact("SinkUsesVar", (func_name, stmt.id, v, "destroyed_object")))

        # Track event emissions with their struct fields
        # event::emit(MyEvent { field1: val1, field2: val2 })
        # This creates EventFieldEmission facts for each field
        if is_event_emit(call.callee) and call.args:
            event_arg = call.args[0]
            if isinstance(event_arg, StructPack):
                struct_name = event_arg.struct_name
                facts.append(Fact("EventEmitSink", (func_name, stmt.id, struct_name)))
                # Track each field and what value flows into it
                for field_name, field_value in event_arg.fields:
                    field_vars = expr_vars(field_value)
                    # EventFieldValue(func, stmt_id, struct_name, field_name, (vars_in_field))
                    facts.append(
                        Fact("EventFieldValue", (func_name, stmt.id, struct_name, field_name, tuple(field_vars)))
                    )
                    # Add sink tracking for IPA propagation
                    for v in field_vars:
                        facts.append(Fact("SinkUsesVar", (func_name, stmt.id, v, "event_field")))
                    # Also check if the field value is a direct field access from another struct
                    # This catches: event::emit(MyEvent { secret: user.password })
                    if isinstance(field_value, FieldAccess):
                        source_field = field_value.field
                        base_vars = expr_vars(field_value.base)
                        # EventFieldFromField(func, stmt_id, struct_name, target_field, source_field, base_vars)
                        facts.append(
                            Fact(
                                "EventFieldFromField",
                                (func_name, stmt.id, struct_name, field_name, source_field, tuple(base_vars)),
                            )
                        )
                        # Track nested field chains (2+ fields) for type resolution.
                        # Single field accesses (e.g., account.key) are already handled
                        # by EventFieldFromField above. FieldAccessChain is only needed for
                        # nested accesses (e.g., account.profile.key) where we need to
                        # resolve intermediate types.
                        chain = expr_field_chain(field_value)
                        if chain and len(chain[1]) > 1:
                            base_var, field_path = chain
                            facts.append(Fact("FieldAccessChain", (func_name, stmt.id, base_var, tuple(field_path))))

    elif isinstance(stmt, ExprStmt) and not isinstance(stmt.expr, Call):
        # Handle nested calls in non-Call expressions (e.g., struct literals as implicit return)
        # MyObject { id: object::new(ctx) } - extract CallArg for nested object::new call
        for nested_call in expr_calls(stmt.expr):
            # GenericCallArg for type arguments
            for type_idx, type_arg in enumerate(nested_call.type_args):
                facts.append(Fact("GenericCallArg", (func_name, stmt.id, nested_call.callee, type_idx, type_arg)))
            # CallArg for regular arguments (needed for TxContext tracking)
            for idx, arg in enumerate(nested_call.args):
                arg_vars = expr_vars(arg)
                facts.append(Fact("CallArg", (func_name, stmt.id, nested_call.callee, idx, tuple(arg_vars))))

    elif isinstance(stmt, IfStmt):
        # Recurse into branches
        for s in stmt.then_body:
            facts.extend(generate_stmt_facts(func_name, s))
        if stmt.else_body:
            for s in stmt.else_body:
                facts.extend(generate_stmt_facts(func_name, s))

        # Track condition for control flow
        cond_vars = expr_vars(stmt.condition)
        facts.append(Fact("ConditionCheck", (func_name, stmt.id, tuple(cond_vars))))

        # Track field accesses in condition: if (obj.field) or if (obj.field == x)
        # ConditionFieldAccess(func, stmt_id, base_var, field)
        cond_field_accesses = expr_field_accesses(stmt.condition)
        for base_vars, field in cond_field_accesses:
            for base_var in base_vars:
                facts.append(Fact("ConditionFieldAccess", (func_name, stmt.id, base_var, field)))

        # Track if-abort pattern for sanitization
        # if (var > limit) { abort } - this sanitizes 'var' after the check
        if _is_abort_branch(stmt.then_body):
            sanitized = _extract_comparison_vars(stmt.condition)
            for v in sanitized:
                facts.append(Fact("SanitizedByAbortCheck", (func_name, stmt.id, v)))

    elif isinstance(stmt, WhileStmt):
        # Track loop bound - the condition variables control iteration count
        # while (i < len) { ... } - 'len' is the loop bound
        bound_vars = _extract_loop_bound_vars(stmt.condition)
        for v in bound_vars:
            facts.append(Fact("LoopBoundSink", (func_name, stmt.id, v)))
            facts.append(Fact("SinkUsesVar", (func_name, stmt.id, v, "loop_bound")))

        # Recurse into body
        for s in stmt.body:
            facts.extend(generate_stmt_facts(func_name, s))

    elif isinstance(stmt, LoopStmt):
        # Infinite loop - check body for break conditions
        # loop { if (i >= len) break; ... } - 'len' is still a bound
        for s in stmt.body:
            # Look for if statements with break that define the bound
            if isinstance(s, IfStmt):
                # Check if then_body or else_body contains break
                if _contains_break(s.then_body) or (s.else_body and _contains_break(s.else_body)):
                    # This is a BREAK condition - semantics are inverted
                    bound_vars = _extract_loop_bound_vars(s.condition, is_break_condition=True)
                    for v in bound_vars:
                        facts.append(Fact("LoopBoundSink", (func_name, stmt.id, v)))
                        facts.append(Fact("SinkUsesVar", (func_name, stmt.id, v, "loop_bound")))
            facts.extend(generate_stmt_facts(func_name, s))

    elif isinstance(stmt, ReturnStmt):
        # Track field accesses in return values for interprocedural tracking
        # ReturnsFieldValue(func, field) - function returns this field's value
        if stmt.value:
            return_field_accesses = expr_field_accesses(stmt.value)
            for _, field in return_field_accesses:
                facts.append(Fact("ReturnsFieldValue", (func_name, field)))

    elif isinstance(stmt, AssignStmt):
        # Handle *ref = val pattern for mutable reference tainting
        # DerefAssigns(func, stmt_id, target_var, (rhs_vars))
        target = stmt.target
        if isinstance(target, Deref) and isinstance(target.inner, VarRef):
            # *param = val - the dereferenced param receives taint from rhs
            param_name = target.inner.name
            rhs_vars = expr_vars(stmt.value)
            if rhs_vars:
                facts.append(Fact("DerefAssigns", (func_name, stmt.id, param_name, tuple(rhs_vars))))

    return facts


def _has_sender_call_in_comparison(expr: Expr) -> bool:
    """Check if expression contains tx_context::sender() call in a comparison.

    Examples:
    - tx_context::sender(ctx) == @admin
    - owner == tx_context::sender(ctx)
    - vault.owner == tx_context::sender(ctx)
    """
    if isinstance(expr, BinOp) and is_comparison_op(expr.op):
        # Check if either side is a sender call
        return _has_sender_call(expr.left) or _has_sender_call(expr.right)
    return False


def _has_sender_call(expr: Expr) -> bool:
    """Recursively check if expression contains a tx_context::sender() call.

    Handles both traditional call syntax and method-call syntax:
    - tx_context::sender(ctx) → Call node with callee "tx_context::sender"
    - ctx.sender() → FieldAccess node with field "sender()" (parser quirk)
    """
    if isinstance(expr, Call):
        return is_sender_source(expr.callee)
    elif isinstance(expr, FieldAccess):
        # Method-call syntax: ctx.sender() is parsed as FieldAccess with field="sender()"
        if expr.field in ("sender", "sender()"):
            return True
        # Recurse into base for chained accesses
        return _has_sender_call(expr.base)
    elif isinstance(expr, BinOp):
        return _has_sender_call(expr.left) or _has_sender_call(expr.right)
    elif isinstance(expr, UnaryOp):
        return _has_sender_call(expr.operand)
    elif isinstance(expr, (Borrow, Deref)):
        return _has_sender_call(expr.inner)
    return False


def _extract_comparison_vars(expr: Expr) -> List[str]:
    """Extract variables from comparison expressions that get sanitized.

    For `x < limit` or `x <= max`, the variable 'x' is being bounded.
    """
    if isinstance(expr, BinOp) and is_comparison_op(expr.op):
        # Both sides could be variable refs
        return expr_vars(expr)
    elif isinstance(expr, Call):
        # Could be assert!(cond, ...) where cond is a comparison
        # Or boolean functions like `is_valid(x)` - not sanitizing
        pass
    return []


def _is_abort_branch(body: List[Stmt]) -> bool:
    """Check if a branch body is just an abort statement."""
    if len(body) == 1 and isinstance(body[0], AbortStmt):
        return True
    # Could also be: if cond { abort 0 } with ExprStmt wrapping abort
    if len(body) == 1 and isinstance(body[0], ExprStmt):
        expr = body[0].expr
        if isinstance(expr, Call) and expr.callee == "abort":
            return True
    return False


def _extract_loop_bound_vars(cond: Expr, is_break_condition: bool = False) -> List[str]:
    """
    Extract variables that control the loop bound from a condition.

    For `i < len` or `i < vector::length(&items)`, we want 'len' or the vector vars.
    The loop counter variable (typically 'i') is NOT the bound - it's the thing being bounded.

    Args:
        cond: The condition expression
        is_break_condition: If True, this is a break condition (loop { if (cond) break; })
                           which has INVERTED semantics - the loop continues while NOT cond

    Strategy for while conditions (is_break_condition=False):
    - For `i < X` or `i <= X`: X is the bound (right side of <, <=)
    - For `X > i` or `X >= i`: X is the bound (left side of >, >=)

    Strategy for break conditions (is_break_condition=True):
    - For `i >= X` or `i > X`: X is the bound (right side) - loop continues while i < X
    - For `X <= i` or `X < i`: X is the bound (left side) - loop continues while i < X
    """
    if not isinstance(cond, BinOp):
        # Not a comparison - extract all vars as potential bounds
        return expr_vars(cond)

    op = cond.op
    left_vars = expr_vars(cond.left)
    right_vars = expr_vars(cond.right)

    # For break conditions, we need to invert: if (i >= len) break means loop while i < len
    if is_break_condition:
        if op in (">", ">="):
            # if (i >= len) break -> bound is len (right side)
            return right_vars
        elif op in ("<", "<="):
            # if (i < len) break -> bound is len (right side) - unusual pattern
            return right_vars
        elif op in ("==", "!="):
            # if (i == len) break or if (i != len) break
            counter_patterns = {"i", "j", "k", "idx", "index", "counter", "count"}
            left_is_counter = any(v.lower() in counter_patterns for v in left_vars)
            right_is_counter = any(v.lower() in counter_patterns for v in right_vars)
            if left_is_counter and not right_is_counter:
                return right_vars
            elif right_is_counter and not left_is_counter:
                return left_vars
            else:
                return left_vars + right_vars
        else:
            return left_vars + right_vars
    else:
        # Common pattern: while (i < len)
        if op in ("<", "<="):
            # Right side is the bound
            return right_vars
        elif op in (">", ">="):
            # Left side is the bound (X > i means i bounded by X)
            return left_vars
        elif op == "!=":
            # Could be `i != len` - both are relevant but prefer non-counter names
            counter_patterns = {"i", "j", "k", "idx", "index", "counter", "count"}
            left_is_counter = any(v.lower() in counter_patterns for v in left_vars)
            right_is_counter = any(v.lower() in counter_patterns for v in right_vars)
            if left_is_counter and not right_is_counter:
                return right_vars
            elif right_is_counter and not left_is_counter:
                return left_vars
            else:
                return left_vars + right_vars
        else:
            return left_vars + right_vars


def _contains_break(body: List[Stmt]) -> bool:
    """Check if a statement list contains a break statement (directly or nested in if)."""
    from .ir import BreakStmt

    for s in body:
        if isinstance(s, BreakStmt):
            return True
        if isinstance(s, IfStmt):
            if _contains_break(s.then_body):
                return True
            if s.else_body and _contains_break(s.else_body):
                return True
    return False


def generate_unused_arg_facts(func: Function, role_types: Optional[set[str]] = None) -> List[Fact]:
    """
    Generate UnusedArg facts for function arguments that are never used.

    An argument is considered "unused" if it doesn't appear in:
    - Any expression in the function body (including nested calls)
    - Assignments
    - Return statements

    Skips:
    - init functions (special constructors, often have unused params for flexibility)
    - Arguments named "_" or starting with "_" (intentionally unused)
    - Arguments whose type is a role/capability struct (checked via role_types)
    - TxContext parameters (Sui runtime context, often passed for future use)

    This is a conservative analysis - if we can't determine usage, we assume used.

    Args:
        func: Function IR to analyze
        role_types: Set of type names that are roles/capabilities (to skip)

    Returns:
        List of UnusedArg(func_name, arg_name, arg_idx) facts
    """
    # Skip init functions entirely - they're constructors with flexible signatures
    func_simple_name = get_simple_name(func.name)
    if func_simple_name == "init":
        return []

    facts = []
    role_types = role_types or set()
    # Pre-compute simple names for role types (role_types may contain FQNs like "mod::AdminCap")
    role_simple_names = {get_simple_name(rt) for rt in role_types}

    # Collect all argument names
    arg_names = {param.name for param in func.params}
    if not arg_names:
        return facts

    # Collect all variables used anywhere in the function body
    used_vars: set[str] = set()
    for stmt in func.body:
        used_vars.update(stmt_vars(stmt))

    # Find unused arguments
    for param in func.params:
        # Skip intentionally unused args (named _ or starting with _)
        if param.name == "_" or param.name.startswith("_"):
            continue

        # Skip role/capability arguments - they are used for authorization
        # Strip reference modifiers for type comparison
        param_type = param.typ.lstrip("&").lstrip("mut ").strip()
        param_type_simple = get_simple_name(param_type)
        # Check both exact match and simple name match
        if param_type in role_types or param_type_simple in role_types or param_type_simple in role_simple_names:
            continue

        # Skip TxContext parameters - Sui runtime context, often passed for future use
        if "TxContext" in param_type:
            continue

        if param.name not in used_vars:
            facts.append(Fact("UnusedArg", (func.name, param.name, param.idx)))

    return facts
