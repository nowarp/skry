"""
Bridge module for Hy rules to call Python semantic checks.

This allows Hy predicates to use complex analysis (CFG, taint, LLM) that's
implemented in Python, while keeping the rule logic composable in Hy.

Usage in Hy:
    (import rules.hy_bridge [call-check])
    (call-check "double_init" f facts ctx)
"""

from typing import Callable, Dict, List

from core.facts import Fact
from core.utils import debug
from rules.ir import Condition, PropName
from rules.eval_context import EvalContext


# Lazy import to avoid circular dependencies
_semantic_checker_class = None
_check_functions: Dict[str, Callable] = {}


def _get_semantic_checker_class():
    """Lazy import SemanticChecker to avoid circular imports."""
    global _semantic_checker_class
    if _semantic_checker_class is None:
        from semantic.checker import SemanticChecker

        _semantic_checker_class = SemanticChecker
    return _semantic_checker_class


def _get_check_functions() -> Dict[str, Callable]:
    """Lazy load all check functions."""
    global _check_functions
    if _check_functions:
        return _check_functions

    # Import all check modules
    from semantic.taint_checks import (
        check_tainted_param,
        check_tainted_recipient,
        check_tainted_state_write,
        check_tainted_amount,
        check_tainted_transfer_value,
        check_tainted_object_destroy,
        check_tainted_loop_bound,
    )
    from semantic.sanitized_checks import (
        check_sanitized_recipient,
        check_sanitized_state_write,
        check_sanitized_amount,
        check_sanitized_transfer_value,
        check_sanitized_object_destroy,
    )
    from semantic.access_checks import (
        check_checks_capability,
        check_checks_sender,
        check_creates_privileged_cap,
        check_requires_parent_cap,
        check_verifies_ownership,
        check_transfers_privileged_to_tainted,
        check_single_step_ownership,
    )
    from semantic.structural_checks import (
        check_is_init,
        check_public,
        check_entry,
        check_orphan_txcontext,
        check_orphan_capability,
        check_orphan_event,
        check_double_init,
        check_self_recursive,
    )
    from semantic.complexity_checks import (
        check_version_check_inconsistent,
        check_unused,
        check_duplicated_branch_condition,
        check_duplicated_branch_body,
    )
    from semantic.defi_checks import (
        check_transfer,
        check_transfers_to_zero_address,
        check_returns_mutable_ref,
        check_weak_randomness,
        check_sensitive_event_leak,
    )

    _check_functions = {
        # Taint checks
        "tainted_param": check_tainted_param,
        "tainted_recipient": check_tainted_recipient,
        "tainted_state_write": check_tainted_state_write,
        "tainted_amount": check_tainted_amount,
        "tainted_transfer_value": check_tainted_transfer_value,
        "tainted_object_destroy": check_tainted_object_destroy,
        "tainted_loop_bound": check_tainted_loop_bound,
        # Sanitized checks
        "sanitized_recipient": check_sanitized_recipient,
        "sanitized_state_write": check_sanitized_state_write,
        "sanitized_amount": check_sanitized_amount,
        "sanitized_transfer_value": check_sanitized_transfer_value,
        "sanitized_object_destroy": check_sanitized_object_destroy,
        # Access control checks
        "checks_capability": check_checks_capability,
        "checks_sender": check_checks_sender,
        "creates_privileged_cap": check_creates_privileged_cap,
        "requires_parent_cap": check_requires_parent_cap,
        "verifies_ownership": check_verifies_ownership,
        "transfers_privileged_to_tainted": check_transfers_privileged_to_tainted,
        "single_step_ownership": check_single_step_ownership,
        # Structural checks
        "is_init": check_is_init,
        "public": check_public,
        "entry": check_entry,
        "orphan_txcontext": check_orphan_txcontext,
        "orphan_capability": check_orphan_capability,
        "orphan_event": check_orphan_event,
        "double_init": check_double_init,
        "self_recursive": check_self_recursive,
        # Complexity checks
        "version_check_inconsistent": check_version_check_inconsistent,
        "unused": check_unused,
        "duplicated_branch_condition": check_duplicated_branch_condition,
        "duplicated_branch_body": check_duplicated_branch_body,
        # DeFi checks
        "transfer": check_transfer,
        "transfers_to_zero_address": check_transfers_to_zero_address,
        "returns_mutable_ref": check_returns_mutable_ref,
        "weak_randomness": check_weak_randomness,
        "sensitive_event_leak": check_sensitive_event_leak,
    }

    return _check_functions


class MinimalRule:
    """
    Minimal Rule-like object for bridge calls.

    The Python check functions expect a Rule object to extract the function
    binding key. This provides just enough interface to make them work.
    """

    def __init__(self, binding_key: str = "f", pattern_type: str = "fun"):
        self.match_clause = MinimalMatchClause(binding_key, pattern_type)
        self.where_clause = None


class MinimalMatchClause:
    """Minimal match clause for bridge."""

    def __init__(self, binding_key: str, pattern_type: str):
        self.pattern = MinimalPattern(binding_key, pattern_type)
        self.body = []  # Empty body - Hy rules don't use statement bindings


class MinimalPattern:
    """Minimal pattern for bridge."""

    def __init__(self, binding_key: str, pattern_type: str):
        self.binding = binding_key
        self.type = pattern_type  # "fun", "role", "event", "const"


def call_check(
    check_name: str,
    entity: str,
    facts: List[Fact],
    ctx: EvalContext,
    binding_key: str = "f",
    pattern_type: str = "fun",
) -> bool:
    """
    Call a Python semantic check from Hy.

    Args:
        check_name: Name of the check (e.g., "double_init", "tainted_recipient")
        entity: The entity being checked (function name, role name, etc.)
        facts: List of facts for the current file
        ctx: EvalContext with project context, source, etc.
        binding_key: The binding key used in the rule (default "f" for functions)
        pattern_type: The pattern type ("fun", "role", "event", "const")

    Returns:
        True if the check passes (vulnerability found), False otherwise
    """
    check_fns = _get_check_functions()
    check_fn = check_fns.get(check_name)

    if check_fn is None:
        debug(f"[hy_bridge] Unknown check: {check_name}")
        return False

    # Build minimal objects for the check
    SemanticChecker = _get_semantic_checker_class()
    checker = SemanticChecker(ctx.ctx, ctx.current_file)

    # Create binding with the entity
    binding = {binding_key: entity}

    # Create minimal condition (no negation - Hy handles that with `not`)
    condition = Condition(subject=binding_key, property=PropName(check_name), negation=False)

    # Create minimal rule
    rule = MinimalRule(binding_key, pattern_type)

    try:
        result = check_fn(
            checker,
            rule,
            binding,
            condition,
            facts,
            ctx.current_source,
            ctx.current_root,
        )
        debug(f"[hy_bridge] {check_name}({entity}) = {result}")
        return result
    except Exception as e:
        debug(f"[hy_bridge] Error in {check_name}: {e}")
        return False


def call_check_capability(check_name: str, cap: str, facts: List[Fact], ctx: EvalContext) -> bool:
    """Convenience wrapper for capability checks."""
    return call_check(check_name, cap, facts, ctx, binding_key="c", pattern_type="capability")


def call_check_event(check_name: str, event: str, facts: List[Fact], ctx: EvalContext) -> bool:
    """Convenience wrapper for event checks."""
    return call_check(check_name, event, facts, ctx, binding_key="e", pattern_type="event")


def call_check_const(check_name: str, const: str, facts: List[Fact], ctx: EvalContext) -> bool:
    """Convenience wrapper for const checks."""
    return call_check(check_name, const, facts, ctx, binding_key="c", pattern_type="const")


def call_llm_classify_access_control(
    func_name: str,
    facts: List[Fact],
    ctx: EvalContext,
) -> bool:
    """
    Call LLM to classify access control vulnerability.

    Generates LLMHasAccessControl or LLMVulnerableAccessControl fact.
    Returns True if vulnerable.
    """
    from semantic.llm_facts import generate_access_control_fact

    if ctx.current_source is None:
        return False
    is_vulnerable = generate_access_control_fact(
        func_name=func_name,
        file_path=ctx.current_file,
        facts=facts,
        source_code=ctx.current_source,
        root=ctx.current_root,
        ctx=ctx.ctx,
    )

    debug(f"[hy_bridge] llm_classify_access_control({func_name}) = {is_vulnerable}")
    return is_vulnerable


def call_llm_classify_missing_unlock(
    func_name: str,
    facts: List[Fact],
    ctx: EvalContext,
) -> bool:
    """
    Call LLM to classify missing unlock vulnerability.

    Generates LLMHasUnlockOnAllPaths or LLMMissingUnlock fact.
    Returns True if vulnerable.
    """
    from semantic.llm_facts import generate_unlock_fact

    if ctx.current_source is None:
        return False
    is_vulnerable = generate_unlock_fact(
        func_name=func_name,
        file_path=ctx.current_file,
        facts=facts,
        source_code=ctx.current_source,
        root=ctx.current_root,
        ctx=ctx.ctx,
    )

    debug(f"[hy_bridge] llm_classify_missing_unlock({func_name}) = {is_vulnerable}")
    return is_vulnerable


def call_llm_classify_arbitrary_drain(
    func_name: str,
    facts: List[Fact],
    ctx: EvalContext,
) -> bool:
    """
    Call LLM to classify arbitrary recipient drain vulnerability.

    Generates LLMCallerOwnsValue or LLMArbitraryDrain fact.
    Returns True if vulnerable.
    """
    from semantic.llm_facts import generate_drain_fact

    if ctx.current_source is None:
        return False
    is_vulnerable = generate_drain_fact(
        func_name=func_name,
        file_path=ctx.current_file,
        facts=facts,
        source_code=ctx.current_source,
        root=ctx.current_root,
        ctx=ctx.ctx,
    )

    debug(f"[hy_bridge] llm_classify_arbitrary_drain({func_name}) = {is_vulnerable}")
    return is_vulnerable


def call_llm_classify_missing_transfer(
    func_name: str,
    facts: List[Fact],
    ctx: EvalContext,
) -> bool:
    """
    Call LLM to classify missing transfer vulnerability.

    Generates LLMValueReachesRecipient or LLMMissingTransfer fact.
    Returns True if vulnerable.
    """
    from semantic.llm_facts import generate_transfer_fact

    if ctx.current_source is None:
        return False
    is_vulnerable = generate_transfer_fact(
        func_name=func_name,
        file_path=ctx.current_file,
        facts=facts,
        source_code=ctx.current_source,
        root=ctx.current_root,
        ctx=ctx.ctx,
    )

    debug(f"[hy_bridge] llm_classify_missing_transfer({func_name}) = {is_vulnerable}")
    return is_vulnerable


def call_llm_classify_sensitive_setter(
    func_name: str,
    facts: List[Fact],
    ctx: EvalContext,
) -> bool:
    """
    Call LLM to classify sensitive setter vulnerability.

    Generates LLMHasSetterAuth or LLMSensitiveSetter fact.
    Returns True if vulnerable.
    """
    from semantic.llm_facts import generate_sensitive_setter_fact

    if ctx.current_source is None:
        return False
    is_vulnerable = generate_sensitive_setter_fact(
        func_name=func_name,
        file_path=ctx.current_file,
        facts=facts,
        source_code=ctx.current_source,
        root=ctx.current_root,
        ctx=ctx.ctx,
    )

    debug(f"[hy_bridge] llm_classify_sensitive_setter({func_name}) = {is_vulnerable}")
    return is_vulnerable


def has_internal_callers(
    func_name: str,
    facts: List[Fact],
    ctx: EvalContext,
) -> bool:
    """
    Check if function has callers within the same package.

    Strong structural signal that function is designed as internal helper.
    Uses pre-built CallGraph.callers mapping.

    Args:
        func_name: FQN of the function to check
        facts: Current file facts (unused, for interface consistency)
        ctx: EvalContext with project context

    Returns:
        True if function has at least one caller from the same package

    LIMITATION: Package detection uses first component of module path.
        e.g., "mypackage::module::func" -> package is "mypackage"
        This is a heuristic that works for typical Sui projects where the
        first path component is the package name. However, it may not work
        correctly for all naming conventions (e.g., multi-level package
        names like "org::project::module"). True package detection would
        require parsing Move.toml or similar project configuration.
    """
    call_graph = getattr(ctx.ctx, "call_graph", None)
    if call_graph is None:
        return False

    callers = call_graph.callers.get(func_name, set())
    if not callers:
        return False

    # Extract package (first component of module path)
    # e.g., "test::vulnerable_internal::do_withdraw" -> "test"
    # NOTE: We use package-level (not module-level) because:
    # - In Sui, public(package) restricts to the same package, not module
    # - A helper in test::helpers called by test::main is "internal" to package test
    # - Cross-module calls within a package are intentional internal APIs

    # Validate func_name is a proper FQN (must contain ::)
    if "::" not in func_name:
        debug(f"[hy_bridge] has_internal_callers({func_name}): invalid FQN (no ::)")
        return False

    func_parts = func_name.split("::")
    func_package = func_parts[0]

    # C2 fix: Empty package name should not match anything
    if not func_package:
        debug(f"[hy_bridge] has_internal_callers({func_name}): empty package name")
        return False

    for caller in callers:
        # Skip callers that aren't valid FQNs
        if "::" not in caller:
            continue
        caller_parts = caller.split("::")
        caller_package = caller_parts[0]
        # Skip empty package names
        if not caller_package:
            continue
        if caller_package == func_package:
            debug(f"[hy_bridge] has_internal_callers({func_name}): found caller {caller}")
            return True

    return False


def call_llm_classify_internal_helper_exposure(
    func_name: str,
    facts: List[Fact],
    ctx: EvalContext,
) -> bool:
    """
    Call LLM to classify internal helper exposure vulnerability.

    Provides rich context: function source + caller/callee signatures.
    Generates LLMInternalHelperExposure or LLMSafeInternalHelper fact.
    Returns True if vulnerable.
    """
    from semantic.llm_facts import generate_internal_helper_exposure_fact

    if ctx.current_source is None:
        return False

    is_vulnerable = generate_internal_helper_exposure_fact(
        func_name=func_name,
        file_path=ctx.current_file,
        facts=facts,
        source_code=ctx.current_source,
        root=ctx.current_root,
        ctx=ctx.ctx,
    )

    debug(f"[hy_bridge] llm_classify_internal_helper_exposure({func_name}) = {is_vulnerable}")
    return is_vulnerable
