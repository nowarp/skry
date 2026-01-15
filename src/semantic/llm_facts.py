"""
LLM-based semantic fact generators.

Each generator calls LLM to classify a function and adds EITHER:
- Positive fact (safe pattern detected)
- Negative fact (vulnerable pattern detected)

Facts are cached. Metadata (reasoning, call traces) stored in LLMCache.
"""

from typing import List, Optional, Dict, Callable, Any, Set, Tuple
from dataclasses import dataclass
import hashlib

from core.facts import Fact
from core.utils import debug, error
from core.context import ProjectContext
from analysis.call_graph import build_global_call_graph, get_transitive_callees, build_call_graph_from_facts
from llm.cache import LLMCache
from llm.client import call_llm_json


def _compute_source_hash(source_code: str) -> str:
    """Compute hash for cache key."""
    return hashlib.sha256(source_code.encode()).hexdigest()[:16]


@dataclass
class LLMFactConfig:
    """Configuration for an LLM fact generator."""

    cache: LLMCache
    positive_fact: str  # Fact name when safe
    negative_fact: str  # Fact name when vulnerable
    response_schema: Dict[str, type]  # Expected LLM response fields
    is_vulnerable_fn: Callable[[Dict[str, Any]], bool]  # (response) -> is_vulnerable
    build_prompt_fn: Callable[..., str]  # Prompt builder function
    debug_tag: str  # Tag for debug logging


def _generate_llm_fact(
    config: LLMFactConfig,
    func_name: str,
    file_path: str,
    facts: List[Fact],
    source_code: str,
    root,
    ctx: Optional[ProjectContext],
    callees: List[str],
    extra_prompt_args: Optional[Dict[str, Any]] = None,
) -> bool:
    """
    Generic LLM fact generator.

    Handles: cache check, LLM call, response parsing, fact addition, caching.

    Returns True if vulnerable (negative fact added).
    """
    debug(f"[llm_facts] {config.debug_tag} {func_name}: callees={len(callees)}")

    # Check if fact already exists (injected from test cache)
    has_vulnerable_fact = any(f.name == config.negative_fact and f.args[0] == func_name for f in facts)
    has_safe_fact = any(f.name == config.positive_fact and f.args[0] == func_name for f in facts)

    if has_vulnerable_fact:
        debug(f"[llm_facts] {config.debug_tag} {func_name}: fact already exists (vulnerable)")
        return True
    if has_safe_fact:
        debug(f"[llm_facts] {config.debug_tag} {func_name}: fact already exists (safe)")
        return False

    # Check cache
    source_hash = _compute_source_hash(source_code)
    cached = config.cache.load(func_name, file_path, source_hash)
    if cached is not None:
        is_vulnerable, reason, has_access_control = cached
        debug(f"[llm_facts] {config.debug_tag} {func_name}: cached")
        fact_name = config.negative_fact if is_vulnerable else config.positive_fact
        facts.append(Fact(fact_name, (func_name,)))
        return is_vulnerable

    # Build prompt
    prompt_args = {
        "func_name": func_name,
        "callees": callees,
        "source_code": source_code,
        "root": root,
        "facts": facts,
        "ctx": ctx,
    }
    if extra_prompt_args:
        prompt_args.update(extra_prompt_args)

    prompt = config.build_prompt_fn(**prompt_args)
    response = call_llm_json(prompt, config.response_schema, context=config.debug_tag)

    if "error" in response:
        error(f"LLM failed to classify {config.debug_tag} for {func_name}: {response['error']}")
        return False

    # Determine vulnerability
    is_vulnerable = config.is_vulnerable_fn(response)
    reason = response.get("reason", "")

    # Add fact
    fact_name = config.negative_fact if is_vulnerable else config.positive_fact
    facts.append(Fact(fact_name, (func_name,)))

    # Build reason string for cache
    if is_vulnerable:
        result_reason = f"LLM: {reason}" if reason else "LLM: vulnerable"
    else:
        result_reason = f"LLM_SAFE: {reason}" if reason else "LLM_SAFE"

    # Cache result
    config.cache.save(func_name, file_path, source_hash, is_vulnerable, result_reason)

    return is_vulnerable


def _get_callees(func_name: str, facts: List[Fact], ctx: Optional[ProjectContext]) -> List[str]:
    """Build call graph and get transitive callees."""
    if ctx:
        call_graph = build_global_call_graph(ctx)
    else:
        call_graph = build_call_graph_from_facts(facts)
    return get_transitive_callees(func_name, call_graph)


# =============================================================================
# Access Control Fact Generator
# =============================================================================


def generate_access_control_fact(
    func_name: str,
    file_path: str,
    facts: List[Fact],
    source_code: str,
    root,
    ctx: Optional[ProjectContext] = None,
) -> bool:
    """
    Generate LLM access control fact.

    Adds either:
    - LLMHasAccessControl(func_name) - if safe
    - LLMVulnerableAccessControl(func_name) - if vulnerable

    Returns True if vulnerable (negative fact added).
    """
    from llm.cache import access_control_cache
    from llm.prompts import build_access_control_prompt, SINK_FACT_TYPES
    from llm.classify import (
        _vulnerability_contexts,
        VulnerabilityContext,
    )
    from llm.client import is_llm_debug_enabled

    callees = _get_callees(func_name, facts, ctx)
    funcs_to_check = [func_name] + callees

    # Collect sink types for prompt context
    sink_types: Set[str] = set()
    for fact in facts:
        if fact.name in SINK_FACT_TYPES and fact.args[0] in funcs_to_check:
            sink_types.add(SINK_FACT_TYPES[fact.name])

    if ctx:
        for callee in callees:
            if callee in ctx.global_facts_index:
                for _, callee_facts in ctx.global_facts_index[callee].items():
                    for fact in callee_facts:
                        if fact.name in SINK_FACT_TYPES:
                            sink_types.add(SINK_FACT_TYPES[fact.name])

    if not sink_types:
        sink_types = {"unknown"}

    debug(f"[llm_facts] access_control {func_name}: callees={len(callees)}, sinks={sink_types}")

    # Check if fact already exists (injected from test cache)
    has_vulnerable_fact = any(f.name == "LLMVulnerableAccessControl" and f.args[0] == func_name for f in facts)
    has_safe_fact = any(f.name == "LLMHasAccessControl" and f.args[0] == func_name for f in facts)

    if has_vulnerable_fact:
        debug(f"[llm_facts] access_control {func_name}: fact already exists (vulnerable)")
        return True
    if has_safe_fact:
        debug(f"[llm_facts] access_control {func_name}: fact already exists (safe)")
        return False

    # Check cache
    source_hash = _compute_source_hash(source_code)
    cached = access_control_cache.load(func_name, file_path, source_hash)
    if cached is not None:
        is_vulnerable, reason, has_access_control = cached
        debug(f"[llm_facts] access_control {func_name}: cached (has_ac={has_access_control})")
        if has_access_control or not is_vulnerable:
            facts.append(Fact("LLMHasAccessControl", (func_name,)))
        else:
            facts.append(Fact("LLMVulnerableAccessControl", (func_name,)))
        return is_vulnerable

    # Build prompt and call LLM
    prompt = build_access_control_prompt(func_name, callees, sink_types, source_code, root, facts, ctx)
    response = call_llm_json(prompt, {"has_access_control": bool, "is_vulnerable": bool}, context="AccessControl")

    if "error" in response:
        error(f"LLM failed to classify {func_name}: {response['error']}")
        return False

    has_access_control = response.get("has_access_control", False)
    is_vulnerable = response.get("is_vulnerable", False)
    reason = response.get("reason", "")

    # If LLM detected access control, override vulnerability
    if has_access_control:
        is_vulnerable = False
        if not reason:
            reason = "has access control"

    # Add appropriate fact
    if has_access_control or not is_vulnerable:
        facts.append(Fact("LLMHasAccessControl", (func_name,)))
        result_reason = f"LLM_SAFE: {reason}" if reason else "LLM_SAFE"
    else:
        facts.append(Fact("LLMVulnerableAccessControl", (func_name,)))
        result_reason = f"LLM: {reason}" if reason else "LLM: vulnerable"

        # Debug mode: collect extended context
        if is_llm_debug_enabled():
            debug(f"[llm_facts] {func_name}: collecting debug context...")
            vuln_ctx = VulnerabilityContext(
                func_name=func_name,
                file_path=file_path,
                classification="VULNERABLE",
                reasoning=reason,
                entry_point=func_name,
                call_trace=callees.copy(),
                sink_types=sink_types.copy(),
            )
            _vulnerability_contexts[func_name] = vuln_ctx

    # Cache result
    access_control_cache.save(
        func_name,
        file_path,
        source_hash,
        is_vulnerable,
        result_reason,
        call_trace=callees if is_vulnerable else None,
        sink_types=sink_types if is_vulnerable else None,
        has_access_control=has_access_control,
    )

    return is_vulnerable


# =============================================================================
# Simple Fact Generators (use generic pattern)
# =============================================================================


def generate_unlock_fact(
    func_name: str,
    file_path: str,
    facts: List[Fact],
    source_code: str,
    root,
    ctx: Optional[ProjectContext] = None,
) -> bool:
    """
    Generate LLM unlock/release fact.

    Adds either:
    - LLMHasUnlockOnAllPaths(func_name) - if safe
    - LLMMissingUnlock(func_name) - if vulnerable
    """
    from llm.cache import unlock_cache
    from llm.prompts import build_unlock_prompt

    def is_vulnerable(response: Dict) -> bool:
        acquires_lock = response.get("acquires_lock", False)
        releases_all = response.get("releases_on_all_paths", True)
        return acquires_lock and not releases_all

    config = LLMFactConfig(
        cache=unlock_cache,
        positive_fact="LLMHasUnlockOnAllPaths",
        negative_fact="LLMMissingUnlock",
        response_schema={"acquires_lock": bool, "releases_on_all_paths": bool},
        is_vulnerable_fn=is_vulnerable,
        build_prompt_fn=build_unlock_prompt,
        debug_tag="unlock",
    )

    callees = _get_callees(func_name, facts, ctx)
    return _generate_llm_fact(config, func_name, file_path, facts, source_code, root, ctx, callees)


def generate_drain_fact(
    func_name: str,
    file_path: str,
    facts: List[Fact],
    source_code: str,
    root,
    ctx: Optional[ProjectContext] = None,
) -> bool:
    """
    Generate LLM arbitrary drain fact.

    Adds either:
    - LLMCallerOwnsValue(func_name) - if safe
    - LLMArbitraryDrain(func_name) - if vulnerable
    """
    from llm.cache import drain_cache
    from llm.prompts import build_drain_prompt

    def is_vulnerable(response: Dict) -> bool:
        is_drain = response.get("is_drain_vulnerability", False)
        caller_owns = response.get("caller_owns_transferred_value", False)
        return is_drain and not caller_owns

    config = LLMFactConfig(
        cache=drain_cache,
        positive_fact="LLMCallerOwnsValue",
        negative_fact="LLMArbitraryDrain",
        response_schema={"is_drain_vulnerability": bool, "caller_owns_transferred_value": bool},
        is_vulnerable_fn=is_vulnerable,
        build_prompt_fn=build_drain_prompt,
        debug_tag="drain",
    )

    callees = _get_callees(func_name, facts, ctx)
    return _generate_llm_fact(config, func_name, file_path, facts, source_code, root, ctx, callees)


def generate_transfer_fact(
    func_name: str,
    file_path: str,
    facts: List[Fact],
    source_code: str,
    root,
    ctx: Optional[ProjectContext] = None,
) -> bool:
    """
    Generate LLM missing transfer fact.

    Adds either:
    - LLMValueReachesRecipient(func_name) - if safe
    - LLMMissingTransfer(func_name) - if vulnerable
    """
    from llm.cache import transfer_cache
    from llm.prompts import build_transfer_prompt

    def is_vulnerable(response: Dict) -> bool:
        value_reaches = response.get("value_reaches_recipient", True)
        is_helper = response.get("is_helper_function", False)
        return not value_reaches and not is_helper

    config = LLMFactConfig(
        cache=transfer_cache,
        positive_fact="LLMValueReachesRecipient",
        negative_fact="LLMMissingTransfer",
        response_schema={"value_reaches_recipient": bool, "is_helper_function": bool},
        is_vulnerable_fn=is_vulnerable,
        build_prompt_fn=build_transfer_prompt,
        debug_tag="transfer",
    )

    callees = _get_callees(func_name, facts, ctx)
    return _generate_llm_fact(config, func_name, file_path, facts, source_code, root, ctx, callees)


# =============================================================================
# Sensitive Setter (custom logic for mutable shared param check)
# =============================================================================


def generate_sensitive_setter_fact(
    func_name: str,
    file_path: str,
    facts: List[Fact],
    source_code: str,
    root,
    ctx: Optional[ProjectContext] = None,
) -> bool:
    """
    Generate LLM sensitive setter fact.

    Adds either:
    - LLMHasSetterAuth(func_name) - if safe
    - LLMSensitiveSetter(func_name) - if vulnerable

    Has custom pre-check for mutable shared params.
    """
    from llm.cache import sensitive_setter_cache
    from llm.prompts import (
        build_sensitive_setter_prompt,
        get_mutable_shared_param_types,
        get_struct_definitions_for_types,
    )

    # Check if fact already exists (from cache injection in E2E tests)
    has_safe_fact = any(f.name == "LLMHasSetterAuth" and f.args[0] == func_name for f in facts)
    has_vuln_fact = any(f.name == "LLMSensitiveSetter" and f.args[0] == func_name for f in facts)

    if has_safe_fact:
        debug(f"[llm_facts] sensitive_setter {func_name}: already has LLMHasSetterAuth fact")
        return False
    if has_vuln_fact:
        debug(f"[llm_facts] sensitive_setter {func_name}: already has LLMSensitiveSetter fact")
        return True

    callees = _get_callees(func_name, facts, ctx)

    # Get mutable shared param types (custom pre-check)
    all_facts = list(facts)
    if ctx and ctx.global_facts_index:
        for file_ctx in ctx.source_files.values():
            all_facts.extend(file_ctx.facts)

    mutable_shared_types = get_mutable_shared_param_types(func_name, all_facts)

    if not mutable_shared_types:
        debug(f"[llm_facts] sensitive_setter {func_name}: no mutable shared params")
        facts.append(Fact("LLMHasSetterAuth", (func_name,)))
        return False

    debug(f"[llm_facts] sensitive_setter {func_name}: mutable_shared={mutable_shared_types}, callees={len(callees)}")

    # Check cache
    source_hash = _compute_source_hash(source_code)
    cached = sensitive_setter_cache.load(func_name, file_path, source_hash)
    if cached is not None:
        is_vulnerable, reason, has_access_control = cached
        debug(f"[llm_facts] sensitive_setter {func_name}: cached (has_ac={has_access_control})")
        fact_name = "LLMSensitiveSetter" if is_vulnerable else "LLMHasSetterAuth"
        facts.append(Fact(fact_name, (func_name,)))
        return is_vulnerable

    # Get struct definitions for prompt
    struct_sources = get_struct_definitions_for_types(mutable_shared_types, all_facts, source_code, root, ctx)

    # Build prompt and call LLM
    prompt = build_sensitive_setter_prompt(
        func_name, callees, mutable_shared_types, struct_sources, source_code, root, facts, ctx
    )
    response = call_llm_json(
        prompt,
        {"has_access_control": bool, "modifies_protocol_config": bool, "modifies_user_owned_state": bool},
        context="SensitiveSetter",
    )

    if "error" in response:
        error(f"LLM failed to classify sensitive setter for {func_name}: {response['error']}")
        return False

    has_access_control = response.get("has_access_control", False)
    modifies_protocol = response.get("modifies_protocol_config", False)
    modifies_user_state = response.get("modifies_user_owned_state", False)
    reason = response.get("reason", "")

    # Determine vulnerability
    if has_access_control:
        is_vulnerable = False
        result_reason = f"LLM_SAFE: has access control. {reason}" if reason else "LLM_SAFE: has access control"
    elif modifies_protocol:
        is_vulnerable = True
        result_reason = f"LLM: modifies protocol config. {reason}" if reason else "LLM: sensitive setter without auth"
    elif modifies_user_state:
        is_vulnerable = False
        result_reason = f"LLM_SAFE: modifies user's own state. {reason}" if reason else "LLM_SAFE: user-scoped"
    else:
        is_vulnerable = False
        result_reason = f"LLM_SAFE: not sensitive. {reason}" if reason else "LLM_SAFE: not sensitive"

    # Add fact
    fact_name = "LLMSensitiveSetter" if is_vulnerable else "LLMHasSetterAuth"
    facts.append(Fact(fact_name, (func_name,)))

    # Cache result
    sensitive_setter_cache.save(
        func_name, file_path, source_hash, is_vulnerable, result_reason, has_access_control=has_access_control
    )

    return is_vulnerable


# =============================================================================
# Internal Helper Exposure Fact Generator
# =============================================================================


def _get_function_signature(func_name: str, ctx: ProjectContext) -> Optional[str]:
    """Get function signature from module index."""
    if not ctx or not hasattr(ctx, "module_index"):
        return None

    # module_index is Dict[str, Function] where key is FQN
    func = ctx.module_index.get(func_name)
    if func:
        # Build signature string from Function IR (Param has .typ, not .type_str)
        params = ", ".join(f"{p.name}: {p.typ}" for p in func.params)
        ret = f" -> {func.ret_type}" if func.ret_type else ""
        simple_name = func.name.split("::")[-1] if "::" in func.name else func.name
        return f"fun {simple_name}({params}){ret}"

    # Try matching by simple name
    simple_target = func_name.split("::")[-1] if "::" in func_name else func_name
    for _, func in ctx.module_index.items():
        simple_name = func.name.split("::")[-1] if "::" in func.name else func.name
        if simple_name == simple_target:
            params = ", ".join(f"{p.name}: {p.typ}" for p in func.params)
            ret = f" -> {func.ret_type}" if func.ret_type else ""
            return f"fun {simple_name}({params}){ret}"

    return None


def _get_caller_callee_context(func_name: str, ctx: ProjectContext) -> Tuple[str, str]:
    """Get caller and callee signatures for context."""
    call_graph = getattr(ctx, "call_graph", None)
    if not call_graph:
        return "(none)", "(none)"

    # Get callers (sorted for deterministic prompt generation / cache key stability)
    callers = call_graph.callers.get(func_name, set())
    caller_sigs = []
    for caller in sorted(callers)[:5]:  # Limit to 5 callers
        sig = _get_function_signature(caller, ctx)
        if sig:
            caller_sigs.append(f"  - {sig}")
        else:
            caller_sigs.append(f"  - {caller}")
    caller_context = "\n".join(caller_sigs) if caller_sigs else "(none)"

    # Get callees (sorted for deterministic prompt generation / cache key stability)
    callees = call_graph.callees.get(func_name, set())
    callee_sigs = []
    for callee in sorted(callees)[:5]:  # Limit to 5 callees
        sig = _get_function_signature(callee, ctx)
        if sig:
            callee_sigs.append(f"  - {sig}")
        else:
            callee_sigs.append(f"  - {callee}")
    callee_context = "\n".join(callee_sigs) if callee_sigs else "(none)"

    return caller_context, callee_context


def _build_internal_helper_exposure_prompt(
    func_name: str,
    func_source: str,
    caller_context: str,
    callee_context: str,
    has_internal_callers: bool,
    has_sensitive_sink: bool,
    has_auth_check: bool,
) -> str:
    """Build prompt for internal helper exposure classification."""
    # Generate observations dynamically based on actual metadata
    observations = ["- Visibility: `public` (externally callable)"]
    if has_internal_callers:
        observations.append("- Has callers within the same package")
    else:
        observations.append("- No callers found within the same package")
    if has_sensitive_sink:
        observations.append("- Contains sensitive operations (balance/state mutation)")
    else:
        observations.append("- No sensitive operations detected")
    if has_auth_check:
        observations.append("- Has capability parameter or sender check")
    else:
        observations.append("- Does not take a capability parameter or check sender")
    observations_str = "\n".join(observations)

    return f"""Analyze this Sui Move function to classify its visibility design intent.

## Target Function
```move
{func_source}
```

## Functions That Call This (callers)
{caller_context}

## Functions This Calls (callees)
{callee_context}

## Structural Observations
{observations_str}

## Classification Task
Determine the design intent: Is this a **legitimate public API** or an **internal helper** that should have restricted visibility (`public(friend)` or `public(package)`)?

**Internal helper indicators (should be restricted):**
1. Low-level operation designed to be wrapped by authorized entry points
2. Callers provide authorization that this function lacks
3. Direct external access would bypass intended access control

**Legitimate public API indicators (should remain public):**
1. Intentionally designed for unrestricted external use
2. Authorization not needed (read-only, user-owns-object patterns)
3. Factory pattern creating user-owned resources
4. Deposit/join operations where user provides their own assets

Carefully consider BOTH possibilities before concluding.

Response format: {{"is_internal_helper": true/false, "reason": "brief explanation"}}"""


def generate_internal_helper_exposure_fact(
    func_name: str,
    file_path: str,
    facts: List[Fact],
    source_code: str,
    root,
    ctx: Optional[ProjectContext] = None,
) -> bool:
    """
    Generate LLM internal helper exposure fact.

    Provides rich context: function source + caller/callee signatures.

    Adds either:
    - LLMSafeInternalHelper(func_name) - if safe (not an internal helper)
    - LLMInternalHelperExposure(func_name) - if vulnerable (should be restricted)

    Returns True if vulnerable (negative fact added).
    """
    from llm.cache import internal_helper_exposure_cache
    from llm.client import call_llm_json
    from move.extract import extract_function_source

    debug(f"[llm_facts] internal_helper_exposure {func_name}")

    # Check if fact already exists (injected from test cache)
    has_vulnerable_fact = any(f.name == "LLMInternalHelperExposure" and f.args[0] == func_name for f in facts)
    has_safe_fact = any(f.name == "LLMSafeInternalHelper" and f.args[0] == func_name for f in facts)

    if has_vulnerable_fact:
        debug(f"[llm_facts] internal_helper_exposure {func_name}: fact already exists (vulnerable)")
        return True
    if has_safe_fact:
        debug(f"[llm_facts] internal_helper_exposure {func_name}: fact already exists (safe)")
        return False

    # Get caller/callee context BEFORE cache lookup (context is part of cache key)
    caller_context, callee_context = ("(none)", "(none)")
    if ctx:
        caller_context, callee_context = _get_caller_callee_context(func_name, ctx)

    # Check cache - include caller/callee context in hash since prompt depends on it
    context_hash = _compute_source_hash(source_code + caller_context + callee_context)
    cached = internal_helper_exposure_cache.load(func_name, file_path, context_hash)
    if cached is not None:
        is_vulnerable, reason, _ = cached
        debug(f"[llm_facts] internal_helper_exposure {func_name}: cached")
        fact_name = "LLMInternalHelperExposure" if is_vulnerable else "LLMSafeInternalHelper"
        facts.append(Fact(fact_name, (func_name,)))
        return is_vulnerable

    # Get function source (note: signature is source_code, func_name, root)
    func_source = extract_function_source(source_code, func_name, root)
    if not func_source:
        debug(f"[llm_facts] internal_helper_exposure {func_name}: could not extract source")
        return False

    # Compute metadata for prompt (based on actual facts, not assumptions)
    has_internal_callers = caller_context != "(none)"
    # Check for direct sink facts (TransferSink, StateWriteSink, AmountExtractionSink)
    # or TaintedAtSink without "_via_" (which indicates IPA-propagated sinks)
    direct_sink_facts = {"TransferSink", "StateWriteSink", "AmountExtractionSink"}
    has_sensitive_sink = any(
        (f.name in direct_sink_facts and f.args[0] == func_name)
        or (f.name == "TaintedAtSink" and f.args[0] == func_name and len(f.args) >= 3 and "_via_" not in f.args[2])
        for f in facts
    )
    has_auth_check = any(
        (f.name == "ChecksCapability" or f.name == "ChecksSender") and f.args[0] == func_name for f in facts
    )

    # Build prompt and call LLM
    prompt = _build_internal_helper_exposure_prompt(
        func_name, func_source, caller_context, callee_context, has_internal_callers, has_sensitive_sink, has_auth_check
    )
    response = call_llm_json(prompt, {"is_internal_helper": bool}, context="InternalHelperExposure")

    if "error" in response:
        error(f"LLM failed to classify internal helper exposure for {func_name}: {response['error']}")
        return False

    is_internal_helper = response.get("is_internal_helper", False)
    reason = response.get("reason", "")

    # Determine vulnerability (internal helper = should be restricted = vulnerable)
    is_vulnerable = is_internal_helper

    # Add fact
    if is_vulnerable:
        facts.append(Fact("LLMInternalHelperExposure", (func_name,)))
        result_reason = f"LLM: {reason}" if reason else "LLM: internal helper should be restricted"
    else:
        facts.append(Fact("LLMSafeInternalHelper", (func_name,)))
        result_reason = f"LLM_SAFE: {reason}" if reason else "LLM_SAFE: not an internal helper"

    # Cache result
    internal_helper_exposure_cache.save(func_name, file_path, context_hash, is_vulnerable, result_reason)

    return is_vulnerable
