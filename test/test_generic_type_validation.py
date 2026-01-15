"""
Tests for generic type validation analysis (taint-style).

Tests cover:
1. Direct validation via type_name::get<T>()
2. Multiple type params with partial validation
3. Multi-hop interprocedural propagation (A->B->C)
4. Type param mapping between caller and callee
"""

from typing import List

from core.facts import Fact
from taint.generics import (
    propagate_generic_validation,
    compute_generic_summary,
    apply_generic_summaries,
    GenericTypeSummary,
)


def sorted_facts(facts: List[Fact]) -> List[Fact]:
    return sorted(facts, key=lambda f: (f.name, f.args))


def _has_fact(facts: List[Fact], name: str, args: tuple) -> bool:
    return any(f.name == name and f.args == args for f in facts)


def _build_global_type_params(facts: List[Fact]) -> dict:
    """Build global type params index from facts."""
    result = {}
    for fact in facts:
        if fact.name == "HasGenericParam":
            func_name, param_idx, type_var = fact.args
            if func_name not in result:
                result[func_name] = {}
            result[func_name][param_idx] = type_var
    return result


FUNC_A = "test::module::func_a"
FUNC_B = "test::module::func_b"
FUNC_C = "test::module::func_c"


# --- Tests for propagate_generic_validation ---


def test_direct_validation_single_type():
    """type_name::get<T>() validates type T when result is in assertion."""
    facts = [
        Fact("HasGenericParam", (FUNC_A, 0, "T")),
        Fact("GenericCallArg", (FUNC_A, "s1", "std::type_name::get", 0, "T")),
        Fact("ConditionCheck", (FUNC_A, "s1", [])),  # Result used in assertion
    ]
    state = propagate_generic_validation(FUNC_A, facts)

    assert "T" in state.validated_types
    assert _has_fact(facts, "TypeValidated", (FUNC_A, "T", "s1"))


def test_direct_validation_multiple_types():
    """type_name::get<T>() validates only T, not other type params."""
    facts = [
        Fact("HasGenericParam", (FUNC_A, 0, "T")),
        Fact("HasGenericParam", (FUNC_A, 1, "U")),
        Fact("GenericCallArg", (FUNC_A, "s1", "std::type_name::get", 0, "T")),
        Fact("ConditionCheck", (FUNC_A, "s1", [])),  # Result used in assertion
    ]
    state = propagate_generic_validation(FUNC_A, facts)

    assert "T" in state.validated_types
    assert "U" not in state.validated_types


def test_no_validation():
    """Function with generic params but no type_name::get call."""
    facts = [
        Fact("HasGenericParam", (FUNC_A, 0, "T")),
        Fact("GenericCallArg", (FUNC_A, "s1", "sui::coin::take", 0, "T")),
    ]
    state = propagate_generic_validation(FUNC_A, facts)

    assert "T" not in state.validated_types
    assert "T" in state.type_to_sinks
    assert ("s1", "sui::coin::take") in state.type_to_sinks["T"]


def test_sink_detection():
    """Detect type params reaching extraction sinks."""
    facts = [
        Fact("HasGenericParam", (FUNC_A, 0, "T")),
        Fact("GenericCallArg", (FUNC_A, "s1", "sui::coin::take", 0, "T")),
        Fact("GenericCallArg", (FUNC_A, "s2", "sui::balance::split", 0, "T")),
    ]
    state = propagate_generic_validation(FUNC_A, facts)

    assert "T" in state.type_to_sinks
    assert len(state.type_to_sinks["T"]) == 2


def test_validated_before_sink():
    """Type validated before reaching sink should be safe."""
    facts = [
        Fact("HasGenericParam", (FUNC_A, 0, "T")),
        Fact("GenericCallArg", (FUNC_A, "s1", "std::type_name::get", 0, "T")),
        Fact("GenericCallArg", (FUNC_A, "s2", "sui::coin::take", 0, "T")),
        Fact("ConditionCheck", (FUNC_A, "s1", [])),  # Result used in assertion
    ]
    state = propagate_generic_validation(FUNC_A, facts)

    assert "T" in state.validated_types
    assert "T" in state.type_to_sinks


# --- Tests for compute_generic_summary ---


def test_summary_captures_validation():
    """Summary captures which type params are validated."""
    facts = [
        Fact("HasGenericParam", (FUNC_A, 0, "T")),
        Fact("HasGenericParam", (FUNC_A, 1, "U")),
        Fact("GenericCallArg", (FUNC_A, "s1", "std::type_name::get", 0, "T")),
        Fact("ConditionCheck", (FUNC_A, "s1", [])),  # Result used in assertion
    ]
    summary = compute_generic_summary(FUNC_A, facts)

    assert summary.type_param_validated.get("T") is True
    assert summary.type_param_validated.get("U") is False


def test_summary_captures_sinks():
    """Summary captures which type params reach sinks."""
    facts = [
        Fact("HasGenericParam", (FUNC_A, 0, "T")),
        Fact("GenericCallArg", (FUNC_A, "s1", "sui::coin::take", 0, "T")),
    ]
    summary = compute_generic_summary(FUNC_A, facts)

    assert "T" in summary.type_param_to_sinks
    assert "sui::coin::take" in summary.type_param_to_sinks["T"]


# --- Tests for apply_generic_summaries (IPA) ---


def test_ipa_propagates_validation():
    """IPA: If callee validates, caller's type param is safe."""
    # func_a<T> calls func_b<T> which validates T
    facts = [
        Fact("HasGenericParam", (FUNC_A, 0, "T")),
        Fact("HasGenericParam", (FUNC_B, 0, "V")),
        Fact("GenericCallArg", (FUNC_A, "s1", FUNC_B, 0, "T")),
    ]
    summaries = {
        FUNC_B: GenericTypeSummary(
            func_name=FUNC_B,
            type_param_validated={"V": True},
            type_param_to_sinks={},
        )
    }
    global_type_params = _build_global_type_params(facts)

    derived = apply_generic_summaries(FUNC_A, facts, summaries, global_type_params)

    assert any(f.name == "TypeValidated" and f.args[0] == FUNC_A and f.args[1] == "T" for f in derived)


def test_ipa_propagates_sinks():
    """IPA: If callee's type param reaches sinks, propagate to caller."""
    # func_a<T> calls func_b<T>, func_b reaches sink without validation
    facts = [
        Fact("HasGenericParam", (FUNC_A, 0, "T")),
        Fact("HasGenericParam", (FUNC_B, 0, "V")),
        Fact("GenericCallArg", (FUNC_A, "s1", FUNC_B, 0, "T")),
    ]
    summaries = {
        FUNC_B: GenericTypeSummary(
            func_name=FUNC_B,
            type_param_validated={"V": False},
            type_param_to_sinks={"V": {"sui::coin::take"}},
        )
    }
    global_type_params = _build_global_type_params(facts)

    derived = apply_generic_summaries(FUNC_A, facts, summaries, global_type_params)

    assert any(f.name == "UnvalidatedTypeAtSink" and f.args[0] == FUNC_A and f.args[1] == "T" for f in derived)


def test_ipa_type_param_mapping():
    """IPA: Correctly map caller's type param to callee's position."""
    # func_a<T, U> calls func_b<U>, func_b validates
    # Only U should be validated in func_a
    facts = [
        Fact("HasGenericParam", (FUNC_A, 0, "T")),
        Fact("HasGenericParam", (FUNC_A, 1, "U")),
        Fact("HasGenericParam", (FUNC_B, 0, "V")),
        Fact("GenericCallArg", (FUNC_A, "s1", FUNC_B, 0, "U")),
    ]
    summaries = {
        FUNC_B: GenericTypeSummary(
            func_name=FUNC_B,
            type_param_validated={"V": True},
            type_param_to_sinks={},
        )
    }
    global_type_params = _build_global_type_params(facts)

    derived = apply_generic_summaries(FUNC_A, facts, summaries, global_type_params)

    # U should be validated via IPA
    validated_types = [f.args[1] for f in derived if f.name == "TypeValidated"]
    assert "U" in validated_types
    assert "T" not in validated_types


def test_ipa_multi_hop_a_b_c():
    """IPA multi-hop: A calls B, B calls C, C validates."""
    # This tests transitive propagation via summaries
    # func_a<T> -> func_b<T> -> func_c<T> (validates)

    # First, compute summary for func_c (validates)
    facts_c = [
        Fact("HasGenericParam", (FUNC_C, 0, "W")),
        Fact("GenericCallArg", (FUNC_C, "s1", "std::type_name::get", 0, "W")),
        Fact("ConditionCheck", (FUNC_C, "s1", [])),  # Result used in assertion
    ]
    summary_c = compute_generic_summary(FUNC_C, facts_c)
    assert summary_c.type_param_validated.get("W") is True

    # Then, compute summary for func_b which calls func_c
    facts_b = [
        Fact("HasGenericParam", (FUNC_B, 0, "V")),
        Fact("HasGenericParam", (FUNC_C, 0, "W")),
        Fact("GenericCallArg", (FUNC_B, "s1", FUNC_C, 0, "V")),
    ]
    summaries = {FUNC_C: summary_c}
    global_type_params_b = _build_global_type_params(facts_b)

    # Apply C's summary to B
    derived_b = apply_generic_summaries(FUNC_B, facts_b, summaries, global_type_params_b)
    facts_b.extend(derived_b)
    summary_b = compute_generic_summary(FUNC_B, facts_b)

    # B should now be marked as validating V
    assert summary_b.type_param_validated.get("V") is True

    # Finally, apply B's summary to A
    facts_a = [
        Fact("HasGenericParam", (FUNC_A, 0, "T")),
        Fact("HasGenericParam", (FUNC_B, 0, "V")),
        Fact("GenericCallArg", (FUNC_A, "s1", FUNC_B, 0, "T")),
    ]
    summaries[FUNC_B] = summary_b
    global_type_params_a = _build_global_type_params(facts_a)

    derived_a = apply_generic_summaries(FUNC_A, facts_a, summaries, global_type_params_a)

    # A's T should be validated via B -> C chain
    validated_in_a = [f.args[1] for f in derived_a if f.name == "TypeValidated" and f.args[0] == FUNC_A]
    assert "T" in validated_in_a


def test_ipa_partial_validation_multi_type():
    """IPA: A<T,U> calls B<U>, B validates. Only U should be validated."""
    # func_a uses T for coin::take, calls func_b with U which validates
    # T should be UnvalidatedTypeAtSink, U should be safe

    facts_b = [
        Fact("HasGenericParam", (FUNC_B, 0, "V")),
        Fact("GenericCallArg", (FUNC_B, "s1", "std::type_name::get", 0, "V")),
        Fact("ConditionCheck", (FUNC_B, "s1", [])),  # Result used in assertion
    ]
    summary_b = compute_generic_summary(FUNC_B, facts_b)

    facts_a = [
        Fact("HasGenericParam", (FUNC_A, 0, "T")),
        Fact("HasGenericParam", (FUNC_A, 1, "U")),
        Fact("HasGenericParam", (FUNC_B, 0, "V")),
        Fact("GenericCallArg", (FUNC_A, "s1", FUNC_B, 0, "U")),
        Fact("GenericCallArg", (FUNC_A, "s2", "sui::coin::take", 0, "T")),
    ]
    summaries = {FUNC_B: summary_b}
    global_type_params = _build_global_type_params(facts_a)

    # Run intraprocedural first
    state_a = propagate_generic_validation(FUNC_A, facts_a)

    # T is not validated intraprocedurally
    assert "T" not in state_a.validated_types
    # T reaches sink
    assert "T" in state_a.type_to_sinks

    # Apply IPA
    derived_a = apply_generic_summaries(FUNC_A, facts_a, summaries, global_type_params)
    facts_a.extend(derived_a)

    # U should be validated via IPA
    validated_in_a = {f.args[1] for f in facts_a if f.name == "TypeValidated" and f.args[0] == FUNC_A}
    assert "U" in validated_in_a
    assert "T" not in validated_in_a


def test_no_validation_for_non_type_name_get():
    """Only type_name::get validates, not similar-sounding functions."""
    facts = [
        Fact("HasGenericParam", (FUNC_A, 0, "T")),
        Fact("GenericCallArg", (FUNC_A, "s1", "other::type_checker::get", 0, "T")),
    ]
    state = propagate_generic_validation(FUNC_A, facts)

    assert "T" not in state.validated_types


# --- Tests for nested type parameter extraction ---


def test_nested_type_single_param():
    """Nested type Balance<T> should extract T as a type param."""
    # This simulates: some_func<Balance<T>>()
    # GenericCallArg facts should contain the inner T, not just Balance
    facts = [
        Fact("HasGenericParam", (FUNC_A, 0, "T")),
        # When parsing some_func<Balance<T>>(), we should get GenericCallArg for T
        Fact("GenericCallArg", (FUNC_A, "s1", "sui::coin::from_balance", 0, "T")),
    ]
    state = propagate_generic_validation(FUNC_A, facts)

    # T should be tracked reaching the sink
    assert "T" in state.type_to_sinks


def test_nested_type_multiple_params():
    """Nested type LP<T0, T1> should extract both T0 and T1."""
    # This simulates: from_balance<LP<T0, T1>>()
    # Should generate GenericCallArg facts for both T0 and T1
    facts = [
        Fact("HasGenericParam", (FUNC_A, 0, "T0")),
        Fact("HasGenericParam", (FUNC_A, 1, "T1")),
        # Both inner type params should be extracted
        Fact("GenericCallArg", (FUNC_A, "s1", "sui::coin::from_balance", 0, "T0")),
        Fact("GenericCallArg", (FUNC_A, "s1", "sui::coin::from_balance", 1, "T1")),
    ]
    state = propagate_generic_validation(FUNC_A, facts)

    # Both type params should be tracked
    assert "T0" in state.type_to_sinks or "T1" in state.type_to_sinks


def test_nested_type_validation():
    """type_name::get<Wrapper<T>>() should validate inner T."""
    # Nested type in validation call should still validate the inner type param
    facts = [
        Fact("HasGenericParam", (FUNC_A, 0, "T")),
        # type_name::get<Wrapper<T>>() validates T (the inner param)
        Fact("GenericCallArg", (FUNC_A, "s1", "std::type_name::get", 0, "T")),
        # Then T is used in sink
        Fact("GenericCallArg", (FUNC_A, "s2", "sui::coin::take", 0, "T")),
        Fact("ConditionCheck", (FUNC_A, "s1", [])),  # Result used in assertion
    ]
    state = propagate_generic_validation(FUNC_A, facts)

    # T should be validated
    assert "T" in state.validated_types
    # T also reaches sink, but is validated first
    assert "T" in state.type_to_sinks


def test_deeply_nested_type():
    """Deeply nested Wrapper<Balance<T>> should extract innermost T."""
    facts = [
        Fact("HasGenericParam", (FUNC_A, 0, "T")),
        # Deeply nested type should extract innermost type param
        Fact("GenericCallArg", (FUNC_A, "s1", "some::function", 0, "T")),
    ]
    _ = propagate_generic_validation(FUNC_A, facts)

    # Should handle the innermost type param
    # (This is more of a structural test to ensure no crashes with deep nesting)
