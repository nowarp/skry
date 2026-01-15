from typing import List

from core.facts import Fact
from taint.analysis import (
    propagate_taint,
    analyze_sink_reachability,
)

def sorted_facts(facts: List[Fact]) -> List[Fact]:
    return sorted(facts, key=lambda f: (f.name, f.args))

def assert_facts_equal(actual: List[Fact], expected: List[Fact]):
    assert sorted_facts(actual) == sorted_facts(expected)

FUNC_NAME = "test_func"

# --- Tests for propagate_taint ---

def test_propagate_taint_simple_assignment():
    facts = [
        Fact("TaintSource", (FUNC_NAME, "p0", 0)),
        Fact("Assigns", (FUNC_NAME, "s1", "x", ("p0",))),
    ]
    derived = propagate_taint(FUNC_NAME, facts)
    expected = [
        Fact("Tainted", (FUNC_NAME, "p0")),
        Fact("Tainted", (FUNC_NAME, "x")),
        Fact("TaintedBy", (FUNC_NAME, "x", "p0")),
    ]
    assert_facts_equal(derived, expected)

def test_propagate_taint_call_result():
    facts = [
        Fact("TaintSource", (FUNC_NAME, "p0", 0)),
        Fact("CallResult", (FUNC_NAME, "s1", "res", "some_call")),
        Fact("CallArg", (FUNC_NAME, "s1", "some_call", 0, ("p0",))),
    ]
    derived = propagate_taint(FUNC_NAME, facts)
    expected = [
        Fact("Tainted", (FUNC_NAME, "p0")),
        Fact("Tainted", (FUNC_NAME, "res")),
        Fact("TaintedBy", (FUNC_NAME, "res", "p0")),
    ]
    assert_facts_equal(derived, expected)

def test_propagate_taint_no_propagation():
    facts = [
        Fact("TaintSource", (FUNC_NAME, "p0", 0)),
        Fact("Assigns", (FUNC_NAME, "s1", "x", ("y",))),  # y is not tainted
    ]
    derived = propagate_taint(FUNC_NAME, facts)
    expected = [
        Fact("Tainted", (FUNC_NAME, "p0")),
    ]
    assert_facts_equal(derived, expected)

# --- Tests for analyze_sink_reachability ---

def test_analyze_sink_reachability_reaches():
    facts = [
        Fact("Tainted", (FUNC_NAME, "x")),
        Fact("TaintedBy", (FUNC_NAME, "x", "p0")),
        Fact("SinkUsesVar", (FUNC_NAME, "s_sink", "x", "recipient")),
        Fact("TransferSink", (FUNC_NAME, "s_sink", "transfer")),
    ]
    derived = analyze_sink_reachability(FUNC_NAME, facts)
    expected = [
        Fact("TaintedAtSink", (FUNC_NAME, "p0", "s_sink", "transfer_recipient", "recipient")),
    ]
    assert_facts_equal(derived, expected)

def test_analyze_sink_reachability_not_tainted():
    facts = [
        Fact("Tainted", (FUNC_NAME, "y")),  # x is not tainted
        Fact("SinkUsesVar", (FUNC_NAME, "s_sink", "x", "recipient")),
        Fact("TransferSink", (FUNC_NAME, "s_sink", "transfer")),
    ]
    derived = analyze_sink_reachability(FUNC_NAME, facts)
    assert derived == []
