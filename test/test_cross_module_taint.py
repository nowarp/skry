"""Tests for cross-module taint propagation."""

from core.context import ProjectContext
from core.facts import Fact
from taint.interproc import FunctionSummary
from taint.cross_module import propagate_taint_across_modules


def make_ctx_with_files(file_facts: dict) -> ProjectContext:
    """Create ProjectContext with multiple files and their facts."""
    ctx = ProjectContext(list(file_facts.keys()))
    for file_path, facts in file_facts.items():
        ctx.source_files[file_path].facts = facts
    return ctx


class TestCrossModuleTaintPropagation:
    """Test cross-module taint detection."""

    def test_entry_calls_callee_with_tainted_arg_reaching_sink(self):
        """
        entry foo(recipient: address) {
            bar(recipient);  // passes tainted arg
        }

        fun bar(addr: address) {
            transfer::transfer(coin, addr);  // sink
        }

        Should emit TaintedSinkInCallee(foo, bar, transfer_recipient, recipient)
        """
        ctx = make_ctx_with_files({
            "module_a.move": [
                Fact("Fun", ("module_a::foo",)),
                Fact("IsEntry", ("module_a::foo",)),
                Fact("IsPublic", ("module_a::foo",)),
                Fact("TaintSource", ("module_a::foo", "recipient", 0)),
                Fact("Tainted", ("module_a::foo", "recipient")),
                Fact("CallArg", ("module_a::foo", "stmt_1", "module_b::bar", 0, ("recipient",))),
                Fact("Calls", ("module_a::foo", "module_b::bar")),
            ],
        })

        # Add function summary for bar - param 0 reaches transfer_recipient sink
        ctx.function_summaries["module_b::bar"] = FunctionSummary(
            func_name="module_b::bar",
            param_to_sinks={0: {"transfer_recipient"}},
        )

        propagate_taint_across_modules(ctx)

        # Check that proper taint fact was generated for entry
        sink_facts = [f for f in ctx.source_files["module_a.move"].facts
                      if f.name == "TaintedAtSink"]
        assert len(sink_facts) == 1
        fact = sink_facts[0]
        assert fact.args[0] == "module_a::foo"  # entry
        assert fact.args[1] == "recipient"  # source_param
        assert "via" in fact.args[2]  # stmt_id contains "via"

    def test_no_fact_when_arg_not_tainted(self):
        """No taint fact if the passed arg is not tainted."""
        ctx = make_ctx_with_files({
            "module_a.move": [
                Fact("Fun", ("module_a::foo",)),
                Fact("IsEntry", ("module_a::foo",)),
                Fact("TaintSource", ("module_a::foo", "recipient", 0)),
                # Note: "safe_addr" is NOT in tainted vars
                Fact("CallArg", ("module_a::foo", "stmt_1", "module_b::bar", 0, ("safe_addr",))),
                Fact("Calls", ("module_a::foo", "module_b::bar")),
            ],
        })

        ctx.function_summaries["module_b::bar"] = FunctionSummary(
            func_name="module_b::bar",
            param_to_sinks={0: {"transfer_recipient"}},
        )

        propagate_taint_across_modules(ctx)

        sink_facts = [f for f in ctx.source_files["module_a.move"].facts
                      if f.name == "TaintedAtSink"]
        assert len(sink_facts) == 0

    def test_no_fact_when_callee_has_no_sinks(self):
        """No taint fact if callee summary has no sinks."""
        ctx = make_ctx_with_files({
            "module_a.move": [
                Fact("Fun", ("module_a::foo",)),
                Fact("IsEntry", ("module_a::foo",)),
                Fact("TaintSource", ("module_a::foo", "recipient", 0)),
                Fact("Tainted", ("module_a::foo", "recipient")),
                Fact("CallArg", ("module_a::foo", "stmt_1", "module_b::bar", 0, ("recipient",))),
                Fact("Calls", ("module_a::foo", "module_b::bar")),
            ],
        })

        # Summary with no sinks
        ctx.function_summaries["module_b::bar"] = FunctionSummary(
            func_name="module_b::bar",
            param_to_sinks={},
        )

        propagate_taint_across_modules(ctx)

        sink_facts = [f for f in ctx.source_files["module_a.move"].facts
                      if f.name == "TaintedAtSink"]
        assert len(sink_facts) == 0

    def test_no_fact_when_wrong_arg_position(self):
        """No taint fact if tainted arg doesn't match sink param position."""
        ctx = make_ctx_with_files({
            "module_a.move": [
                Fact("Fun", ("module_a::foo",)),
                Fact("IsEntry", ("module_a::foo",)),
                Fact("TaintSource", ("module_a::foo", "recipient", 0)),
                Fact("Tainted", ("module_a::foo", "recipient")),
                # Pass tainted arg at position 1, but sink is at position 0
                Fact("CallArg", ("module_a::foo", "stmt_1", "module_b::bar", 1, ("recipient",))),
                Fact("Calls", ("module_a::foo", "module_b::bar")),
            ],
        })

        # Sink only for param 0, not param 1
        ctx.function_summaries["module_b::bar"] = FunctionSummary(
            func_name="module_b::bar",
            param_to_sinks={0: {"transfer_recipient"}},
        )

        propagate_taint_across_modules(ctx)

        sink_facts = [f for f in ctx.source_files["module_a.move"].facts
                      if f.name == "TaintedAtSink"]
        assert len(sink_facts) == 0

    def test_multiple_sink_types(self):
        """Generate facts for multiple sink types from same callee."""
        ctx = make_ctx_with_files({
            "module_a.move": [
                Fact("Fun", ("module_a::foo",)),
                Fact("IsEntry", ("module_a::foo",)),
                Fact("TaintSource", ("module_a::foo", "data", 0)),
                Fact("Tainted", ("module_a::foo", "data")),
                Fact("CallArg", ("module_a::foo", "stmt_1", "module_b::bar", 0, ("data",))),
                Fact("Calls", ("module_a::foo", "module_b::bar")),
            ],
        })

        # Summary with multiple sink types for param 0
        ctx.function_summaries["module_b::bar"] = FunctionSummary(
            func_name="module_b::bar",
            param_to_sinks={0: {"transfer_recipient", "state_write"}},
        )

        propagate_taint_across_modules(ctx)

        # Check for both taint fact types (now unified as TaintedAtSink with different sink_types)
        tainted_facts = [f for f in ctx.source_files["module_a.move"].facts
                        if f.name == "TaintedAtSink"]
        assert len(tainted_facts) == 2  # One for each sink type

        # Verify we have one of each sink_type
        sink_types = {f.args[3] for f in tainted_facts}
        assert sink_types == {"transfer_recipient", "state_write"}

    def test_no_summaries_available(self):
        """No crash when no summaries available."""
        ctx = make_ctx_with_files({
            "module_a.move": [
                Fact("Fun", ("module_a::foo",)),
                Fact("IsEntry", ("module_a::foo",)),
            ],
        })
        # No summaries
        ctx.function_summaries = {}

        # Should not crash
        propagate_taint_across_modules(ctx)

    def test_empty_call_graph(self):
        """No crash when call graph is empty."""
        ctx = make_ctx_with_files({
            "module_a.move": [
                Fact("Fun", ("module_a::foo",)),
                Fact("IsEntry", ("module_a::foo",)),
                Fact("TaintSource", ("module_a::foo", "recipient", 0)),
            ],
        })
        # No Calls facts

        ctx.function_summaries["module_b::bar"] = FunctionSummary(
            func_name="module_b::bar",
            param_to_sinks={0: {"transfer_recipient"}},
        )

        propagate_taint_across_modules(ctx)

        sink_facts = [f for f in ctx.source_files["module_a.move"].facts
                      if f.name == "TaintedSinkInCallee"]
        assert len(sink_facts) == 0


class TestTransitiveTaintPropagation:
    """Test multi-hop taint propagation through call chains."""

    def test_taint_through_intermediate_callee(self):
        """
        Multi-hop taint: entry -> bar -> baz -> sink

        entry foo(recipient: address) {
            bar(recipient);
        }

        fun bar(addr: address) {
            baz(addr);  // passes to another callee
        }

        fun baz(dest: address) {
            transfer::transfer(coin, dest);  // sink
        }

        Should emit TaintedSinkInCallee(foo, baz, transfer_recipient, recipient)
        """
        ctx = make_ctx_with_files({
            "module_a.move": [
                # Entry function foo
                Fact("Fun", ("module_a::foo",)),
                Fact("IsEntry", ("module_a::foo",)),
                Fact("TaintSource", ("module_a::foo", "recipient", 0)),
                Fact("Tainted", ("module_a::foo", "recipient")),
                # foo calls bar with tainted recipient
                Fact("CallArg", ("module_a::foo", "stmt_1", "module_a::bar", 0, ("recipient",))),
                Fact("Calls", ("module_a::foo", "module_a::bar")),

                # Intermediate function bar
                Fact("Fun", ("module_a::bar",)),
                Fact("FormalArg", ("module_a::bar", 0, "addr", "address")),
                Fact("TaintSource", ("module_a::bar", "addr", 0)),
                Fact("Tainted", ("module_a::bar", "addr")),
                # bar calls baz with its tainted param
                Fact("CallArg", ("module_a::bar", "stmt_2", "module_b::baz", 0, ("addr",))),
                Fact("Calls", ("module_a::bar", "module_b::baz")),
            ],
        })

        # Summary for bar: param 0 flows to baz's param 0
        ctx.function_summaries["module_a::bar"] = FunctionSummary(
            func_name="module_a::bar",
            param_to_sinks={},  # bar itself has no direct sink
        )

        # Summary for baz: param 0 reaches transfer_recipient sink
        ctx.function_summaries["module_b::baz"] = FunctionSummary(
            func_name="module_b::baz",
            param_to_sinks={0: {"transfer_recipient"}},
        )

        propagate_taint_across_modules(ctx)

        sink_facts = [f for f in ctx.source_files["module_a.move"].facts
                      if f.name == "TaintedAtSink"]

        # Should detect that foo's recipient reaches sink via bar
        # (bar's summary is composed with baz's sink)
        # Note: Multihop creates facts at each hop, so we may have multiple facts
        assert len(sink_facts) >= 1, f"Expected TaintedTransferRecipient, got: {sink_facts}"

        # The facts are for the entry function
        foo_sink = [f for f in sink_facts if f.args[0] == "module_a::foo"]
        assert len(foo_sink) >= 1, f"Expected sink fact for foo, got: {sink_facts}"

        # Verify at least one fact has the correct source param
        has_recipient = any(f.args[1] == "recipient" for f in foo_sink)
        assert has_recipient, f"Expected fact with source 'recipient', got: {foo_sink}"
        assert foo_sink[0].args[1] == "recipient"  # source param

        # Verify bar's summary was composed with baz's sink
        bar_summary = ctx.function_summaries["module_a::bar"]
        assert 0 in bar_summary.param_to_sinks
        assert "transfer_recipient" in bar_summary.param_to_sinks[0]

    def test_taint_three_hop_chain(self):
        """
        Three-hop: entry -> a -> b -> c -> sink

        entry foo(data) { a(data); }
        fun a(x) { b(x); }
        fun b(y) { c(y); }
        fun c(z) { state_write(z); }  // sink
        """
        ctx = make_ctx_with_files({
            "entry.move": [
                Fact("Fun", ("entry::foo",)),
                Fact("IsEntry", ("entry::foo",)),
                Fact("TaintSource", ("entry::foo", "data", 0)),
                Fact("Tainted", ("entry::foo", "data")),
                Fact("CallArg", ("entry::foo", "s1", "mod::a", 0, ("data",))),
                Fact("Calls", ("entry::foo", "mod::a")),
            ],
            "mod.move": [
                # Function a
                Fact("Fun", ("mod::a",)),
                Fact("FormalArg", ("mod::a", 0, "x", "u64")),
                Fact("TaintSource", ("mod::a", "x", 0)),
                Fact("Tainted", ("mod::a", "x")),
                Fact("CallArg", ("mod::a", "s2", "mod::b", 0, ("x",))),
                Fact("Calls", ("mod::a", "mod::b")),

                # Function b
                Fact("Fun", ("mod::b",)),
                Fact("FormalArg", ("mod::b", 0, "y", "u64")),
                Fact("TaintSource", ("mod::b", "y", 0)),
                Fact("Tainted", ("mod::b", "y")),
                Fact("CallArg", ("mod::b", "s3", "mod::c", 0, ("y",))),
                Fact("Calls", ("mod::b", "mod::c")),

                # Function c - has the sink
                Fact("Fun", ("mod::c",)),
                Fact("FormalArg", ("mod::c", 0, "z", "u64")),
            ],
        })

        # Summaries - only c has a sink
        ctx.function_summaries["mod::a"] = FunctionSummary(func_name="mod::a", param_to_sinks={})
        ctx.function_summaries["mod::b"] = FunctionSummary(func_name="mod::b", param_to_sinks={})
        ctx.function_summaries["mod::c"] = FunctionSummary(
            func_name="mod::c",
            param_to_sinks={0: {"state_write"}},
        )

        propagate_taint_across_modules(ctx)

        sink_facts = [f for f in ctx.source_files["entry.move"].facts
                      if f.name == "TaintedAtSink"]

        # Should detect foo's data reaches sink via a (which composes b -> c)
        # Note: Multihop creates facts at each hop, so we may have multiple facts
        assert len(sink_facts) >= 1, "Expected TaintedStateWrite for 3-hop chain, got none"

        # The facts are for the entry function
        foo_sink = [f for f in sink_facts if f.args[0] == "entry::foo"]
        assert len(foo_sink) >= 1, f"Expected sink fact for foo, got: {sink_facts}"

        # Verify at least one fact has the correct source param
        has_data = any(f.args[1] == "data" for f in foo_sink)
        assert has_data, f"Expected fact with source 'data', got: {foo_sink}"

        # Verify summaries were composed transitively: c -> b -> a
        a_summary = ctx.function_summaries["mod::a"]
        b_summary = ctx.function_summaries["mod::b"]
        assert 0 in a_summary.param_to_sinks, "a should have composed sink"
        assert "state_write" in a_summary.param_to_sinks[0]
        assert 0 in b_summary.param_to_sinks, "b should have composed sink from c"
        assert "state_write" in b_summary.param_to_sinks[0]
