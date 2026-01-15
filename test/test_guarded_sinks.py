"""Tests for per-sink guard tracking (Phase 2 IPA)."""

from core.facts import Fact
from core.context import ProjectContext
from taint.interproc import FunctionSummary
from taint.guards import (
    collect_function_guards,
    enrich_summaries_with_guards,
    generate_guarded_sink_facts,
)


class TestCollectFunctionGuards:
    """Test collect_function_guards function."""

    def _make_ctx(self, facts_by_file: dict) -> ProjectContext:
        """Create ProjectContext with given facts."""
        ctx = ProjectContext(list(facts_by_file.keys()))
        for file_path, facts in facts_by_file.items():
            ctx.source_files[file_path].facts = facts
        return ctx

    def test_collects_sender_guard(self):
        """Collects sender guard from HasSenderEqualityCheck fact."""
        ctx = self._make_ctx({
            "file.move": [
                Fact("HasSenderEqualityCheck", ("withdraw",)),
            ],
        })

        guards = collect_function_guards(ctx)

        assert "withdraw" in guards
        assert "sender" in guards["withdraw"]

    def test_collects_role_guard(self):
        """Collects role guard from ChecksCapability fact."""
        ctx = self._make_ctx({
            "file.move": [
                Fact("ChecksCapability", ("AdminCap", "admin_action")),
            ],
        })

        guards = collect_function_guards(ctx)

        assert "admin_action" in guards
        assert "role:AdminCap" in guards["admin_action"]

    def test_collects_version_guard(self):
        """Collects version guard from HasVersionCheck fact."""
        ctx = self._make_ctx({
            "file.move": [
                Fact("HasVersionCheck", ("versioned_func",)),
            ],
        })

        guards = collect_function_guards(ctx)

        assert "versioned_func" in guards
        assert "version" in guards["versioned_func"]

    def test_collects_pause_from_project_facts(self):
        """Collects pause guard from ChecksPause in project_facts."""
        ctx = self._make_ctx({"file.move": []})
        ctx.project_facts = [Fact("ChecksPause", ("paused_func",))]

        guards = collect_function_guards(ctx)

        assert "paused_func" in guards
        assert "pause" in guards["paused_func"]

    def test_multiple_guards_same_function(self):
        """Function can have multiple guard types."""
        ctx = self._make_ctx({
            "file.move": [
                Fact("HasSenderEqualityCheck", ("secure_func",)),
                Fact("ChecksCapability", ("AdminCap", "secure_func")),
            ],
        })

        guards = collect_function_guards(ctx)

        assert "secure_func" in guards
        assert guards["secure_func"] == {"sender", "role:AdminCap"}


class TestEnrichSummariesWithGuards:
    """Test enrich_summaries_with_guards function."""

    def _make_ctx(self, facts_by_file: dict) -> ProjectContext:
        """Create ProjectContext with given facts."""
        ctx = ProjectContext(list(facts_by_file.keys()))
        for file_path, facts in facts_by_file.items():
            ctx.source_files[file_path].facts = facts
        return ctx

    def test_adds_guards_to_summary(self):
        """Adds guards to existing summary."""
        ctx = self._make_ctx({
            "file.move": [
                Fact("HasSenderEqualityCheck", ("withdraw",)),
            ],
        })
        ctx.function_summaries = {
            "withdraw": FunctionSummary(func_name="withdraw"),
        }

        enrich_summaries_with_guards(ctx)

        assert "sender" in ctx.function_summaries["withdraw"].guards

    def test_no_guards_for_unguarded_function(self):
        """No guards added for function without guard facts."""
        ctx = self._make_ctx({"file.move": []})
        ctx.function_summaries = {
            "unguarded": FunctionSummary(func_name="unguarded"),
        }

        enrich_summaries_with_guards(ctx)

        assert len(ctx.function_summaries["unguarded"].guards) == 0


class TestGenerateGuardedSinkFacts:
    """Test generate_guarded_sink_facts function."""

    def _make_ctx(self, facts_by_file: dict) -> ProjectContext:
        """Create ProjectContext with given facts."""
        ctx = ProjectContext(list(facts_by_file.keys()))
        for file_path, facts in facts_by_file.items():
            ctx.source_files[file_path].facts = facts
        return ctx

    def test_generates_guarded_sink_for_recipient(self):
        """Generates GuardedSink for TaintedTransferRecipient with sender check."""
        ctx = self._make_ctx({
            "file.move": [
                Fact("HasSenderEqualityCheck", ("withdraw",)),
                Fact("TaintedAtSink", ("withdraw", "recipient", "stmt1", "transfer_recipient", "")),
            ],
        })

        count = generate_guarded_sink_facts(ctx)

        assert count == 1
        facts = ctx.source_files["file.move"].facts
        assert any(
            f.name == "GuardedSink" and f.args == ("withdraw", "stmt1", "sender")
            for f in facts
        )

    def test_generates_guarded_sink_for_value(self):
        """Generates GuardedSink for TaintedTransferValue with sender check."""
        ctx = self._make_ctx({
            "file.move": [
                Fact("HasSenderEqualityCheck", ("deposit",)),
                Fact("TaintedAtSink", ("deposit", "amount", "stmt2", "transfer_value", "")),
            ],
        })

        count = generate_guarded_sink_facts(ctx)

        assert count == 1
        facts = ctx.source_files["file.move"].facts
        assert any(
            f.name == "GuardedSink" and f.args == ("deposit", "stmt2", "sender")
            for f in facts
        )

    def test_multiple_guards_multiple_facts(self):
        """Multiple guards generate multiple GuardedSink facts per sink."""
        ctx = self._make_ctx({
            "file.move": [
                Fact("HasSenderEqualityCheck", ("func",)),
                Fact("ChecksCapability", ("AdminCap", "func")),
                Fact("TaintedAtSink", ("func", "recipient", "stmt1", "transfer_recipient", "")),
            ],
        })

        count = generate_guarded_sink_facts(ctx)

        assert count == 2  # One for sender, one for role
        facts = ctx.source_files["file.move"].facts
        assert any(f.name == "GuardedSink" and f.args == ("func", "stmt1", "sender") for f in facts)
        assert any(f.name == "GuardedSink" and f.args == ("func", "stmt1", "role:AdminCap") for f in facts)

    def test_no_guards_no_facts(self):
        """No GuardedSink facts when function has no guards."""
        ctx = self._make_ctx({
            "file.move": [
                Fact("TaintedAtSink", ("unguarded", "recipient", "stmt1", "transfer_recipient", "")),
            ],
        })

        count = generate_guarded_sink_facts(ctx)

        assert count == 0
        facts = ctx.source_files["file.move"].facts
        assert not any(f.name == "GuardedSink" for f in facts)

    def test_handles_multiple_sinks(self):
        """Handles function with multiple sinks."""
        ctx = self._make_ctx({
            "file.move": [
                Fact("HasSenderEqualityCheck", ("multi_sink",)),
                Fact("TaintedAtSink", ("multi_sink", "r1", "stmt1", "transfer_recipient", "")),
                Fact("TaintedAtSink", ("multi_sink", "v1", "stmt2", "transfer_value", "")),
                Fact("TaintedAtSink", ("multi_sink", "s1", "stmt3", "state_write", "")),
            ],
        })

        count = generate_guarded_sink_facts(ctx)

        assert count == 3  # One per sink
        facts = ctx.source_files["file.move"].facts
        guarded_sinks = [f for f in facts if f.name == "GuardedSink"]
        assert len(guarded_sinks) == 3
        stmt_ids = {f.args[1] for f in guarded_sinks}
        assert stmt_ids == {"stmt1", "stmt2", "stmt3"}


class TestTransitiveGuardPropagation:
    """Test transitive guard propagation via function summaries."""

    def _make_ctx(self, facts_by_file: dict) -> ProjectContext:
        """Create ProjectContext with given facts."""
        ctx = ProjectContext(list(facts_by_file.keys()))
        for file_path, facts in facts_by_file.items():
            ctx.source_files[file_path].facts = facts
        return ctx

    def test_summary_guards_used_for_guarded_sink(self):
        """Guards from function summaries generate GuardedSink facts.

        Scenario: caller() calls callee() which has HasSenderEqualityCheck.
        Caller has a sink. After summary composition, caller's summary
        has callee's guards. GuardedSink should be generated for caller's sink.
        """
        ctx = self._make_ctx({
            "file.move": [
                # Caller has sink but no direct guard
                Fact("TaintedAtSink", ("caller", "recipient", "stmt1", "transfer_recipient", "")),
                # Callee has direct guard (not caller)
                Fact("HasSenderEqualityCheck", ("callee",)),
            ],
        })
        # Simulate summary with transitive guards (after composition)
        ctx.function_summaries = {
            "caller": FunctionSummary(func_name="caller", guards={"sender"}),
            "callee": FunctionSummary(func_name="callee", guards={"sender"}),
        }

        count = generate_guarded_sink_facts(ctx)

        # Caller's sink should get GuardedSink via summary guards
        assert count == 1
        facts = ctx.source_files["file.move"].facts
        assert any(
            f.name == "GuardedSink" and f.args == ("caller", "stmt1", "sender")
            for f in facts
        )


class TestCrossModuleGuardPropagation:
    """Test guard propagation through cross-module taint."""

    def _make_ctx(self, facts_by_file: dict) -> ProjectContext:
        """Create ProjectContext with given facts."""
        ctx = ProjectContext(list(facts_by_file.keys()))
        for file_path, facts in facts_by_file.items():
            ctx.source_files[file_path].facts = facts
        return ctx

    def test_callee_guards_propagate_to_summary(self):
        """Guards propagate from callee to caller summary during composition."""
        from taint.cross_module import _compose_summaries_transitively

        ctx = self._make_ctx({
            "caller.move": [
                Fact("TaintSource", ("caller", "param", 0)),
                Fact("Tainted", ("caller", "param")),
                Fact("CallArg", ("caller", "stmt1", "callee", 0, ("param",))),
            ],
            "callee.move": [
                Fact("HasSenderEqualityCheck", ("callee",)),
            ],
        })
        ctx.function_summaries = {
            "caller": FunctionSummary(func_name="caller"),
            "callee": FunctionSummary(
                func_name="callee",
                param_to_sinks={0: {"transfer_recipient"}},
                guards={"sender"},
            ),
        }

        _compose_summaries_transitively(ctx)

        # Caller should have callee's guards now
        assert "sender" in ctx.function_summaries["caller"].guards
