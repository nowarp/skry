from core.context import ProjectContext
from core.facts import Fact
from analysis.call_graph import build_call_graph_ir


class TestCallGraphIR:
    """Test CallGraph IR building and transitive callee computation."""

    def test_build_call_graph_ir_basic(self):
        """Test basic call graph IR building."""
        ctx = ProjectContext([])
        ctx.source_files["test.move"] = type(
            "FileCtx",
            (),
            {
                "facts": [
                    Fact("Calls", ("a", "b")),
                    Fact("Calls", ("b", "c")),
                    Fact("Calls", ("a", "d")),
                ]
            },
        )()

        cg = build_call_graph_ir(ctx)

        assert ctx.call_graph is cg
        assert cg.callees["a"] == {"b", "d"}
        assert cg.callees["b"] == {"c"}
        assert cg.callers["b"] == {"a"}
        assert cg.callers["c"] == {"b"}
        assert cg.callers["d"] == {"a"}

    def test_transitive_callees(self):
        """Test transitive callee computation."""
        ctx = ProjectContext([])
        ctx.source_files["test.move"] = type(
            "FileCtx",
            (),
            {
                "facts": [
                    Fact("Calls", ("entry", "helper")),
                    Fact("Calls", ("helper", "deep")),
                ]
            },
        )()

        cg = build_call_graph_ir(ctx)

        # entry -> helper -> deep
        assert cg.transitive_callees["entry"] == {"helper", "deep"}
        assert cg.transitive_callees["helper"] == {"deep"}

    def test_cyclic_calls(self):
        """Test call graph with cycles doesn't infinite loop."""
        ctx = ProjectContext([])
        ctx.source_files["test.move"] = type(
            "FileCtx",
            (),
            {
                "facts": [
                    Fact("Calls", ("a", "b")),
                    Fact("Calls", ("b", "a")),  # Cycle
                ]
            },
        )()

        cg = build_call_graph_ir(ctx)

        # Both should have each other as transitive callees
        assert "b" in cg.transitive_callees["a"]
        assert "a" in cg.transitive_callees["b"]
