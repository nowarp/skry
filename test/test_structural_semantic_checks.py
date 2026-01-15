"""
Tests for semantic/structural_checks.py

Tests structural property checks:
- check_is_init
- check_public
- check_entry
- check_orphan_txcontext
- check_orphan_capability
- check_orphan_event
- check_double_init
- check_self_recursive
"""

from typing import List

from analysis.call_graph import CallGraph
from core.context import ProjectContext
from core.facts import Fact
from rules.ir import Condition
from semantic.checker import SemanticChecker
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


class MockFileContext:
    """Mock SourceFileContext for testing."""

    def __init__(self, path: str, facts: List[Fact]):
        self.path = path
        self.facts = facts
        self.source_code = ""
        self.root = None
        self.is_test_only = False


def make_mock_ctx(files: dict) -> ProjectContext:
    """Create a mock ProjectContext from a dict of {path: facts}."""
    source_files = list(files.keys())
    ctx = ProjectContext(source_files)

    for path, facts in files.items():
        ctx.source_files[path] = MockFileContext(path, facts)

    return ctx


class MinimalPattern:
    """Minimal pattern for testing."""
    def __init__(self, binding="f", pattern_type="fun"):
        self.binding = binding
        self.type = pattern_type


class MinimalMatchClause:
    """Minimal match clause for testing."""
    def __init__(self, pattern):
        self.pattern = pattern


class MinimalRule:
    """Minimal rule for testing."""
    def __init__(self, match_pattern="fun", binding_key="f"):
        self.match_pattern = match_pattern
        self.match_modifiers = []
        pattern = MinimalPattern(binding=binding_key, pattern_type=match_pattern)
        self.match_clause = MinimalMatchClause(pattern)


class TestIsInit:
    """Tests for check_is_init."""

    def test_init_function_returns_true(self):
        """If function has IsInit fact, should return True."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::init",)),
                Fact("IsInit", ("mod::init",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::init"}
        condition = Condition(subject="f", negation=False, property="is_init")

        result = check_is_init(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True

    def test_non_init_function_returns_false(self):
        """If function has no IsInit fact, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="is_init")

        result = check_is_init(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False


class TestPublic:
    """Tests for check_public."""

    def test_public_function_returns_true(self):
        """If function has IsPublic fact, should return True."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("IsPublic", ("mod::foo",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="public")

        result = check_public(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True

    def test_non_public_function_returns_false(self):
        """If function has no IsPublic fact, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="public")

        result = check_public(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False


class TestEntry:
    """Tests for check_entry."""

    def test_entry_function_returns_true(self):
        """If function has IsEntry fact, should return True."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("IsEntry", ("mod::foo",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="entry")

        result = check_entry(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True

    def test_non_entry_function_returns_false(self):
        """If function has no IsEntry fact, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="entry")

        result = check_entry(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False


class TestOrphanTxContext:
    """Tests for check_orphan_txcontext."""

    def test_orphan_txcontext_returns_true(self):
        """If function has OrphanTxContextFunction fact, should return True."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("OrphanTxContextFunction", ("mod::foo",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="orphan_txcontext")

        result = check_orphan_txcontext(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True

    def test_non_orphan_txcontext_returns_false(self):
        """If function has no OrphanTxContextFunction fact, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="orphan_txcontext")

        result = check_orphan_txcontext(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False


class TestOrphanCapability:
    """Tests for check_orphan_capability."""

    def test_orphan_capability_returns_true(self):
        """If capability has OrphanCapability fact, should return True."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Struct", ("mod::AdminCap",)),
                Fact("OrphanCapability", ("mod::AdminCap",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule(match_pattern="capability", binding_key="c")
        binding = {"c": "mod::AdminCap"}
        condition = Condition(subject="c", negation=False, property="orphan_capability")

        result = check_orphan_capability(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True

    def test_non_orphan_capability_returns_false(self):
        """If capability has no OrphanCapability fact, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Struct", ("mod::AdminCap",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule(match_pattern="capability", binding_key="c")
        binding = {"c": "mod::AdminCap"}
        condition = Condition(subject="c", negation=False, property="orphan_capability")

        result = check_orphan_capability(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False

    def test_simple_name_matching(self):
        """Should match capabilities by simple name."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Struct", ("pkg::mod::AdminCap",)),
                Fact("OrphanCapability", ("AdminCap",)),  # Simple name
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule(match_pattern="capability", binding_key="c")
        binding = {"c": "pkg::mod::AdminCap"}
        condition = Condition(subject="c", negation=False, property="orphan_capability")

        result = check_orphan_capability(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True


class TestOrphanEvent:
    """Tests for check_orphan_event."""

    def test_orphan_event_returns_true(self):
        """If event has OrphanEvent fact, should return True."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Struct", ("mod::TransferEvent",)),
                Fact("OrphanEvent", ("mod::TransferEvent",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule(match_pattern="event", binding_key="e")
        binding = {"e": "mod::TransferEvent"}
        condition = Condition(subject="e", negation=False, property="orphan_event")

        result = check_orphan_event(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True

    def test_non_orphan_event_returns_false(self):
        """If event has no OrphanEvent fact, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Struct", ("mod::TransferEvent",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule(match_pattern="event", binding_key="e")
        binding = {"e": "mod::TransferEvent"}
        condition = Condition(subject="e", negation=False, property="orphan_event")

        result = check_orphan_event(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False


class TestDoubleInit:
    """Tests for check_double_init."""

    def test_non_init_calling_init_returns_true(self):
        """If public non-init function calls init function, should return True."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("Fun", ("mod::init",)),
                Fact("IsInit", ("mod::init",)),
                Fact("IsPublic", ("mod::foo",)),  # Must be public to be flagged
            ]
        })
        ctx.call_graph = CallGraph(
            callees={"mod::foo": {"mod::init"}},
            callers={},
            transitive_callees={"mod::foo": {"mod::init"}},
        )

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="double_init")

        result = check_double_init(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True

    def test_init_calling_init_returns_false(self):
        """If init function calls another init function, should return False (allowed)."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::init",)),
                Fact("Fun", ("mod::other_init",)),
                Fact("IsInit", ("mod::init",)),
                Fact("IsInit", ("mod::other_init",)),
                Fact("InFun", ("mod::init", "mod::other_init@1")),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::init"}
        condition = Condition(subject="f", negation=False, property="double_init")

        result = check_double_init(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False

    def test_no_init_calls_returns_false(self):
        """If function doesn't call any init function, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("Fun", ("mod::init",)),
                Fact("IsInit", ("mod::init",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="double_init")

        result = check_double_init(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False

    def test_calls_init_impl_returns_true(self):
        """If public function calls InitImpl helper, should return True."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::reset",)),
                Fact("Fun", ("mod::do_init",)),
                Fact("Fun", ("mod::init",)),
                Fact("IsInit", ("mod::init",)),
                Fact("IsEntry", ("mod::reset",)),  # Must be public/entry to be flagged
                Fact("InitImpl", ("mod::do_init",)),  # Helper called by init
            ]
        })
        ctx.call_graph = CallGraph(
            callees={"mod::reset": {"mod::do_init"}},
            callers={},
            transitive_callees={"mod::reset": {"mod::do_init"}},
        )

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::reset"}
        condition = Condition(subject="f", negation=False, property="double_init")

        result = check_double_init(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True

    def test_init_impl_calling_each_other_returns_false(self):
        """InitImpl helpers can call each other (not a violation)."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::helper1",)),
                Fact("Fun", ("mod::helper2",)),
                Fact("Fun", ("mod::init",)),
                Fact("IsInit", ("mod::init",)),
                Fact("InitImpl", ("mod::helper1",)),
                Fact("InitImpl", ("mod::helper2",)),
                Fact("InFun", ("mod::helper1", "mod::helper2@1")),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::helper1"}
        condition = Condition(subject="f", negation=False, property="double_init")

        result = check_double_init(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False

    def test_private_function_calling_init_returns_false(self):
        """Private function calling init should NOT be flagged (not an attack vector)."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::private_helper",)),
                Fact("Fun", ("mod::init",)),
                Fact("IsInit", ("mod::init",)),
                # No IsPublic or IsEntry for private_helper
                Fact("InFun", ("mod::private_helper", "mod::init@1")),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::private_helper"}
        condition = Condition(subject="f", negation=False, property="double_init")

        result = check_double_init(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False  # Private functions are not exploitable

    def test_transitive_call_to_init_returns_true(self):
        """Public function transitively calling init helper should be flagged."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::backdoor",)),
                Fact("Fun", ("mod::passthrough",)),
                Fact("Fun", ("mod::do_init",)),
                Fact("Fun", ("mod::init",)),
                Fact("IsInit", ("mod::init",)),
                Fact("IsEntry", ("mod::backdoor",)),
                Fact("InitImpl", ("mod::do_init",)),
                # backdoor -> passthrough -> do_init (but no direct call to init)
            ]
        })
        # Set up call graph with transitive callees
        ctx.call_graph = CallGraph(
            callees={
                "mod::backdoor": {"mod::passthrough"},
                "mod::passthrough": {"mod::do_init"},
            },
            callers={},
            transitive_callees={
                "mod::backdoor": {"mod::passthrough", "mod::do_init"},
                "mod::passthrough": {"mod::do_init"},
            },
        )

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::backdoor"}
        condition = Condition(subject="f", negation=False, property="double_init")

        result = check_double_init(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True  # Transitive chain detected

    def test_no_call_graph_returns_false(self):
        """If call graph is None, should return False (no transitive info)."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("Fun", ("mod::init",)),
                Fact("IsInit", ("mod::init",)),
                Fact("IsPublic", ("mod::foo",)),
            ]
        })
        # No call graph set - ctx.call_graph is None

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="double_init")

        result = check_double_init(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False  # No call graph means no transitive detection

    def test_entry_function_transitive_returns_true(self):
        """Entry function (not just public) transitively calling init should be flagged."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::entry_point",)),
                Fact("Fun", ("mod::helper",)),
                Fact("Fun", ("mod::do_init",)),
                Fact("IsInit", ("mod::init",)),
                Fact("IsEntry", ("mod::entry_point",)),  # Entry, not public
                Fact("InitImpl", ("mod::do_init",)),
            ]
        })
        ctx.call_graph = CallGraph(
            callees={"mod::entry_point": {"mod::helper"}, "mod::helper": {"mod::do_init"}},
            callers={},
            transitive_callees={"mod::entry_point": {"mod::helper", "mod::do_init"}},
        )

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::entry_point"}
        condition = Condition(subject="f", negation=False, property="double_init")

        result = check_double_init(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True  # Entry functions are also flagged


class TestSelfRecursive:
    """Tests for check_self_recursive."""

    def test_self_recursive_returns_true(self):
        """If function has SelfRecursive fact, should return True."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("SelfRecursive", ("mod::foo",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="self_recursive")

        result = check_self_recursive(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True

    def test_non_self_recursive_returns_false(self):
        """If function has no SelfRecursive fact, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="self_recursive")

        result = check_self_recursive(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False
