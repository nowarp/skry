"""
Tests for semantic/taint_checks.py

Tests taint-related property checks:
- check_tainted_param
- check_tainted_recipient
- check_tainted_state_write
- check_tainted_amount
- check_tainted_transfer_value
- check_tainted_object_destroy
- check_tainted_loop_bound
"""

from typing import List

from core.context import ProjectContext
from core.facts import Fact
from rules.ir import Condition
from semantic.checker import SemanticChecker
from semantic.taint_checks import (
    check_tainted_param,
    check_tainted_recipient,
    check_tainted_state_write,
    check_tainted_amount,
    check_tainted_transfer_value,
    check_tainted_object_destroy,
    check_tainted_loop_bound,
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


class TestTaintedParam:
    """Tests for check_tainted_param."""

    def test_taint_reaches_sink_returns_true(self):
        """If function has TaintedAtSink fact, should return True."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("TaintedAtSink", ("mod::foo", "param", "stmt1", "transfer_recipient", "recipient")),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="tainted_param")

        result = check_tainted_param(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True

    def test_no_taint_reaches_sink_returns_false(self):
        """If function has no TaintReachesSink fact, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="tainted_param")

        result = check_tainted_param(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False


class TestTaintedRecipient:
    """Tests for check_tainted_recipient."""

    def test_tainted_recipient_returns_true(self):
        """If function has TaintedTransferRecipient fact, should return True."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("TaintedAtSink", ("mod::foo", "recipient_param", "stmt1", "transfer_recipient", "")),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="tainted_recipient")

        result = check_tainted_recipient(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True

    def test_no_tainted_recipient_returns_false(self):
        """If function has no TaintedTransferRecipient fact, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="tainted_recipient")

        result = check_tainted_recipient(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False

    def test_owned_object_guard_returns_false(self):
        """If function has owned object guard, should return False (not vulnerable)."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("TaintedAtSink", ("mod::foo", "recipient_param", "stmt1", "transfer_recipient", "")),
                Fact("OperatesOnOwnedOnly", ("mod::foo",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="tainted_recipient")

        result = check_tainted_recipient(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False

    def test_user_provided_coin_value_returns_false(self):
        """If transfer value comes from user's own Coin param, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("TaintedAtSink", ("mod::foo", "recipient_param", "stmt1", "transfer_recipient", "")),
                Fact("TaintedAtSink", ("mod::foo", "coin_param", "stmt1", "transfer_value", "")),
                Fact("FormalArg", ("mod::foo", 0, "coin_param", "Coin<SUI>")),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="tainted_recipient")

        result = check_tainted_recipient(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        # User is moving their own coin, not protocol funds
        assert result is False


class TestTaintedStateWrite:
    """Tests for check_tainted_state_write."""

    def test_tainted_state_write_returns_true(self):
        """If function has TaintedStateWrite fact, should return True."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("TaintedAtSink", ("mod::foo", "value_param", "stmt1", "state_write", "")),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="tainted_state_write")

        result = check_tainted_state_write(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True

    def test_no_tainted_state_write_returns_false(self):
        """If function has no TaintedStateWrite fact, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="tainted_state_write")

        result = check_tainted_state_write(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False


class TestTaintedAmount:
    """Tests for check_tainted_amount."""

    def test_tainted_amount_returns_true(self):
        """If function has TaintedAmountExtraction fact, should return True."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("TaintedAtSink", ("mod::foo", "amount_param", "stmt1", "amount_extraction", "")),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="tainted_amount")

        result = check_tainted_amount(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True

    def test_no_tainted_amount_returns_false(self):
        """If function has no TaintedAmountExtraction fact, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="tainted_amount")

        result = check_tainted_amount(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False


class TestTaintedTransferValue:
    """Tests for check_tainted_transfer_value."""

    def test_tainted_transfer_value_returns_true(self):
        """If function has TaintedTransferValue fact, should return True."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("TaintedAtSink", ("mod::foo", "value_param", "stmt1", "transfer_value", "")),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="tainted_transfer_value")

        result = check_tainted_transfer_value(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True

    def test_no_tainted_transfer_value_returns_false(self):
        """If function has no TaintedTransferValue fact, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="tainted_transfer_value")

        result = check_tainted_transfer_value(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False


class TestTaintedObjectDestroy:
    """Tests for check_tainted_object_destroy."""

    def test_tainted_object_destroy_returns_true(self):
        """If function has TaintedObjectDestroy fact, should return True."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("TaintedAtSink", ("mod::foo", "obj_param", "stmt1", "object_destroy", "")),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="tainted_object_destroy")

        result = check_tainted_object_destroy(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True

    def test_no_tainted_object_destroy_returns_false(self):
        """If function has no TaintedObjectDestroy fact, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="tainted_object_destroy")

        result = check_tainted_object_destroy(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False


class TestTaintedLoopBound:
    """Tests for check_tainted_loop_bound."""

    def test_tainted_loop_bound_returns_true(self):
        """If function has TaintedLoopBound fact without sanitization, should return True."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("TaintedAtSink", ("mod::foo", "count_param", "stmt1", "loop_bound", "")),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="tainted_loop_bound")

        result = check_tainted_loop_bound(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True

    def test_sanitized_loop_bound_returns_false(self):
        """If function has TaintedLoopBound but also SanitizedLoopBound, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("TaintedAtSink", ("mod::foo", "count_param", "stmt1", "loop_bound", "")),
                Fact("SanitizedAtSink", ("mod::foo", "count_param", "stmt1", "loop_bound", "")),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="tainted_loop_bound")

        result = check_tainted_loop_bound(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        # Sanitized, so not vulnerable
        assert result is False

    def test_no_tainted_loop_bound_returns_false(self):
        """If function has no TaintedLoopBound fact, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="tainted_loop_bound")

        result = check_tainted_loop_bound(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False
