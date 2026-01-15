"""
Tests for semantic/sanitized_checks.py

Tests sanitization-related property checks:
- check_sanitized_recipient
- check_sanitized_state_write
- check_sanitized_amount
- check_sanitized_transfer_value
- check_sanitized_object_destroy
"""

from typing import List

from core.context import ProjectContext
from core.facts import Fact
from rules.ir import Condition
from semantic.checker import SemanticChecker
from semantic.sanitized_checks import (
    check_sanitized_recipient,
    check_sanitized_state_write,
    check_sanitized_amount,
    check_sanitized_transfer_value,
    check_sanitized_object_destroy,
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


class TestSanitizedRecipient:
    """Tests for check_sanitized_recipient."""

    def test_sanitized_returns_true(self):
        """If function has SanitizedTransferRecipient fact, should return True."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("SanitizedAtSink", ("mod::foo", "param", "stmt1", "transfer_recipient", "")),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="sanitized_recipient")

        result = check_sanitized_recipient(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True

    def test_not_sanitized_returns_false(self):
        """If function has no SanitizedTransferRecipient fact, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="sanitized_recipient")

        result = check_sanitized_recipient(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False

    def test_negation_handling(self):
        """Should properly handle negation flag."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=True, property="sanitized_recipient")

        result = check_sanitized_recipient(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        # No sanitization, negated should return True
        assert result is True


class TestSanitizedStateWrite:
    """Tests for check_sanitized_state_write."""

    def test_sanitized_returns_true(self):
        """If function has SanitizedStateWrite fact, should return True."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("SanitizedAtSink", ("mod::foo", "value", "stmt1", "state_write", "")),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="sanitized_state_write")

        result = check_sanitized_state_write(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True

    def test_not_sanitized_returns_false(self):
        """If function has no SanitizedStateWrite fact, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="sanitized_state_write")

        result = check_sanitized_state_write(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False


class TestSanitizedAmount:
    """Tests for check_sanitized_amount."""

    def test_sanitized_returns_true(self):
        """If function has SanitizedAmountExtraction fact, should return True."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("SanitizedAtSink", ("mod::foo", "amount", "stmt1", "amount_extraction", "")),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="sanitized_amount")

        result = check_sanitized_amount(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True

    def test_not_sanitized_returns_false(self):
        """If function has no SanitizedAmountExtraction fact, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="sanitized_amount")

        result = check_sanitized_amount(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False


class TestSanitizedTransferValue:
    """Tests for check_sanitized_transfer_value."""

    def test_sanitized_returns_true(self):
        """If function has SanitizedTransferValue fact, should return True."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("SanitizedAtSink", ("mod::foo", "coin", "stmt1", "transfer_value", "")),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="sanitized_transfer_value")

        result = check_sanitized_transfer_value(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True

    def test_not_sanitized_returns_false(self):
        """If function has no SanitizedTransferValue fact, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="sanitized_transfer_value")

        result = check_sanitized_transfer_value(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False


class TestSanitizedObjectDestroy:
    """Tests for check_sanitized_object_destroy."""

    def test_sanitized_returns_true(self):
        """If function has SanitizedObjectDestroy fact, should return True."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("SanitizedAtSink", ("mod::foo", "obj", "stmt1", "object_destroy", "")),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="sanitized_object_destroy")

        result = check_sanitized_object_destroy(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True

    def test_not_sanitized_returns_false(self):
        """If function has no SanitizedObjectDestroy fact, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="sanitized_object_destroy")

        result = check_sanitized_object_destroy(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False
