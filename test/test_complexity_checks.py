from typing import List

from core.context import ProjectContext
from core.facts import Fact
from rules.ir import Condition
from semantic.checker import SemanticChecker
from semantic.complexity_checks import (
    check_version_check_inconsistent,
    check_unused,
    check_duplicated_branch_condition,
    check_duplicated_branch_body,
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


class TestVersionCheckInconsistent:
    """Tests for check_version_check_inconsistent."""

    def test_no_versioning_returns_false(self):
        """If project has no versioning, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="version_check_inconsistent")

        result = check_version_check_inconsistent(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False

    def test_function_calls_version_check_returns_false(self):
        """If function already calls a version check, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("Fun", ("mod::verify_version",)),
                Fact("InFun", ("mod::foo", "mod::verify_version@1")),
            ]
        })
        ctx.project_facts = [
            Fact("FeatureVersion", (True,)),
            Fact("HasVersionCheck", ("mod::verify_version",)),
        ]

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="version_check_inconsistent")

        result = check_version_check_inconsistent(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False

    def test_inconsistent_version_check_returns_true(self):
        """If other functions in module call version check but this doesn't, should return True."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("Fun", ("mod::bar",)),
                Fact("Fun", ("mod::verify_version",)),
                Fact("InFun", ("mod::bar", "mod::verify_version@1")),
                Fact("SameModule", ("mod::foo", "mod::bar")),
            ]
        })
        ctx.project_facts = [
            Fact("FeatureVersion", (True,)),
            Fact("HasVersionCheck", ("mod::verify_version",)),
        ]

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="version_check_inconsistent")

        result = check_version_check_inconsistent(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True

    def test_transitive_version_check_call(self):
        """Should detect transitive calls to version check."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("Fun", ("mod::bar",)),
                Fact("Fun", ("mod::helper",)),
                Fact("Fun", ("mod::verify_version",)),
                Fact("InFun", ("mod::foo", "mod::helper@1")),
                Fact("InFun", ("mod::helper", "mod::verify_version@1")),
                Fact("InFun", ("mod::bar", "mod::verify_version@1")),
                Fact("SameModule", ("mod::foo", "mod::bar")),
            ]
        })
        ctx.project_facts = [
            Fact("FeatureVersion", (True,)),
            Fact("HasVersionCheck", ("mod::verify_version",)),
        ]

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="version_check_inconsistent")

        # mod::foo calls helper which calls verify_version, so it should NOT be inconsistent
        result = check_version_check_inconsistent(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False

    def test_version_check_method_detection(self):
        """Should detect common version check method patterns."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("Fun", ("mod::bar",)),
                Fact("InFun", ("mod::bar", "verify_version@1")),  # Simple name call
                Fact("SameModule", ("mod::foo", "mod::bar")),
            ]
        })
        ctx.project_facts = [
            Fact("FeatureVersion", (True,)),
        ]

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="version_check_inconsistent")

        result = check_version_check_inconsistent(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        # mod::bar calls a common version method, mod::foo doesn't
        assert result is True

    def test_no_same_module_functions(self):
        """If no SameModule facts exist, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
            ]
        })
        ctx.project_facts = [
            Fact("FeatureVersion", (True,)),
            Fact("HasVersionCheck", ("other::verify_version",)),
        ]

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="version_check_inconsistent")

        result = check_version_check_inconsistent(
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
        ctx.project_facts = [
            Fact("FeatureVersion", (True,)),
        ]

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=True, property="version_check_inconsistent")

        result = check_version_check_inconsistent(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        # No versioning pattern detected, negated should return True
        assert result is True


class TestUnused:
    """Tests for check_unused."""

    def test_unused_arg_returns_true(self):
        """If function has UnusedArg fact, should return True."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("UnusedArg", ("mod::foo", "unused_param", 0)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="arg", negation=False, property="unused")

        result = check_unused(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True

    def test_no_unused_arg_returns_false(self):
        """If function has no UnusedArg fact, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="arg", negation=False, property="unused")

        result = check_unused(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is False

    def test_multiple_unused_args_existential(self):
        """With multiple unused args, should return True (existential semantics)."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("UnusedArg", ("mod::foo", "param1", 0)),
                Fact("UnusedArg", ("mod::foo", "param2", 1)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="arg", negation=False, property="unused")

        result = check_unused(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True

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
        condition = Condition(subject="arg", negation=True, property="unused")

        result = check_unused(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        # No unused arg, negated should return True
        assert result is True


class TestDuplicatedBranchCondition:
    """Tests for check_duplicated_branch_condition."""

    def test_duplicated_condition_returns_true(self):
        """If function has DuplicatedBranchCondition fact, should return True."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("DuplicatedBranchCondition", ("mod::foo", "x == y")),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="duplicated_branch_condition")

        result = check_duplicated_branch_condition(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True

    def test_no_duplicated_condition_returns_false(self):
        """If function has no DuplicatedBranchCondition fact, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="duplicated_branch_condition")

        result = check_duplicated_branch_condition(
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
        condition = Condition(subject="f", negation=True, property="duplicated_branch_condition")

        result = check_duplicated_branch_condition(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        # No duplicated condition, negated should return True
        assert result is True


class TestDuplicatedBranchBody:
    """Tests for check_duplicated_branch_body."""

    def test_duplicated_body_returns_true(self):
        """If function has DuplicatedBranchBody fact, should return True."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
                Fact("DuplicatedBranchBody", ("mod::foo", "do_something()")),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="duplicated_branch_body")

        result = check_duplicated_branch_body(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        assert result is True

    def test_no_duplicated_body_returns_false(self):
        """If function has no DuplicatedBranchBody fact, should return False."""
        ctx = make_mock_ctx({
            "test.move": [
                Fact("Fun", ("mod::foo",)),
            ]
        })

        checker = SemanticChecker(ctx, "test.move")
        rule = MinimalRule()
        binding = {"f": "mod::foo"}
        condition = Condition(subject="f", negation=False, property="duplicated_branch_body")

        result = check_duplicated_branch_body(
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
        condition = Condition(subject="f", negation=True, property="duplicated_branch_body")

        result = check_duplicated_branch_body(
            checker, rule, binding, condition, ctx.source_files["test.move"].facts, "", None
        )

        # No duplicated body, negated should return True
        assert result is True
