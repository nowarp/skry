"""Tests for reporter module."""
import os
# Disable colors before importing reporter (evaluated at import time)
os.environ["SKRY_NO_COLORS"] = "1"

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from reporter import OutputMode, report_violations
from rules.ir import Rule, Match, Severity, FunPattern
from core.facts import Fact


# Type alias for Clause list (body of match)
Clause = Any


@dataclass
class MockSourceFileContext:
    """Mock for SourceFileContext."""
    path: str
    source_code: Optional[str] = None
    root: Optional[Any] = None
    facts: List[Fact] = field(default_factory=list)


@dataclass
class MockLocation:
    """Mock for SourceLocation."""
    line: int
    column: int

    def __str__(self):
        return f"{self.line}:{self.column}"


class MockProjectContext:
    """Mock for ProjectContext."""
    def __init__(self):
        self.source_files: Dict[str, MockSourceFileContext] = {}
        self.all_location_maps: Dict[str, Dict[str, MockLocation]] = {}


def make_rule(
    name: str = "test_rule",
    severity: Severity = Severity.MEDIUM,
    description: Optional[str] = None,
    example_bad: Optional[str] = None,
    example_fixed: Optional[str] = None,
) -> Rule:
    """Create a mock Rule for testing."""
    return Rule(
        name=name,
        match_clause=Match(
            pattern=FunPattern(modifiers=["public"], binding="f"),
            body=[]
        ),
        where_clause=None,
        severity=severity,
        categories=[],
        description=description,
        example_bad=example_bad,
        example_fixed=example_fixed,
    )


class TestOutputMode:
    """Test OutputMode enum."""

    def test_short_mode_value(self):
        assert OutputMode.SHORT.value == "short"

    def test_full_mode_value(self):
        assert OutputMode.FULL.value == "full"

    def test_context_mode_value(self):
        assert OutputMode.CONTEXT.value == "context"

    def test_create_from_string(self):
        assert OutputMode("short") == OutputMode.SHORT
        assert OutputMode("full") == OutputMode.FULL
        assert OutputMode("context") == OutputMode.CONTEXT


class TestReportViolationsNoViolations:
    """Test report_violations with no violations."""

    def test_no_violations_returns_zero(self, capsys):
        ctx = MockProjectContext()
        result = report_violations([], ctx, OutputMode.SHORT)
        assert result == 0
        captured = capsys.readouterr()
        assert "No violations found" in captured.out


class TestReportViolationsShortMode:
    """Test report_violations in SHORT mode."""

    def test_short_mode_shows_rule_and_location(self, capsys):
        ctx = MockProjectContext()
        ctx.all_location_maps = {
            "/test/file.move": {"test_module::vulnerable_func": MockLocation(10, 5)}
        }

        rule = make_rule(name="dangerous_pattern")
        binding = {"f": "test_module::vulnerable_func"}
        violations = [(rule, binding)]

        result = report_violations(violations, ctx, OutputMode.SHORT)

        assert result == 1
        captured = capsys.readouterr()
        assert "[dangerous_pattern]" in captured.out
        assert "[10:5]" in captured.out
        assert "vulnerable_func" in captured.out

    def test_short_mode_no_severity_or_description(self, capsys):
        ctx = MockProjectContext()
        ctx.all_location_maps = {
            "/test/file.move": {"mod::func": MockLocation(1, 1)}
        }

        rule = make_rule(
            name="test_rule",
            severity=Severity.HIGH,
            description="This is dangerous"
        )
        binding = {"f": "mod::func"}
        violations = [(rule, binding)]

        report_violations(violations, ctx, OutputMode.SHORT)

        captured = capsys.readouterr()
        # Should NOT contain severity or description in SHORT mode
        assert "Severity:" not in captured.out
        assert "Description:" not in captured.out


class TestReportViolationsFullMode:
    """Test report_violations in FULL mode."""

    def test_full_mode_includes_severity(self, capsys):
        ctx = MockProjectContext()
        ctx.all_location_maps = {
            "/test/file.move": {"mod::func": MockLocation(1, 1)}
        }

        rule = make_rule(severity=Severity.HIGH)
        binding = {"f": "mod::func"}
        violations = [(rule, binding)]

        report_violations(violations, ctx, OutputMode.FULL)

        captured = capsys.readouterr()
        # Severity is shown in header tag: [HIGH][rule_name]
        assert "[HIGH]" in captured.out

    def test_full_mode_includes_description(self, capsys):
        ctx = MockProjectContext()
        ctx.all_location_maps = {
            "/test/file.move": {"mod::func": MockLocation(1, 1)}
        }

        rule = make_rule(description="Vulnerable to reentrancy attack")
        binding = {"f": "mod::func"}
        violations = [(rule, binding)]

        report_violations(violations, ctx, OutputMode.FULL)

        captured = capsys.readouterr()
        assert "Description: Vulnerable to reentrancy attack" in captured.out

    def test_full_mode_no_examples(self, capsys):
        ctx = MockProjectContext()
        ctx.all_location_maps = {
            "/test/file.move": {"mod::func": MockLocation(1, 1)}
        }

        rule = make_rule(
            example_bad="bad code here",
            example_fixed="fixed code here"
        )
        binding = {"f": "mod::func"}
        violations = [(rule, binding)]

        report_violations(violations, ctx, OutputMode.FULL)

        captured = capsys.readouterr()
        # Should NOT contain examples in FULL mode
        assert "Example (vulnerable):" not in captured.out
        assert "Example (fixed):" not in captured.out


class TestReportViolationsContextMode:
    """Test report_violations in CONTEXT mode."""

    def test_context_mode_includes_examples(self, capsys):
        ctx = MockProjectContext()
        ctx.all_location_maps = {
            "/test/file.move": {"mod::func": MockLocation(1, 1)}
        }

        rule = make_rule(
            severity=Severity.CRITICAL,
            description="Critical vulnerability",
            example_bad="let x = user_input;",
            example_fixed="let x = sanitize(user_input);"
        )
        binding = {"f": "mod::func"}
        violations = [(rule, binding)]

        report_violations(violations, ctx, OutputMode.CONTEXT)

        captured = capsys.readouterr()
        # Severity is shown in header tag: [CRITICAL][rule_name]
        assert "[CRITICAL]" in captured.out
        # Description is shown with label
        assert "Description:" in captured.out
        assert "Critical vulnerability" in captured.out
        # Plus examples
        assert "Example (vulnerable):" in captured.out
        assert "let x = user_input;" in captured.out
        assert "Example (fixed):" in captured.out
        assert "let x = sanitize(user_input);" in captured.out



class TestReportViolationsMultipleBindings:
    """Test violations with multiple bindings."""

    def test_shows_relevant_bindings(self, capsys):
        ctx = MockProjectContext()
        ctx.all_location_maps = {
            "/test/file.move": {
                "mod::func": MockLocation(10, 1),
                "tainted_var": MockLocation(12, 5)
            }
        }

        rule = make_rule()
        binding = {
            "f": "mod::func",
            "x": "tainted_var",
            "x_type": "u64"  # Should be filtered out
        }
        violations = [(rule, binding)]

        report_violations(violations, ctx, OutputMode.SHORT)

        captured = capsys.readouterr()
        assert "x: tainted_var" in captured.out
        assert "(12:5)" in captured.out
        # Type bindings should be excluded
        assert "x_type" not in captured.out


class TestReportViolationsMultipleViolations:
    """Test reporting multiple violations."""

    def test_multiple_violations_count(self, capsys):
        ctx = MockProjectContext()
        ctx.all_location_maps = {
            "/test/file.move": {
                "mod::func1": MockLocation(10, 1),
                "mod::func2": MockLocation(20, 1),
                "mod::func3": MockLocation(30, 1),
            }
        }

        violations = [
            (make_rule(name="rule1"), {"f": "mod::func1"}),
            (make_rule(name="rule2"), {"f": "mod::func2"}),
            (make_rule(name="rule3"), {"f": "mod::func3"}),
        ]

        result = report_violations(violations, ctx, OutputMode.SHORT)

        assert result == 3
        captured = capsys.readouterr()
        assert "Found 3 violation(s)" in captured.out
        assert "[rule1]" in captured.out
        assert "[rule2]" in captured.out
        assert "[rule3]" in captured.out


class TestReportViolationsUnknownLocation:
    """Test handling of unknown locations."""

    def test_unknown_function_location(self, capsys):
        ctx = MockProjectContext()
        ctx.all_location_maps = {}  # No locations known

        rule = make_rule()
        binding = {"f": "unknown::func"}
        violations = [(rule, binding)]

        report_violations(violations, ctx, OutputMode.SHORT)

        captured = capsys.readouterr()
        # Should still report but with empty location
        assert "[test_rule][]" in captured.out
        assert "unknown::func" in captured.out
