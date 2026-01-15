"""
Marker parser for E2E fixture files.

Parses markers from .move files for self-documenting test fixtures.

Marker syntax:
    // @expect: rule-name
    public entry fun vulnerable_function(...) { ... }

    // @false-negative: rule-name (reason)
    public entry fun missed_vulnerable(...) { ... }

    // @false-positive: rule-name (reason)
    public entry fun incorrectly_flagged(...) { ... }

    // @inject: FactName(arg1, arg2)
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple, Optional


@dataclass
class ExpectedWarning:
    """Represents an @expect marker."""
    file_path: str
    line_number: int
    rule_name: str
    func_name: Optional[str] = None


@dataclass
class InjectedFact:
    """Represents an @inject marker."""
    fact_string: str


@dataclass
class FalseNegative:
    """Represents a @false-negative marker - known missed detection."""
    file_path: str
    line_number: int
    rule_name: str
    func_name: Optional[str] = None
    reason: Optional[str] = None


@dataclass
class FalsePositive:
    """Represents a @false-positive marker - known incorrect detection."""
    file_path: str
    line_number: int
    rule_name: str
    func_name: Optional[str] = None
    reason: Optional[str] = None


# Regex patterns
EXPECT_PATTERN = re.compile(r'^\s*//\s*@expect:\s*(\S+)\s*$')
INJECT_PATTERN = re.compile(r'^\s*//\s*@inject:\s*(.+?)\s*$')
# @false-negative: rule-name [optional reason in parens]
FALSE_NEGATIVE_PATTERN = re.compile(r'^\s*//\s*@false-negative:\s*(\S+)(?:\s*\((.+?)\))?\s*$')
# @false-positive: rule-name [optional reason in parens]
FALSE_POSITIVE_PATTERN = re.compile(r'^\s*//\s*@false-positive:\s*(\S+)(?:\s*\((.+?)\))?\s*$')
FUNCTION_PATTERN = re.compile(r'^\s*(?:public(?:\([^)]*\))?\s+)?(?:entry\s+)?fun\s+(\w+)\s*(?:<[^>]*>)?\s*\(')
STRUCT_PATTERN = re.compile(r'^\s*(?:public\s+)?struct\s+(\w+)\s*(?:<[^>]*>)?\s*(?:has\s+|{)')


def _extract_function_name(line: str) -> Optional[str]:
    """Extract function name from a Move function definition line."""
    match = FUNCTION_PATTERN.match(line)
    return match.group(1) if match else None


def _extract_struct_name(line: str) -> Optional[str]:
    """Extract struct name from a Move struct definition line."""
    match = STRUCT_PATTERN.match(line)
    return match.group(1) if match else None


def _find_next_definition(lines: List[str], start_idx: int) -> Optional[str]:
    """Find the next function or struct definition, skipping comments.

    Args:
        lines: List of lines (0-indexed)
        start_idx: Index to start searching from (0-indexed)

    Returns:
        Function or struct name, or None if not found
    """
    for i in range(start_idx, min(start_idx + 5, len(lines))):  # Look ahead up to 5 lines
        line = lines[i]
        # Skip comment lines and blank lines
        if line.strip().startswith('//') or not line.strip():
            continue
        # Try to extract function name
        entity_name = _extract_function_name(line)
        if entity_name:
            return entity_name
        # Try to extract struct name
        entity_name = _extract_struct_name(line)
        if entity_name:
            return entity_name
    return None


@dataclass
class ParsedMarkers:
    """Container for all parsed markers from a file."""
    expected: List[ExpectedWarning]
    injected: List[InjectedFact]
    false_negatives: List[FalseNegative]
    false_positives: List[FalsePositive]


def parse_markers(file_path: str) -> Tuple[List[ExpectedWarning], List[InjectedFact]]:
    """
    Parse @expect and @inject markers from a .move file.

    Args:
        file_path: Path to the .move file

    Returns:
        Tuple of (expected_warnings, injected_facts)
    """
    result = parse_all_markers(file_path)
    return result.expected, result.injected


def parse_all_markers(file_path: str) -> ParsedMarkers:
    """
    Parse all markers from a .move file.

    Supported markers:
        @expect: rule-name              - Expected violation
        @inject: FactName(args)         - Inject fact for testing
        @false-negative: rule-name      - Known missed detection (TODO)
        @false-positive: rule-name      - Known incorrect detection (TODO)

    Optional reason in parentheses: @false-negative: rule-name (reason here)

    Args:
        file_path: Path to the .move file

    Returns:
        ParsedMarkers with all marker types
    """
    expected_warnings = []
    injected_facts = []
    false_negatives = []
    false_positives = []

    if not Path(file_path).exists():
        return ParsedMarkers(expected_warnings, injected_facts, false_negatives, false_positives)

    with open(file_path, 'r') as f:
        lines = f.readlines()

    for i, line in enumerate(lines, start=1):
        # Check for @expect marker
        expect_match = EXPECT_PATTERN.match(line)
        if expect_match:
            rule_name = expect_match.group(1)
            entity_name = _find_next_definition(lines, i)
            expected_warnings.append(ExpectedWarning(
                file_path=file_path,
                line_number=i,
                rule_name=rule_name,
                func_name=entity_name
            ))
            continue

        # Check for @inject marker
        inject_match = INJECT_PATTERN.match(line)
        if inject_match:
            fact_string = inject_match.group(1).strip()
            injected_facts.append(InjectedFact(fact_string=fact_string))
            continue

        # Check for @false-negative marker
        fn_match = FALSE_NEGATIVE_PATTERN.match(line)
        if fn_match:
            rule_name = fn_match.group(1)
            reason = fn_match.group(2)
            entity_name = _find_next_definition(lines, i)
            false_negatives.append(FalseNegative(
                file_path=file_path,
                line_number=i,
                rule_name=rule_name,
                func_name=entity_name,
                reason=reason
            ))
            continue

        # Check for @false-positive marker
        fp_match = FALSE_POSITIVE_PATTERN.match(line)
        if fp_match:
            rule_name = fp_match.group(1)
            reason = fp_match.group(2)
            entity_name = _find_next_definition(lines, i)
            false_positives.append(FalsePositive(
                file_path=file_path,
                line_number=i,
                rule_name=rule_name,
                func_name=entity_name,
                reason=reason
            ))
            continue

    return ParsedMarkers(expected_warnings, injected_facts, false_negatives, false_positives)
