"""
Main entry point and pass orchestration.
"""

import sys
import os
import argparse
from typing import List, Tuple, Optional, Union

# Load environment variables from .env file (if exists)
try:
    from dotenv import load_dotenv  # ty: ignore[unresolved-import]

    load_dotenv()
except ImportError:
    pass

from rules.ir import Rule, Binding, Severity
from rules.hy_loader import HyRule
from core.utils import debug, error, info
from core.context import ProjectContext
from reporter import OutputMode, report_violations
from cli.helpers import (
    validate_environment,
    collect_source_files,
    parse_all_rules,
)
from cli.debug import dump_ast_impl, check_parser_impl, dump_fact_schemas, dump_facts_to_dir
from analysis.cap_graph import dump_cap_graph_to_dir


AnyRule = Union[Rule, HyRule]


def main(
    input_path: str,
    rule_paths: List[str],
    dump_ast: bool = False,
    check_parser: bool = False,
    output_mode: OutputMode = OutputMode.SHORT,
    output_dir: Optional[str] = None,
    min_severity: Optional[Severity] = None,
    selected_rules: Optional[List[str]] = None,
    single_category: Optional[str] = None,
    suppress_rules: Optional[List[str]] = None,
    dump_facts_dir: Optional[str] = None,
    skip_tests: bool = False,
    dump_cap_graph_dir: Optional[str] = None,
) -> int:
    """Main entry point for analysis."""
    # Step 0: Validate environment (minimal - just tree-sitter)
    validate_environment(require_llm=False)

    # Step 1: Collect source files
    source_files = collect_source_files(input_path)
    if not source_files:
        error(f"No source files found at: {input_path}")
        return 1

    if check_parser:
        return check_parser_impl(source_files)

    # Step 2: Parse rules
    rules = parse_all_rules(rule_paths)
    if not rules:
        error("No rules loaded. Check your rule paths.")
        return 1

    # Filter to selected rules if specified
    if selected_rules:
        rule_set = set(selected_rules)
        matching = [r for r in rules if r.name in rule_set]
        not_found = rule_set - {r.name for r in matching}
        if not_found:
            error(f"Rule(s) not found: {', '.join(sorted(not_found))}. Use --list-rules to see available rules.")
            return 1
        rules = matching
        print(f"Running {len(rules)} selected rule(s): {', '.join(selected_rules)}")

    # Filter to single category if specified
    if single_category:
        matching = [r for r in rules if single_category in (r.categories or [])]
        if not matching:
            error(f"No rules with category '{single_category}'. Use --list-categories to see available categories.")
            return 1
        rules = matching
        print(f"Running {len(rules)} rule(s) with category: {single_category}")

    # Suppress specified rules
    if suppress_rules:
        suppress_set = set(suppress_rules)
        original_count = len(rules)
        rules = [r for r in rules if r.name not in suppress_set]
        skipped_count = original_count - len(rules)
        if skipped_count > 0:
            debug(f"--suppress-rule: Skipping {skipped_count} rule(s): {', '.join(suppress_rules)}")

    if min_severity:
        original_count = len(rules)
        rules = [r for r in rules if r.severity >= min_severity]
        skipped_count = original_count - len(rules)
        if skipped_count > 0:
            debug(f"--min-severity {min_severity.value}: Skipping {skipped_count} rule(s) below threshold")
        if not rules:
            error(f"No rules left after filtering by severity >= {min_severity.value}")
            return 1

    if len(rules) > 1:
        info(f"Enabled {len(rules)} rules")

    if dump_ast:
        dump_ast_impl(source_files)

    # Initialize context
    ctx = ProjectContext(source_files)

    # ========================================================================
    # PASS 1: Structural analysis (CST → facts)
    # ========================================================================
    from analysis import run_structural_analysis

    debug("Pass 1: Structural analysis...")
    run_structural_analysis(ctx, skip_tests=skip_tests)

    # ========================================================================
    # PASS 2: Semantic fact generation (LLM classification)
    # ========================================================================
    from semantic_facts_builder import SemanticFactsBuilder
    from rules.utils import collect_required_features

    validate_environment(require_llm=True)
    required_features = collect_required_features(rules)
    debug(f"Pass 2: Semantic facts (required features: {required_features or 'none'})...")
    SemanticFactsBuilder(required_features).build(ctx, rules)

    # ========================================================================
    # PASS 3: Fact propagation (taint analysis, derived facts, cross-file joins)
    # ========================================================================
    from analysis import run_fact_propagation

    debug("Pass 3: Fact propagation...")
    run_fact_propagation(ctx)

    # ========================================================================
    # PASS 4: Filter evaluation to reduce LLM calls (structural checks → candidates)
    # ========================================================================
    from pipeline import run_filter_pass, run_llm_facts_pass

    debug("Pass 4: Filter evaluation...")
    filter_result = run_filter_pass(ctx, rules)

    # ========================================================================
    # PASS 5: LLM semantic facts (generates LLM facts for candidates)
    # ========================================================================
    if filter_result.candidates:
        debug("Pass 5: LLM semantic facts...")
        classify_violations = run_llm_facts_pass(ctx, filter_result)
    else:
        debug("Pass 5: Skipped (no candidates)")
        classify_violations = []

    # Combine all violations
    all_violations: List[Tuple[AnyRule, Binding]] = []
    all_violations.extend(filter_result.violations)
    all_violations.extend(classify_violations)

    # Dump facts to directory if requested
    if dump_facts_dir:
        dump_facts_to_dir(ctx, dump_facts_dir)

    # Dump capability graph if requested
    if dump_cap_graph_dir:
        dump_cap_graph_to_dir(ctx, dump_cap_graph_dir)

    # Report violations
    has_rule_clauses = any(
        (isinstance(r, HyRule) and r.filter_clause is not None) or (isinstance(r, Rule) and r.where_clause is not None)
        for r in rules
    )

    output_file = None
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        project_name = os.path.basename(os.path.normpath(input_path))
        ext = ".json" if output_mode == OutputMode.JSON else ".txt"
        output_path = os.path.join(output_dir, f"OUT-{project_name}{ext}")
        output_file = open(output_path, "w", encoding="utf-8")
        print(f"Writing results to: {output_path}")

    try:
        if has_rule_clauses:
            num_violations = report_violations(all_violations, ctx, output_mode, output_file)
        else:
            num_violations = 0
    finally:
        if output_file:
            output_file.close()

    return 1 if num_violations > 0 else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Static analysis tool for Move code")
    parser.add_argument("input_path", nargs="?", help="Input Move source file or directory")
    parser.add_argument("rule_file", nargs="?", help="Rule file (positional, optional if -r/--rules is used)")
    parser.add_argument(
        "-r",
        "--rules",
        action="append",
        metavar="PATH",
        help="Rule file or directory (can be specified multiple times)",
    )
    parser.add_argument("-da", "--dump-ast", action="store_true", help="Dump tree-sitter AST")
    parser.add_argument("--list-rules", action="store_true", help="List all rules with descriptions")
    parser.add_argument("--list-facts", action="store_true", help="Dump all registered facts")
    parser.add_argument("--list-categories", action="store_true", help="List all rule categories")
    parser.add_argument(
        "--rule",
        action="append",
        metavar="NAME",
        help="Run only the specified rule(s) (can be specified multiple times)",
    )
    parser.add_argument("--category", metavar="NAME", help="Run only rules with the specified category")
    parser.add_argument(
        "--suppress-rule",
        action="append",
        metavar="NAME",
        help="Suppress (skip) the specified rule (can be specified multiple times)",
    )
    parser.add_argument(
        "-cp", "--check-parser", action="store_true", help="Check parser: validate all files parse correctly"
    )
    parser.add_argument(
        "--min-severity",
        choices=["info", "low", "medium", "high", "critical"],
        default=None,
        help="Minimum severity to report (info/low/medium/high/critical)",
    )
    parser.add_argument(
        "-o", "--output", choices=["short", "full", "context", "json"], default="short", help="Output verbosity"
    )
    parser.add_argument("-O", "--output-dir", metavar="DIR", help="Save results to files in DIR")
    parser.add_argument("--dump-facts", metavar="DIR", help="Dump all facts to markdown files in DIR (debug)")
    parser.add_argument(
        "-dcg", "--dump-cap-graph", metavar="DIR", help="Dump capability graph to DIR (one markdown file per module)"
    )
    parser.add_argument(
        "--skip-tests",
        action="store_true",
        help="Skip test/example directories (test/, tests/, example/, examples/, mock/, mocks/)",
    )
    args = parser.parse_args()

    if args.list_facts:
        dump_fact_schemas()
        sys.exit(0)

    if args.list_categories:
        rule_paths: List[str] = []
        if args.rule_file:
            rule_paths.append(args.rule_file)
        if args.rules:
            rule_paths.extend(args.rules)
        if not rule_paths:
            rule_paths = ["./rules"]
        rules = parse_all_rules(rule_paths)
        categories: set[str] = set()
        for rule in rules:
            if rule.categories:
                categories.update(rule.categories)
        print(f"Available categories ({len(categories)}):\n")
        for cat in sorted(categories):
            count = sum(1 for r in rules if cat in (r.categories or []))
            print(f"  {cat} ({count} rules)")
        sys.exit(0)

    if args.list_rules:
        rule_paths: List[str] = []
        if args.rule_file:
            rule_paths.append(args.rule_file)
        if args.rules:
            rule_paths.extend(args.rules)
        if not rule_paths:
            rule_paths = ["./rules"]
        rules = parse_all_rules(rule_paths)
        if not rules:
            print("No rules found.")
            sys.exit(1)
        print(f"Available rules ({len(rules)}):\n")
        for rule in sorted(rules, key=lambda r: r.name):
            llm_tag = " [LLM]" if getattr(rule, "requires_llm", False) else ""
            sev = rule.severity.value.upper()
            desc = rule.description or "(no description)"
            print(f"  {rule.name}{llm_tag} [{sev}]")
            print(f"    {desc}\n")
        sys.exit(0)

    if not args.input_path:
        parser.error("input_path is required (or use --dump-syntax/--list-facts/--list-rules)")

    rule_paths: List[str] = []
    if args.rule_file:
        rule_paths.append(args.rule_file)
    if args.rules:
        rule_paths.extend(args.rules)
    if not rule_paths and not args.check_parser:
        rule_paths = ["./rules"]

    output_mode = OutputMode(args.output)
    min_severity = Severity.from_string(args.min_severity) if args.min_severity else None

    sys.exit(
        main(
            args.input_path,
            rule_paths,
            dump_ast=args.dump_ast,
            check_parser=args.check_parser,
            output_mode=output_mode,
            output_dir=args.output_dir,
            min_severity=min_severity,
            selected_rules=args.rule,
            single_category=args.category,
            suppress_rules=args.suppress_rule,
            skip_tests=args.skip_tests,
            dump_facts_dir=args.dump_facts,
            dump_cap_graph_dir=args.dump_cap_graph,
        )
    )
