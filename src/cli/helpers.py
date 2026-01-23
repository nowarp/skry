"""
CLI helper functions: environment validation, file collection, rule parsing.
"""

import os
import sys
from pathlib import Path
from typing import List

from rules.hy_loader import HyRule, load_hy_rules
from core.utils import debug, error, warn
from move.parse import TREE_SITTER_MOVE_DIR

# Type alias for rules (now only HyRule)
AnyRule = HyRule


def validate_environment(require_llm: bool = True) -> None:
    """
    Validate that the environment is properly configured.
    Exits with error if validation fails.
    """
    errors = []

    # Check LLM configuration (only if LLM is needed)
    if require_llm:
        llm_mode = os.getenv("SKRY_LLM_MODE", "api").lower()
        if llm_mode == "api":
            if not os.getenv("DEEPSEEK_API_KEY"):
                errors.append(
                    "DEEPSEEK_API_KEY not set. Either:\n"
                    "  1. Set environment variable: export DEEPSEEK_API_KEY=your_key\n"
                    "  2. Use manual mode or Claude Code: export SKRY_LLM_MODE=manual|claude-cli"
                )

    # Check tree-sitter grammar
    grammar_path = TREE_SITTER_MOVE_DIR / "grammar.js"
    if not grammar_path.exists():
        errors.append(
            f"tree-sitter-sui-move grammar not found at {TREE_SITTER_MOVE_DIR}. Initialize submodules:\n  git submodule update --init --recursive"
        )

    # Check if tree-sitter library is built
    so_path = TREE_SITTER_MOVE_DIR / "build" / "move.so"
    if grammar_path.exists() and not so_path.exists():
        warn("tree-sitter library not built yet. Will build on first run...")

    if errors:
        error("Environment validation failed:\n")
        for i, err in enumerate(errors, 1):
            error(f"\n{i}. {err}\n")
        sys.exit(1)


def _is_build_artifact_dir(dir_path: Path) -> bool:
    """Check if directory is a Move build artifact directory."""
    if "build" not in dir_path.parts:
        return False
    return (dir_path / "BuildInfo.yaml").exists()


def collect_source_files(input_path: str) -> List[str]:
    """Collect .move source files from a path (file or directory)."""
    path = Path(input_path)
    if not path.exists():
        return []
    if path.is_file():
        return [str(path)]
    if path.is_dir():
        source_files = []
        skip_dirs: set = set()

        for file_path in path.rglob("*.move"):
            should_skip = False
            for parent in file_path.parents:
                if parent in skip_dirs:
                    should_skip = True
                    break
                if parent not in skip_dirs and _is_build_artifact_dir(parent):
                    skip_dirs.add(parent)
                    should_skip = True
                    break

            if not should_skip:
                source_files.append(str(file_path))

        return sorted(source_files)
    return []


def collect_rule_files(rule_path: str) -> List[str]:
    """Collect .hy rule files from a path (file or directory)."""
    path = Path(rule_path)
    if not path.exists():
        return []
    if path.is_file():
        return [str(path)]
    if path.is_dir():
        rule_files = []
        for file_path in path.rglob("*.hy"):
            # Skip private files (starting with _)
            if not file_path.name.startswith("_"):
                rule_files.append(str(file_path))
        return sorted(rule_files)
    return []


def parse_hy_rules(rule_file: str) -> List[HyRule]:
    """Parse a single .hy rule file."""
    try:
        return load_hy_rules(rule_file)
    except FileNotFoundError:
        error(f"Rule file not found: {rule_file}")
        raise
    except Exception as e:
        error(f"Failed to parse Hy rule file '{rule_file}': {e}")
        raise


def parse_all_rules(rule_paths: List[str]) -> List[HyRule]:
    """Parse all .hy rule files and return list of rules."""
    all_rules: List[HyRule] = []
    rule_files: List[str] = []

    for rule_path in rule_paths:
        files = collect_rule_files(rule_path)
        if not files:
            error(f"No rule files found at: {rule_path}")
            continue
        rule_files.extend(files)

    if not rule_files:
        return []

    for rule_file in rule_files:
        try:
            rules = parse_hy_rules(rule_file)
            debug(f"Loaded {len(rules)} rule(s) from {rule_file}")
            all_rules.extend(rules)
        except Exception as e:
            error(f"Skipping {rule_file}: {e}")
            continue

    return all_rules
