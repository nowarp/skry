"""
Debug and development CLI commands: syntax dump, AST dump, parser check, fact schemas.
"""

import os
import json
from pathlib import Path
from collections import defaultdict
from typing import List, Dict, Set, Tuple, Optional

from move.parse import parse_move_source, find_error_nodes
from core.utils import error
from core.facts import Fact, get_all_fact_schemas, get_facts_by_scope
from core.context import ProjectContext
from core.cache import CACHE_DIR


def _find_struct_reasoning(struct_fqn: str) -> Optional[str]:
    """
    Find cached LLM reasoning for a struct from debug cache.

    Args:
        struct_fqn: Fully qualified struct name (e.g., "module::StructName")

    Returns:
        Reasoning string if found, None otherwise
    """
    debug_dir = Path(CACHE_DIR) / "llm_debug"
    if not debug_dir.exists():
        return None

    # Extract simple name for matching in struct definition
    simple_name = struct_fqn.split("::")[-1] if "::" in struct_fqn else struct_fqn

    for cache_file in debug_dir.glob("*.json"):
        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            prompt = data.get("prompt", "")

            # Must be a struct classification prompt with "## Struct Definition"
            # AND the struct must be the PRIMARY target (appears right after the header)
            if "## Struct Definition" not in prompt:
                continue

            # Check if this struct is the target of classification
            # Look for pattern: "## Struct Definition\n...struct SimpleStructName..."
            struct_def_idx = prompt.find("## Struct Definition")
            if struct_def_idx == -1:
                continue

            # Get the section after "## Struct Definition" (first 500 chars should contain struct name)
            section = prompt[struct_def_idx : struct_def_idx + 500]
            if f"struct {simple_name}" not in section:
                continue

            response = data.get("response", {})
            reason = response.get("reason")
            if reason:
                return reason
        except (json.JSONDecodeError, OSError):
            continue

    return None


def dump_ast_tree(source_code: str, root, max_depth: int = 10) -> None:
    """Print the tree-sitter AST structure for debugging."""

    def print_node(node, depth: int = 0):
        if depth > max_depth:
            return

        indent = "  " * depth
        text = source_code[node.start_byte : node.end_byte]

        if len(text) > 60:
            text = text[:60] + "..."
        text = text.replace("\n", "\\n")

        print(f"{indent}{node.type} [{node.start_byte}:{node.end_byte}] {repr(text)}")

        for child in node.children:
            print_node(child, depth + 1)

    print_node(root)


def check_parser_errors(input_file: str, source_code: str, root) -> bool:
    """Check for parser errors in AST. Returns True if errors found."""
    errors: list = []
    find_error_nodes(root, source_code, errors)
    if errors:
        error(f"PARSER ERRORS FOUND in {input_file}: {len(errors)} ERROR node(s)")
        error("=== ERROR NODES DETAIL ===")
        for err_node, err_depth, err_text in errors:
            indent = "  " * err_depth
            error(f"{indent}ERROR [{err_node.start_byte}:{err_node.end_byte}] {repr(err_text)}")
        error("=== End AST ===")
        return True
    return False


def check_parser_impl(source_files: List[str]) -> int:
    """Validate all files parse correctly (no ERROR nodes)."""
    print("Parser check mode: Validating parse trees...")
    has_errors = False
    for source_file in source_files:
        try:
            with open(source_file, "r", encoding="utf-8") as f:
                source_code = f.read()
        except Exception as e:
            error(f"Failed to read {source_file}: {e}")
            has_errors = True
            continue
        try:
            root = parse_move_source(source_code)
        except Exception as e:
            error(f"Failed to parse {source_file}: {e}")
            has_errors = True
            continue
        if check_parser_errors(source_file, source_code, root):
            has_errors = True
    if has_errors:
        error("Parser validation FAILED: ERROR nodes found in AST")
        return 1
    else:
        print("✓ Parser validation PASSED: No ERROR nodes found")
        return 0


def dump_ast_impl(source_files: List[str]) -> None:
    """Dump AST for all source files."""
    for source_file in source_files:
        with open(source_file, "r", encoding="utf-8") as f:
            source_code = f.read()
        try:
            root = parse_move_source(source_code)
        except Exception as e:
            error(f"parsing {source_file}: {e}")
            continue
        print(f"\n=== AST for {source_file} ===")
        dump_ast_tree(source_code, root)
        print("=== End AST ===\n")


def dump_fact_schemas() -> None:
    """Dump all registered fact schemas with descriptions."""
    print("=" * 70)
    print("SKRY FACT REGISTRY")
    print("=" * 70)

    from core.facts import Scope

    scopes: list[Scope] = ["struct", "function", "statement", "project"]
    for scope in scopes:
        facts = get_facts_by_scope(scope)
        if not facts:
            continue

        print(f"\n## {scope.upper()} SCOPE ({len(facts)} facts)")
        print("-" * 50)

        for schema in sorted(facts, key=lambda s: s.name):
            # Format args
            args_str = ", ".join(f"{name}: {t.__name__}" for name, t in schema.args)
            flags = []
            if schema.requires_llm:
                flags.append("LLM")
            flags_str = f" [{', '.join(flags)}]" if flags else ""

            print(f"  {schema.name}({args_str}){flags_str}")
            print(f"    {schema.description}")

    total = len(get_all_fact_schemas())
    print("\n" + "=" * 70)
    print(f"Total: {total} facts registered")
    print("=" * 70)


def _collect_source_ranges(root, source_code: str) -> Dict[str, Tuple[int, int, int, int, str]]:
    """
    Walk AST to collect source ranges for functions and structs.
    Returns: dict of name -> (start_byte, end_byte, line, col, comment)
    """
    from move.utils import _extract_text, _byte_to_line_col, _extract_preceding_comment

    ranges: Dict[str, Tuple[int, int, int, int, str]] = {}

    def walk(node):
        if node.type == "function_definition":
            for child in node.children:
                if child.type == "function_identifier":
                    name = _extract_text(source_code, child.start_byte, child.end_byte).strip()
                    line, col = _byte_to_line_col(source_code, node.start_byte)
                    comment = _extract_preceding_comment(node, source_code) or ""
                    ranges[name] = (node.start_byte, node.end_byte, line, col, comment)
                    break
        elif node.type == "struct_definition":
            for child in node.children:
                if child.type == "struct_identifier":
                    name = _extract_text(source_code, child.start_byte, child.end_byte).strip()
                    line, col = _byte_to_line_col(source_code, node.start_byte)
                    comment = _extract_preceding_comment(node, source_code) or ""
                    ranges[name] = (node.start_byte, node.end_byte, line, col, comment)
                    break
        for child in node.children:
            walk(child)

    walk(root)
    return ranges


def dump_facts_to_dir(ctx: ProjectContext, output_dir: str) -> None:
    """
    Dump all facts for each source file to markdown files.

    Creates one .facts.md file per source file with:
    - All facts grouped by entity (function/struct)
    - Source code for each entity
    - File:line:col location
    - Call graph connections
    """
    os.makedirs(output_dir, exist_ok=True)

    for file_path, file_ctx in ctx.source_files.items():
        if file_ctx.is_test_only:
            continue

        basename = os.path.basename(file_path)
        output_path = os.path.join(output_dir, f"{basename}.facts.md")
        source_code = file_ctx.source_code or ""

        # Collect source ranges for functions/structs from AST
        source_ranges: Dict[str, Tuple[int, int, int, int, str]] = {}
        if file_ctx.root and source_code:
            source_ranges = _collect_source_ranges(file_ctx.root, source_code)

        # Get location map for this file
        location_map = ctx.all_location_maps.get(file_path, {})

        # Collect function and struct names (qualified)
        func_names: Set[str] = set()
        struct_names: Set[str] = set()

        for fact in file_ctx.facts:
            if fact.name == "Fun":
                func_names.add(fact.args[0])
            elif fact.name == "Struct":
                struct_names.add(fact.args[0])

        # Group facts by entity
        func_facts: Dict[str, List[Fact]] = defaultdict(list)
        struct_facts: Dict[str, List[Fact]] = defaultdict(list)
        other_facts: List[Fact] = []

        for fact in file_ctx.facts:
            if not fact.args:
                other_facts.append(fact)
                continue

            entity = fact.args[0]
            if entity in func_names:
                func_facts[entity].append(fact)
            elif entity in struct_names:
                struct_facts[entity].append(fact)
            elif fact.name == "StructField" and len(fact.args) >= 1:
                struct_facts[entity].append(fact)
            else:
                other_facts.append(fact)

        # Helper to get simple name from qualified name
        def simple_name(qualified: str) -> str:
            return qualified.split("::")[-1] if "::" in qualified else qualified

        # Helper to get source code for entity
        def get_source(qualified: str) -> str:
            name = simple_name(qualified)
            if name in source_ranges:
                start, end, _, _, _ = source_ranges[name]
                return source_code[start:end]
            return ""

        # Helper to get comment for entity
        def get_comment(qualified: str) -> str:
            name = simple_name(qualified)
            if name in source_ranges:
                return source_ranges[name][4]
            return ""

        # Helper to get location string
        def get_location(qualified: str) -> str:
            if qualified in location_map:
                return str(location_map[qualified])
            # Fallback: try to get from source_ranges
            name = simple_name(qualified)
            if name in source_ranges:
                _, _, line, col, _ = source_ranges[name]
                return f"{file_path}:{line}:{col}"
            return file_path

        # Write output
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(f"# {basename}\n\n")

            # Structs section
            if struct_facts:
                f.write("## Structs\n\n")
                for struct_name in sorted(struct_facts.keys()):
                    loc = get_location(struct_name)
                    f.write(f"### {struct_name}\n")
                    f.write(f"`{loc}`\n\n")

                    # Source code
                    src = get_source(struct_name)
                    if src:
                        f.write("```move\n")
                        f.write(src)
                        f.write("\n```\n\n")

                    facts = struct_facts[struct_name]
                    if facts:
                        f.write("**Facts:**\n")
                        for fact in sorted(facts, key=lambda x: x.name):
                            f.write(f"- `{fact.name}{fact.args}`\n")
                        f.write("\n")

                    # LLM reasoning (if available in debug cache)
                    reasoning = _find_struct_reasoning(struct_name)
                    if reasoning:
                        f.write("**LLM Reasoning:**\n")
                        for line in reasoning.split("\n"):
                            f.write(f"> {line}\n")
                        f.write("\n")

                    f.write("---\n\n")

            # Functions section
            if func_facts:
                f.write("## Functions\n\n")
                for func_name in sorted(func_facts.keys()):
                    loc = get_location(func_name)
                    f.write(f"### {func_name}\n")
                    f.write(f"**Location:** `{loc}`\n\n")

                    # Comment
                    comment = get_comment(func_name)
                    if comment:
                        f.write(f"**Comment:** {comment}\n\n")

                    # Source code
                    src = get_source(func_name)
                    if src:
                        f.write("**Source:**\n```move\n")
                        f.write(src)
                        f.write("\n```\n\n")

                    facts = func_facts[func_name]
                    if facts:
                        # Separate Calls facts for readability
                        calls_facts = [fa for fa in facts if fa.name == "Calls"]
                        other = [fa for fa in facts if fa.name != "Calls"]

                        if other:
                            f.write("**Facts:**\n")
                            for fact in sorted(other, key=lambda x: x.name):
                                f.write(f"- `{fact.name}{fact.args}`\n")
                            f.write("\n")

                        if calls_facts:
                            f.write("**Calls:**\n")
                            for fact in calls_facts:
                                callee = fact.args[1] if len(fact.args) > 1 else "?"
                                f.write(f"- → `{callee}`\n")
                            f.write("\n")
                    f.write("---\n\n")

            # Other facts (project-level, etc.)
            if other_facts:
                f.write("## Other Facts\n\n")
                for fact in sorted(other_facts, key=lambda x: x.name):
                    f.write(f"- `{fact.name}{fact.args}`\n")
                f.write("\n")

    # Write project-level facts to __project.md
    project_output_path = os.path.join(output_dir, "__project.md")
    with open(project_output_path, "w", encoding="utf-8") as f:
        f.write("# Project Facts\n\n")

        if ctx.project_facts:
            # Group by fact name for readability
            facts_by_name: Dict[str, List[Fact]] = defaultdict(list)
            for fact in ctx.project_facts:
                facts_by_name[fact.name].append(fact)

            for fact_name in sorted(facts_by_name.keys()):
                f.write(f"## {fact_name}\n\n")
                for fact in sorted(facts_by_name[fact_name], key=lambda x: str(x.args)):
                    f.write(f"- `{fact.name}{fact.args}`\n")
                f.write("\n")
        else:
            f.write("*No project-level facts generated.*\n")

    print(f"Facts dumped to: {output_dir}/")
