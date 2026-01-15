"""
Main structural fact builder - orchestrates all structural analysis passes.
"""

from typing import Dict, List, Tuple
import hashlib

from core.context import ProjectContext, SourceFileContext
from move.parse import build_code_facts, parse_move_source
from move.utils import SourceLocation
from core.facts import Fact, FACT_REGISTRY
from core.utils import debug, info, warn, error

from analysis.transfers import (
    generate_transfers_facts,
    detect_zero_address_transfers,
)
from analysis.access_control import (
    generate_calls_sender_facts,
    generate_checks_role_facts,
    generate_is_capability_facts,
    generate_transfer_and_share_facts,
    generate_capability_hierarchy_facts,
)
from analysis.orphans import (
    detect_orphan_roles,
    detect_orphan_events,
)
from analysis.patterns import (
    detect_self_recursive_calls,
    generate_same_module_facts,
    build_shared_object_facts,
    generate_creates_capability_facts,
    propagate_creates_capability_facts,
)
from analysis.call_graph import build_call_facts, build_call_graph_ir


# Path patterns that indicate test/example directories
TEST_PATH_PATTERNS = ("test/", "tests/", "example/", "examples/", "mock/", "mocks/")


def _is_test_path(path: str) -> bool:
    """Check if path contains test/example directory patterns."""
    path_lower = path.lower()
    return any(pattern in path_lower for pattern in TEST_PATH_PATTERNS)


class StructuralBuilder:
    def __init__(self, skip_tests: bool = False):
        self.skip_tests = skip_tests

    def build(self, ctx: ProjectContext):
        """
        Collect structural facts from the CST in the given ProjectContext.
        """
        self._parse_files(ctx)
        self._resolve_reexports(ctx)  # Fix import_maps before fact generation
        for file_ctx in ctx.source_files.values():
            if file_ctx.is_test_only:
                continue
            filename = file_ctx.path
            debug(f"[StructuralBuilder.build]: {filename}")
            file_facts, file_func_index, file_location_map = self.collect_structural_facts(file_ctx)
            ctx.source_files[filename].facts = file_facts
            ctx.all_location_maps[filename] = file_location_map
            for func_name, func_facts in file_func_index.items():
                if func_name not in ctx.global_facts_index:
                    ctx.global_facts_index[func_name] = {}
                if filename in ctx.global_facts_index[func_name]:
                    warn(f"Function {func_name} appears twice in {filename}")
                    ctx.global_facts_index[func_name][filename].extend(func_facts)
                else:
                    ctx.global_facts_index[func_name][filename] = func_facts

        num_functions = len(ctx.global_facts_index)
        duplicates = [(name, len(files)) for name, files in ctx.global_facts_index.items() if len(files) > 1]

        debug(f"[StructuralBuilder.build]: indexed {num_functions} functions")
        if duplicates:
            debug(f"  (!) {len(duplicates)} functions defined in multiple files")
            for func_name, num_files in duplicates[:5]:
                debug(f"      {func_name}: {num_files} files")

        build_call_facts(ctx)  # Must run early - other passes use Calls facts
        build_call_graph_ir(ctx)  # Pre-compute transitive callees for query-time checks
        generate_transfer_and_share_facts(ctx)  # Must run before generate_is_role_facts (uses PacksStruct facts)
        generate_is_capability_facts(
            ctx
        )  # Must run before generate_checks_role_facts and generate_creates_capability_facts
        generate_creates_capability_facts(ctx)  # Must run after generate_is_role_facts
        propagate_creates_capability_facts(
            ctx
        )  # Must run after generate_creates_capability_facts and build_call_graph_ir
        generate_checks_role_facts(ctx)
        generate_capability_hierarchy_facts(
            ctx
        )  # Must run after generate_checks_role_facts and generate_creates_capability_facts
        generate_transfers_facts(ctx)
        generate_calls_sender_facts(ctx)
        detect_zero_address_transfers(ctx)
        # Note: detect_orphan_txcontext_functions runs after taint analysis (needs CallArg facts)
        detect_orphan_roles(ctx)
        detect_orphan_events(ctx)
        detect_self_recursive_calls(ctx)
        generate_same_module_facts(ctx)
        build_shared_object_facts(ctx)

    def _parse_files(self, ctx: ProjectContext) -> None:
        from move.collectors import is_test_only_module
        from move.imports import _parse_imports, _parse_module_declaration

        test_only_count = 0
        path_skip_count = 0
        for file_ctx in ctx.source_files.values():
            with open(file_ctx.path, "r", encoding="utf-8") as f:
                file_ctx.source_code = f.read()
                file_ctx.source_code_hash = hashlib.sha256(file_ctx.source_code.encode()).hexdigest()
            file_ctx.root = parse_move_source(file_ctx.source_code)

            # Parse import map and module path for type resolution
            file_ctx.import_map = _parse_imports(file_ctx.source_code, file_ctx.root)
            file_ctx.module_path = _parse_module_declaration(file_ctx.source_code, file_ctx.root)

            # Check if file should be skipped:
            # 1. Module has #[test_only] annotation
            # 2. Path matches test/example patterns (if --skip-tests enabled)
            if is_test_only_module(file_ctx.source_code, file_ctx.root):
                file_ctx.is_test_only = True
                test_only_count += 1
                debug(f"  Skipping test_only module: {file_ctx.path}")
            elif self.skip_tests and _is_test_path(file_ctx.path):
                file_ctx.is_test_only = True
                path_skip_count += 1
                debug(f"  Skipping test/example path: {file_ctx.path}")
            else:
                file_ctx.is_test_only = False

        if test_only_count > 0:
            info(f"Skipping {test_only_count} test_only module(s)")
        if path_skip_count > 0:
            info(f"Skipping {path_skip_count} test/example path(s)")

        processed_count = len(ctx.source_files) - test_only_count - path_skip_count
        info(f"Processing {processed_count} source file(s)...")

    def _resolve_reexports(self, ctx: ProjectContext) -> None:
        """
        Fix import_maps to resolve re-exports to canonical FQNs.

        When module A imports a type from B via `use B::Type`, but B re-exports
        Type from module C, the import_map has A::Type -> B::Type. This pass
        fixes it to A::Type -> C::Type by finding where the struct is defined.
        """
        from core.utils import get_simple_name

        # Collect all struct FQNs from parsed ASTs
        struct_fqns: set[str] = set()
        simple_to_fqns: dict[str, set[str]] = {}

        for file_ctx in ctx.source_files.values():
            if file_ctx.is_test_only or not file_ctx.module_path:
                continue
            # Scan AST for struct definitions
            struct_names = self._collect_struct_names(file_ctx)
            for name in struct_names:
                fqn = f"{file_ctx.module_path}::{name}"
                struct_fqns.add(fqn)
                simple = get_simple_name(fqn)
                if simple not in simple_to_fqns:
                    simple_to_fqns[simple] = set()
                simple_to_fqns[simple].add(fqn)

        if not struct_fqns:
            return

        # Build re-export resolution map
        reexport_map: dict[str, str] = {}
        for file_ctx in ctx.source_files.values():
            if file_ctx.is_test_only:
                continue
            for alias, fqn in file_ctx.import_map.items():
                if fqn in struct_fqns:
                    continue  # Already canonical
                # FQN doesn't exist - likely a re-export
                simple = get_simple_name(fqn)
                if simple in simple_to_fqns:
                    candidates = simple_to_fqns[simple]
                    if len(candidates) == 1:
                        canonical = next(iter(candidates))
                        if canonical != fqn:
                            reexport_map[fqn] = canonical

        if not reexport_map:
            return

        # Apply to all import_maps
        fix_count = 0
        for file_ctx in ctx.source_files.values():
            if file_ctx.is_test_only:
                continue
            for alias, fqn in list(file_ctx.import_map.items()):
                if fqn in reexport_map:
                    file_ctx.import_map[alias] = reexport_map[fqn]
                    fix_count += 1

        if fix_count > 0:
            debug(f"Resolved {fix_count} re-export(s) in import_maps")

    def _collect_struct_names(self, file_ctx: SourceFileContext) -> List[str]:
        """Extract struct names from parsed AST (simple names, not FQNs)."""
        if not file_ctx.root or not file_ctx.source_code:
            return []

        struct_names: List[str] = []
        source = file_ctx.source_code

        def traverse(node):
            if node.type == "struct_definition":
                for child in node.children:
                    if child.type == "struct_identifier":
                        name = source[child.start_byte : child.end_byte].strip()
                        struct_names.append(name)
                        break
            for child in node.children:
                traverse(child)

        traverse(file_ctx.root)
        return struct_names

    def collect_structural_facts(
        self, file_ctx: SourceFileContext
    ) -> Tuple[List[Fact], Dict[str, List[Fact]], Dict[str, SourceLocation]]:
        """Pass 1: Collect structural facts from a single file (no LLM calls)."""
        assert file_ctx.source_code is not None, "source_code must be loaded before analysis"
        try:
            facts, location_map = build_code_facts(
                file_ctx.source_code, file_ctx.root, filename=file_ctx.path, import_map=file_ctx.import_map
            )
        except Exception as e:
            error(f"building facts for {file_ctx.path}: {e}")
            import traceback

            traceback.print_exc()
            return [], {}, {}

        # Build function facts index using schema metadata
        function_facts_index: Dict[str, List[Fact]] = {}

        for fact in facts:
            schema = FACT_REGISTRY.get(fact.name)
            if schema and schema.func_name_arg_idx is not None:
                func_name = fact.args[schema.func_name_arg_idx]
                function_facts_index.setdefault(func_name, []).append(fact)

        return facts, function_facts_index, location_map
