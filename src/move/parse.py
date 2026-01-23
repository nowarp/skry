"""
Move source code parsing - main entry points.

This is the public API for Move parsing. Internal implementation is split across:
# TODO: 1 file = 1 module assumption; multi-module files return only last module
- move/utils.py: Shared utilities (text extraction, line/col calculation)
- move/imports.py: Import/alias resolution
- move/extract.py: Source code extraction (functions, structs, docstrings)
- move/collectors.py: AST node collectors
"""

import sys
import warnings
from pathlib import Path
from typing import List, Tuple, Optional, Set, Dict, Any

from core.utils import error, get_simple_name
from core.facts import Fact

# Re-export public API from submodules
from move.utils import SourceLocation, _extract_text, _byte_to_line_col
from move.imports import _parse_module_declaration, _parse_imports, _replace_import_alias
from move.extract import (
    strip_ref_modifiers,
)
from move.types import strip_generics
from move.collectors import (
    _collect_local_vars,
    _collect_functions,
    _collect_structs,
    _collect_constants,
    _collect_calls,
    _collect_pack_bindings,
    _collect_duplicated_branch_conditions,
    _collect_duplicated_branch_bodies,
    _collect_field_accesses,
    _collect_destructuring_accesses,
    _collect_pack_expressions,
)

try:
    from tree_sitter import Language, Parser
except ImportError:
    error("tree-sitter not installed. Run: pip install -r requirements.txt")
    sys.exit(1)

TREE_SITTER_MOVE_DIR = Path(__file__).resolve().parent.parent.parent / "third-party/sui/external-crates/move/tooling/tree-sitter"

# Types that represent extractable value (Coin, Balance, Token, etc.)
# These are types that when returned from a function, indicate value extraction
COIN_TYPE_PATTERNS = {
    "Coin",
    "Balance",
    "Token",
    "sui::coin::Coin",
    "sui::balance::Balance",
    "sui::token::Token",
    "0x2::coin::Coin",
    "0x2::balance::Balance",
    "0x2::token::Token",
}


def _is_coin_type(type_str: str) -> bool:
    """Check if type represents extractable value (Coin, Balance, Token)."""
    # Strip generic params for base type check
    base_type = type_str.split("<")[0].strip()

    # Direct match
    if base_type in COIN_TYPE_PATTERNS:
        return True

    # Check suffix (e.g., "my_module::Coin" matches "Coin")
    type_suffix = get_simple_name(base_type)
    return type_suffix in {"Coin", "Balance", "Token"}


def _setup_tree_sitter_move() -> Language:
    move_dir = Path(TREE_SITTER_MOVE_DIR)
    build_dir = move_dir / "build"
    so_path = build_dir / "move.so"

    if not move_dir.exists():
        error(f"tree-sitter-sui-move not found. Clone it to {TREE_SITTER_MOVE_DIR}")
        sys.exit(1)

    if not so_path.exists():
        try:
            build_dir.mkdir(parents=True, exist_ok=True)
            Language.build_library(str(so_path), [str(move_dir)])
        except Exception as e:
            error(f"building tree-sitter-move: {e}")
            sys.exit(1)

    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=FutureWarning)
        return Language(str(so_path), "move")


def parse_move_source(source_code: str):
    """
    Parse Move source code using tree-sitter and return the root node.
    """
    move_lang = _setup_tree_sitter_move()
    parser = Parser()
    parser.set_language(move_lang)
    tree = parser.parse(bytes(source_code, "utf8"))
    return tree.root_node


def build_code_facts(
    source_code: str,
    root,
    role_types: Optional[Set[str]] = None,
    filename: str = "",
    import_map: Optional[Dict[str, str]] = None,
) -> Tuple[List[Fact], Dict[str, SourceLocation]]:
    """
    Parse Move source code and extract facts about functions, structs, calls, etc.

    Args:
        source_code: The Move source code to parse
        root: Pre-parsed tree-sitter root node
        role_types: Optional set of fully-qualified role type names from other files
        filename: Source file path for location tracking
        import_map: Optional pre-computed import map (for re-export resolution)

    Returns:
        Tuple of (facts, location_map) where location_map maps entity identifiers
        to SourceLocation objects
    """
    if role_types is None:
        role_types = set()
    facts: List[Fact] = []
    location_map: Dict[str, SourceLocation] = {}

    try:
        module_path = _parse_module_declaration(source_code, root)
        if import_map is None:
            import_map = _parse_imports(source_code, root)

        # Collect nodes
        # functions: (name, start_byte, is_public, is_entry, is_test_only, is_friend, params, return_type, type_params, is_abort_only)
        functions: List[
            Tuple[str, int, bool, bool, bool, bool, List[Tuple[int, str, str]], Optional[str], List[str], bool]
        ] = []
        # calls: (callee_name, start_byte, args, emitted_event_type, receiver)
        calls: List[Tuple[str, int, List[Tuple[int, str]], Optional[str], Optional[str]]] = []
        local_vars: List[Tuple[str, int]] = []
        # structs: (name, start_byte, fields, abilities, comment, type_params)
        structs: List[
            Tuple[str, int, List[Tuple[int, str, str, Optional[str]]], List[str], Optional[str], List[Tuple[str, bool]]]
        ] = []
        constants: List[Tuple[str, int, str, str, Any]] = []
        duplicated_conditions: List[Tuple[int, str, int]] = []
        duplicated_bodies: List[Tuple[int, str, int]] = []
        field_accesses: List[Tuple[str, str, str, int]] = []  # (base_var, field_path, snippet, pos)
        pack_exprs: List[Tuple[str, int]] = []  # (struct_name, byte_pos)

        # Collect pack bindings first (for emit detection: let e = Event {...}; emit(e))
        pack_bindings = _collect_pack_bindings(root, source_code, import_map, module_path or "")

        def collect_nodes(node):
            nonlocal module_path
            _collect_local_vars(node, source_code, local_vars)
            _collect_functions(node, source_code, functions)
            _collect_structs(node, source_code, structs)
            _collect_constants(node, source_code, constants)
            _collect_calls(node, source_code, calls, import_map, module_path or "", pack_bindings)
            _collect_duplicated_branch_conditions(node, source_code, duplicated_conditions)
            _collect_duplicated_branch_bodies(node, source_code, duplicated_bodies)
            _collect_field_accesses(node, source_code, field_accesses)
            _collect_destructuring_accesses(node, source_code, field_accesses)  # Same list as field accesses
            _collect_pack_expressions(node, source_code, pack_exprs, import_map, module_path or "")
            for child in node.children:
                collect_nodes(child)

        collect_nodes(root)

        # Sort by position
        functions.sort(key=lambda x: x[1])
        calls.sort(key=lambda x: x[1])
        local_vars.sort(key=lambda x: x[1])
        structs.sort(key=lambda x: x[1])
        constants.sort(key=lambda x: x[1])

        def _qualify_name(name: str) -> str:
            if module_path:
                return f"{module_path}::{name}"
            return name

        # Create struct facts
        for struct_name, struct_start, fields, abilities, struct_comment, type_params in structs:
            qualified_struct_name = _qualify_name(struct_name)
            facts.append(Fact("Struct", (qualified_struct_name,)))

            line, col = _byte_to_line_col(source_code, struct_start)
            location_map[qualified_struct_name] = SourceLocation(filename, line, col)

            if struct_comment:
                facts.append(Fact("StructComment", (qualified_struct_name, struct_comment)))

            # Generate StructPhantomTypeParam facts
            for param_idx, (type_var, is_phantom) in enumerate(type_params):
                if is_phantom:
                    facts.append(Fact("StructPhantomTypeParam", (qualified_struct_name, param_idx, type_var)))

            for field_idx, field_name, field_type, field_comment in fields:
                facts.append(Fact("StructField", (qualified_struct_name, field_idx, field_name, field_type)))
                if field_comment:
                    facts.append(Fact("FieldComment", (qualified_struct_name, field_name, field_comment)))

            has_copy = "copy" in abilities
            has_drop = "drop" in abilities
            has_key = "key" in abilities
            has_store = "store" in abilities
            if has_copy and has_drop and not has_key and not has_store:
                facts.append(Fact("IsEvent", (qualified_struct_name,)))
            if has_copy:
                facts.append(Fact("HasCopyAbility", (qualified_struct_name,)))
            if has_drop:
                facts.append(Fact("HasDropAbility", (qualified_struct_name,)))
            if has_key:
                facts.append(Fact("HasKeyAbility", (qualified_struct_name,)))
            if has_store:
                facts.append(Fact("HasStoreAbility", (qualified_struct_name,)))

        # Create constant facts
        for const_name, const_start, const_type, raw_value, parsed_value in constants:
            qualified_const_name = _qualify_name(const_name)
            facts.append(Fact("ConstDef", (qualified_const_name, const_name, parsed_value, const_type)))

            line, col = _byte_to_line_col(source_code, const_start)
            location_map[qualified_const_name] = SourceLocation(filename, line, col)

        # Create function facts (skip test_only and abort-only functions entirely)
        call_counter = 0
        for (
            func_name,
            func_start,
            is_public,
            is_entry,
            is_test_only,
            is_friend,
            params,
            return_type,
            type_params,
            is_abort_only,
        ) in functions:
            # Skip test functions - no analysis needed
            if is_test_only:
                continue

            # Skip abort-only stub functions - they generate false positives
            if is_abort_only:
                continue

            qualified_func_name = _qualify_name(func_name)
            facts.append(Fact("Fun", (qualified_func_name,)))

            line, col = _byte_to_line_col(source_code, func_start)
            location_map[qualified_func_name] = SourceLocation(filename, line, col)
            if is_public:
                facts.append(Fact("IsPublic", (qualified_func_name,)))
            if is_entry:
                facts.append(Fact("IsEntry", (qualified_func_name,)))
            if is_friend:
                facts.append(Fact("IsFriend", (qualified_func_name,)))

            if return_type:
                # Qualify return type similar to how parameter types are qualified
                return_type_clean = strip_ref_modifiers(return_type)

                # For generic types like Coin<T>, extract base type for import resolution
                base_type = return_type_clean.split("<")[0] if "<" in return_type_clean else return_type_clean
                resolved_base = _replace_import_alias(base_type, import_map)

                # Reconstruct full type with generics if present
                if "<" in return_type_clean:
                    generic_part = return_type_clean[len(base_type) :]  # e.g., "<T>" from "Coin<T>"
                    resolved_return_type = resolved_base + generic_part
                else:
                    resolved_return_type = resolved_base

                # Only add module_path if:
                # 1. No :: in name (not already qualified)
                # 2. We have a module_path
                # 3. The base type was NOT resolved through import_map (i.e., it's a local type)
                if "::" not in resolved_return_type and module_path and resolved_base == base_type:
                    qualified_return_type = f"{module_path}::{resolved_return_type}"
                else:
                    qualified_return_type = resolved_return_type

                # Preserve ref modifiers in the qualified type
                if return_type.startswith("&mut "):
                    qualified_return_type = f"&mut {qualified_return_type}"
                elif return_type.startswith("&"):
                    qualified_return_type = f"&{qualified_return_type}"

                facts.append(Fact("FunReturnType", (qualified_func_name, qualified_return_type)))
                if is_public and return_type.startswith("&mut"):
                    mut_type = return_type[4:].strip()
                    is_generic_accessor = mut_type in type_params
                    if is_generic_accessor:
                        facts.append(Fact("IsGenericAccessor", (qualified_func_name,)))
                    else:
                        facts.append(Fact("ReturnsMutableRef", (qualified_func_name, qualified_return_type)))
                # Check if function returns Coin/Balance/Token type (value extraction)
                # Use the qualified base type for checking
                qualified_base = resolved_base if "<" in return_type_clean else qualified_return_type
                if _is_coin_type(qualified_base):
                    # Skip immutable references - they cannot be used to extract value
                    # Only flag owned values (Coin<T>) and mutable refs (&mut Balance<T>)
                    is_immutable_ref = qualified_return_type.startswith("&") and not qualified_return_type.startswith(
                        "&mut "
                    )
                    if not is_immutable_ref:
                        # Store the type without ref modifiers for ReturnsCoinType
                        coin_type_without_ref = qualified_return_type
                        if qualified_return_type.startswith("&mut "):
                            coin_type_without_ref = qualified_return_type[5:]
                        elif qualified_return_type.startswith("&"):
                            coin_type_without_ref = qualified_return_type[1:]
                        facts.append(Fact("ReturnsCoinType", (qualified_func_name, coin_type_without_ref)))

            if func_name == "init":
                is_valid_init = False
                param_types = [p[2] for p in params]

                if len(param_types) == 1:
                    if "TxContext" in param_types[0]:
                        is_valid_init = True
                elif len(param_types) == 2:
                    if "TxContext" in param_types[1]:
                        is_valid_init = True

                if is_valid_init:
                    facts.append(Fact("IsInit", (qualified_func_name,)))

            for param_idx, param_name, param_type in params:
                # Resolve type to FQN via imports, preserving ref modifiers
                param_type_clean = strip_ref_modifiers(param_type)
                resolved_param_type = _replace_import_alias(param_type_clean, import_map)

                # Don't qualify primitive types
                base_for_qualify = resolved_param_type.split("<")[0]
                primitives = {"address", "bool", "signer", "u8", "u16", "u32", "u64", "u128", "u256", "vector"}
                if "::" not in resolved_param_type and module_path and base_for_qualify not in primitives:
                    qualified_param_type = f"{module_path}::{resolved_param_type}"
                else:
                    qualified_param_type = resolved_param_type

                # Preserve ref modifiers in resolved type for FormalArg
                ref_prefix = param_type[: len(param_type) - len(param_type_clean)]
                resolved_full_type = f"{ref_prefix}{qualified_param_type}"
                facts.append(Fact("FormalArg", (qualified_func_name, param_idx, param_name, resolved_full_type)))

                role_type = None
                if qualified_param_type in role_types:
                    role_type = qualified_param_type
                elif resolved_param_type in role_types:
                    role_type = resolved_param_type

                if role_type:
                    facts.append(Fact("ChecksCapability", (role_type, qualified_func_name)))

            # Generate facts for generic type parameters
            for idx, type_var in enumerate(type_params):
                facts.append(Fact("HasGenericParam", (qualified_func_name, idx, type_var)))

            next_func_start = None
            for other_name, other_start, _, _, _, _, _, _, _, _ in functions:
                if other_start > func_start:
                    next_func_start = other_start
                    break

            for var_name, var_start in local_vars:
                if var_start > func_start:
                    if next_func_start is None or var_start < next_func_start:
                        facts.append(Fact("InFun", (qualified_func_name, var_name)))

            for callee_name, call_start, args, emitted_event_type, receiver in calls:
                if call_start > func_start:
                    if next_func_start is None or call_start < next_func_start:
                        call_counter += 1
                        call_id = f"{callee_name}@{call_counter}"
                        facts.append(Fact("Call", (call_id,)))
                        facts.append(Fact("InFun", (qualified_func_name, call_id)))

                        # Track method calls (calls with receiver)
                        if receiver is not None:
                            facts.append(Fact("IsMethodCall", (call_id,)))

                        line, col = _byte_to_line_col(source_code, call_start)
                        location_map[call_id] = SourceLocation(filename, line, col)

                        for arg_idx, arg_name in args:
                            facts.append(Fact("ActualArg", (call_id, arg_idx, arg_name)))

                        if emitted_event_type:
                            facts.append(Fact("EmitsEvent", (qualified_func_name, emitted_event_type)))

            # Generate FieldAccess facts (deduplicate nested paths)
            param_map = {p[1]: p[2] for p in params}  # param_name -> param_type

            # Filter to this function's scope and deduplicate nested paths
            # For pool.config.fee, keep only config.fee (longest), not config
            func_accesses = [
                (base_var, field_path, snippet, access_pos)
                for base_var, field_path, snippet, access_pos in field_accesses
                if access_pos > func_start and (next_func_start is None or access_pos < next_func_start)
            ]
            # Group by (base_var, pos), keep longest path
            best_paths: dict[tuple[str, int], tuple[str, str]] = {}  # (base_var, pos) -> (longest_path, snippet)
            for base_var, field_path, snippet, access_pos in func_accesses:
                key = (base_var, access_pos)
                if key not in best_paths or len(field_path) > len(best_paths[key][0]):
                    best_paths[key] = (field_path, snippet)

            for (base_var, access_pos), (field_path, snippet) in best_paths.items():
                if base_var in param_map:
                    param_type = param_map[base_var]
                    struct_type = strip_ref_modifiers(param_type)
                    struct_type = strip_generics(struct_type)  # Match HasKeyAbility struct names
                    struct_type = _replace_import_alias(struct_type, import_map)
                    if "::" not in struct_type and module_path and struct_type[0:1].isupper():
                        struct_type = f"{module_path}::{struct_type}"
                    line_num, _ = _byte_to_line_col(source_code, access_pos)
                    # Keep existing FieldAccess with full info (for compatibility)
                    facts.append(Fact("FieldAccess", (qualified_func_name, struct_type, field_path, snippet, line_num)))
                    # Add new ReadsField with simple schema
                    facts.append(Fact("ReadsField", (qualified_func_name, struct_type, field_path)))

            # Generate PacksStruct facts for struct instantiations in this function
            func_packs = [
                (struct_name, pack_pos)
                for struct_name, pack_pos in pack_exprs
                if pack_pos > func_start and (next_func_start is None or pack_pos < next_func_start)
            ]
            for struct_name, pack_pos in func_packs:
                facts.append(Fact("PacksStruct", (qualified_func_name, struct_name)))

            # Generate PacksToVar facts for variable bindings to packed structs
            # This tracks which variable holds which struct type (let var = Struct {...})
            for var_name, bindings in pack_bindings.items():
                for pack_pos, struct_type in bindings:
                    if pack_pos > func_start and (next_func_start is None or pack_pos < next_func_start):
                        facts.append(Fact("PacksToVar", (qualified_func_name, var_name, struct_type)))

        # Generate DuplicatedBranchCondition facts
        for dup_pos, cond_text, _ in duplicated_conditions:
            containing_func = None
            for (
                func_name,
                func_start,
                is_public,
                is_entry,
                is_test_only,
                is_friend,
                params,
                return_type,
                type_params,
                _,
            ) in functions:
                next_func_start = None
                for other_name, other_start, _, _, _, _, _, _, _, _ in functions:
                    if other_start > func_start:
                        next_func_start = other_start
                        break
                if dup_pos > func_start and (next_func_start is None or dup_pos < next_func_start):
                    containing_func = _qualify_name(func_name)
                    break

            if containing_func:
                facts.append(Fact("DuplicatedBranchCondition", (containing_func, cond_text)))
                dup_id = f"dup_cond@{dup_pos}"
                line, col = _byte_to_line_col(source_code, dup_pos)
                location_map[dup_id] = SourceLocation(filename, line, col)

        # Generate DuplicatedBranchBody facts
        for dup_pos, body_text, _ in duplicated_bodies:
            containing_func = None
            for (
                func_name,
                func_start,
                is_public,
                is_entry,
                is_test_only,
                is_friend,
                params,
                return_type,
                type_params,
                _,
            ) in functions:
                next_func_start = None
                for other_name, other_start, _, _, _, _, _, _, _, _ in functions:
                    if other_start > func_start:
                        next_func_start = other_start
                        break
                if dup_pos > func_start and (next_func_start is None or dup_pos < next_func_start):
                    containing_func = _qualify_name(func_name)
                    break

            if containing_func:
                body_snippet = body_text[:50] + "..." if len(body_text) > 50 else body_text
                facts.append(Fact("DuplicatedBranchBody", (containing_func, body_snippet)))
                dup_id = f"dup_body@{dup_pos}"
                line, col = _byte_to_line_col(source_code, dup_pos)
                location_map[dup_id] = SourceLocation(filename, line, col)

    except Exception as e:
        error(f"parsing Move code: {e}")

    return facts, location_map


def find_error_nodes(node, source_code: str, errors: list, depth: int = 0, max_depth: int = 50) -> None:
    """Find ERROR nodes in the parse tree (for debugging parse failures)."""
    if depth > max_depth:
        return
    if node.type == "ERROR":
        text = _extract_text(source_code, node.start_byte, node.end_byte)
        if len(text) > 100:
            text = text[:100] + "..."
        errors.append((node, depth, text))
    for child in node.children:
        find_error_nodes(child, source_code, errors, depth + 1, max_depth)
