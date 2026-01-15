"""
AST node collectors for Move parsing.
"""

import re
from typing import List, Tuple, Optional, Set, Dict

from core.utils import debug, get_simple_name
from move.utils import _extract_text, _extract_preceding_comment
from move.imports import _replace_import_alias


def strip_ref_modifiers(text: str) -> str:
    """Strip reference modifiers like &mut, &, mut from the beginning of text."""
    text = text.strip()
    if text.startswith("&mut"):
        text = text[4:].strip()
    elif text.startswith("&"):
        text = text[1:].strip()
    if text.startswith("mut "):
        text = text[4:].strip()
    return text


# =============================================================================
# Parameter and field parsing
# =============================================================================


def _parse_function_parameters_new_grammar(function_node, source_code: str) -> List[Tuple[int, str, str]]:
    """Parse function parameters from a function_definition node (new grammar)."""
    params: List[Tuple[int, str, str]] = []

    for child in function_node.children:
        if child.type == "function_parameters":
            param_idx = 0
            for param_node in child.children:
                if param_node.type == "function_parameter":
                    var_name = None
                    param_type = None

                    for subchild in param_node.children:
                        if subchild.type == "variable_identifier":
                            var_name = _extract_text(source_code, subchild.start_byte, subchild.end_byte).strip()
                        elif subchild.type in (
                            "ref_type",
                            "apply_type",
                            "module_access",
                            "identifier",
                            "primitive_type",
                        ):
                            param_type = _extract_text(source_code, subchild.start_byte, subchild.end_byte).strip()

                    if var_name and param_type:
                        params.append((param_idx, var_name, param_type))
                        param_idx += 1
            break

    return params


def _parse_call_arguments(arg_list_node, source_code: str, import_map: dict[str, str]) -> List[Tuple[int, str]]:
    """Parse function call arguments from an arg_list node (new grammar)."""
    args: List[Tuple[int, str]] = []
    arg_idx = 0

    i = 0
    while i < len(arg_list_node.children):
        child = arg_list_node.children[i]
        if child.type in ("(", ")", ",", "newline"):
            i += 1
            continue

        arg_start_byte = child.start_byte
        arg_end_byte = child.end_byte

        j = i + 1
        while j < len(arg_list_node.children):
            next_child = arg_list_node.children[j]
            if next_child.type == ",":
                arg_end_byte = next_child.start_byte
                break
            elif next_child.type == ")":
                arg_end_byte = next_child.start_byte
                break
            elif next_child.type not in ("newline",):
                arg_end_byte = next_child.end_byte
            j += 1

        arg_text = _extract_text(source_code, arg_start_byte, arg_end_byte).strip()
        if arg_text.endswith(","):
            arg_text = arg_text[:-1].strip()
        arg_text = strip_ref_modifiers(arg_text)
        if "::" in arg_text:
            parts = arg_text.split("::", 1)
            if len(parts) == 2 and parts[0] in import_map:
                arg_text = f"{import_map[parts[0]]}::{parts[1]}"

        args.append((arg_idx, arg_text))
        arg_idx += 1

        if j < len(arg_list_node.children) and arg_list_node.children[j].type == ",":
            i = j + 1
        else:
            i = j

    return args


# =============================================================================
# Test annotation helpers
# =============================================================================


def _has_test_annotation(node, source_code: str) -> bool:
    """Check if a function has #[test] or #[test(...)] annotation."""
    prev = node.prev_sibling
    while prev is not None:
        if prev.type == "annotation":
            ann_text = _extract_text(source_code, prev.start_byte, prev.end_byte).strip()
            if ann_text.startswith("#[test]") or ann_text.startswith("#[test("):
                return True
        elif prev.type not in ("newline", "comment", "line_comment", "block_comment"):
            break
        prev = prev.prev_sibling
    return False


def _has_test_only_annotation(node, source_code: str) -> bool:
    """Check if a function has #[test_only] annotation."""
    prev = node.prev_sibling
    while prev is not None:
        if prev.type == "annotation":
            ann_text = _extract_text(source_code, prev.start_byte, prev.end_byte).strip()
            if ann_text.startswith("#[test_only]"):
                return True
        elif prev.type not in ("newline", "comment", "line_comment", "block_comment"):
            break
        prev = prev.prev_sibling
    return False


def is_test_only_module(source_code: str, root) -> bool:
    """Check if the entire module is marked #[test_only]."""

    def check_module(node) -> bool:
        if node.type == "module_definition":
            prev = node.prev_sibling
            while prev is not None:
                if prev.type == "annotation":
                    ann_text = _extract_text(source_code, prev.start_byte, prev.end_byte).strip()
                    if ann_text.startswith("#[test_only]"):
                        return True
                elif prev.type not in ("newline", "comment", "line_comment", "block_comment"):
                    break
                prev = prev.prev_sibling
            return False

        for child in node.children:
            if check_module(child):
                return True
        return False

    return check_module(root)


# =============================================================================
# AST Collectors
# =============================================================================


def _is_abort_only_function(func_node) -> bool:
    """Check if function body contains only an abort statement (stub function)."""
    block = None
    for child in func_node.children:
        if child.type == "block":
            block = child
            break

    if not block:
        return False

    # Get statements in block (skip braces, newlines, comments)
    stmts = [
        c for c in block.children if c.type not in ("{", "}", "newline", "comment", "line_comment", "block_comment")
    ]

    if len(stmts) != 1:
        return False

    stmt = stmts[0]
    return stmt.type == "abort_expression"


def _collect_local_vars(node, source_code: str, local_vars: list) -> None:
    """Collect local variable declarations (let bindings)."""
    if node.type == "let_statement":
        for child in node.children:
            if child.type == "bind_list":
                for bind_var in child.children:
                    if bind_var.type == "bind_var":
                        for var_id in bind_var.children:
                            if var_id.type == "variable_identifier":
                                var_name = _extract_text(source_code, var_id.start_byte, var_id.end_byte).strip()
                                if var_name:
                                    local_vars.append((var_name, node.start_byte))


def _collect_duplicated_branch_conditions(node, source_code: str, duplicates: list) -> None:
    """Detect if-else chains where the same condition appears multiple times."""
    if node.type != "if_expression":
        return

    conditions: List[Tuple[int, str]] = []

    def _extract_condition(if_node) -> Optional[Tuple[int, str]]:
        for i, child in enumerate(if_node.children):
            if child.type in ("if", "(", ")"):
                continue
            if child.type in (
                "binary_expression",
                "name_expression",
                "call_expression",
                "unary_expression",
                "bool_literal",
                "parenthesized_expression",
            ):
                cond_text = _extract_text(source_code, child.start_byte, child.end_byte)
                cond_text = " ".join(cond_text.split())
                return (child.start_byte, cond_text)
        return None

    def _traverse_if_chain(if_node):
        cond = _extract_condition(if_node)
        if cond:
            conditions.append(cond)

        found_else = False
        for i, child in enumerate(if_node.children):
            if child.type == "else":
                found_else = True
            elif found_else and child.type == "if_expression":
                _traverse_if_chain(child)
                break

    _traverse_if_chain(node)

    seen: Dict[str, int] = {}
    for pos, cond_text in conditions:
        if cond_text in seen:
            duplicates.append((pos, cond_text, seen[cond_text]))
        else:
            seen[cond_text] = pos


def _strip_comments(text: str) -> str:
    """Strip // and /* */ comments from Move code."""
    # Remove /* */ block comments (non-greedy)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    # Remove // line comments
    text = re.sub(r"//[^\n]*", "", text)
    return text


def _collect_duplicated_branch_bodies(node, source_code: str, duplicates: list) -> None:
    """Detect if-else chains where multiple branches have identical bodies."""
    if node.type != "if_expression":
        return

    bodies: List[Tuple[int, str, int]] = []

    def _extract_body(block_node) -> Optional[Tuple[int, str, int]]:
        if block_node.type != "block":
            return None
        body_text = _extract_text(source_code, block_node.start_byte, block_node.end_byte)
        body_text = _strip_comments(body_text)
        body_text = body_text.strip()
        if body_text.startswith("{"):
            body_text = body_text[1:]
        if body_text.endswith("}"):
            body_text = body_text[:-1]
        body_text = " ".join(body_text.split())
        return (block_node.start_byte, body_text, len(body_text))

    def _traverse_if_chain(if_node):
        found_else = False
        for child in if_node.children:
            if child.type == "block" and not found_else:
                body = _extract_body(child)
                if body:
                    bodies.append(body)
            elif child.type == "else":
                found_else = True
            elif found_else:
                if child.type == "if_expression":
                    _traverse_if_chain(child)
                elif child.type == "block":
                    body = _extract_body(child)
                    if body:
                        bodies.append(body)
                break

    _traverse_if_chain(node)

    if len(bodies) < 2:
        return

    by_length: Dict[int, List[Tuple[int, str]]] = {}
    for pos, body_text, length in bodies:
        if length not in by_length:
            by_length[length] = []
        by_length[length].append((pos, body_text))

    for length, group in by_length.items():
        if len(group) < 2:
            continue
        seen: Dict[str, int] = {}
        for pos, body_text in group:
            if body_text in seen:
                duplicates.append((pos, body_text, seen[body_text]))
            else:
                seen[body_text] = pos


def _collect_functions(node, source_code: str, functions: list) -> None:
    """Collect function definitions (including test functions for boundary calculation)."""
    if node.type == "function_definition":
        func_name = None
        is_public = False
        is_entry = False
        # Mark both #[test] and #[test_only] functions
        is_test_only = _has_test_annotation(node, source_code) or _has_test_only_annotation(node, source_code)
        params = []
        return_type = None
        type_params = []

        for child in node.children:
            if child.type == "function_identifier":
                func_name = _extract_text(source_code, child.start_byte, child.end_byte).strip()
                break

        is_friend = False
        for child in node.children:
            if child.type == "modifier":
                mod_full_text = _extract_text(source_code, child.start_byte, child.end_byte).strip()
                mod_normalized = mod_full_text.replace(" ", "")
                if mod_normalized == "public(friend)":
                    is_public = True
                    is_friend = True
                elif mod_normalized == "public(package)":
                    is_public = True
                    is_friend = True
                else:
                    for subchild in child.children:
                        mod_text = _extract_text(source_code, subchild.start_byte, subchild.end_byte).strip()
                        if mod_text == "public":
                            is_public = True
                        elif mod_text == "entry":
                            is_entry = True

        for child in node.children:
            if child.type == "type_parameters":
                for param_child in child.children:
                    if param_child.type == "type_parameter":
                        for id_child in param_child.children:
                            if id_child.type == "type_parameter_identifier":
                                type_params.append(
                                    _extract_text(source_code, id_child.start_byte, id_child.end_byte).strip()
                                )
                                break
                break

        for child in node.children:
            if child.type == "ret_type":
                ret_text = _extract_text(source_code, child.start_byte, child.end_byte).strip()
                if ret_text.startswith(":"):
                    return_type = ret_text[1:].strip()
                else:
                    return_type = ret_text
                break

        if func_name:
            is_abort_only = _is_abort_only_function(node)
            try:
                params = _parse_function_parameters_new_grammar(node, source_code)
                functions.append(
                    (
                        func_name,
                        node.start_byte,
                        is_public,
                        is_entry,
                        is_test_only,
                        is_friend,
                        params,
                        return_type,
                        type_params,
                        is_abort_only,
                    )
                )
            except Exception as e:
                debug(f"Error parsing function parameters: {e}")
                functions.append(
                    (
                        func_name,
                        node.start_byte,
                        is_public,
                        is_entry,
                        is_test_only,
                        is_friend,
                        [],
                        return_type,
                        type_params,
                        is_abort_only,
                    )
                )


def _collect_structs(node, source_code: str, structs: list) -> None:
    """Collect struct declarations with abilities and comments."""
    if node.type == "struct_definition":
        struct_name = None
        fields = []
        abilities: Set[str] = set()
        type_params: List[Tuple[str, bool]] = []  # [(type_var, is_phantom), ...]

        struct_comment = _extract_preceding_comment(node, source_code)

        for child in node.children:
            if child.type == "struct_identifier":
                struct_name = _extract_text(source_code, child.start_byte, child.end_byte).strip()
            elif child.type == "type_parameters":
                # Extract type parameters with phantom modifier
                for param_child in child.children:
                    if param_child.type == "type_parameter":
                        is_phantom = False
                        type_var = None
                        for param_subchild in param_child.children:
                            if param_subchild.type == "phantom":
                                is_phantom = True
                            elif param_subchild.type == "type_parameter_identifier":
                                type_var = _extract_text(
                                    source_code, param_subchild.start_byte, param_subchild.end_byte
                                ).strip()
                        if type_var:
                            type_params.append((type_var, is_phantom))
            elif child.type == "ability_decls":
                for ability_child in child.children:
                    if ability_child.type == "ability":
                        ability_text = _extract_text(
                            source_code, ability_child.start_byte, ability_child.end_byte
                        ).strip()
                        abilities.add(ability_text)
            elif child.type == "datatype_fields":
                for subchild in child.children:
                    if subchild.type == "named_fields":
                        field_idx = 0
                        for field_child in subchild.children:
                            if field_child.type == "field_annotation":
                                field_comment = _extract_preceding_comment(field_child, source_code)
                                field_text = _extract_text(
                                    source_code, field_child.start_byte, field_child.end_byte
                                ).strip()
                                if ":" in field_text:
                                    parts = field_text.split(":", 1)
                                    field_name = parts[0].strip()
                                    field_type = parts[1].strip()
                                    fields.append((field_idx, field_name, field_type, field_comment))
                                    field_idx += 1
                        break

        if struct_name:
            structs.append((struct_name, node.start_byte, fields, abilities, struct_comment, type_params))


def _collect_constants(node, source_code: str, constants: list) -> None:
    """Collect constant definitions."""
    if node.type == "constant":
        const_name = None
        const_type = None
        const_value_raw = None
        const_value_parsed = None

        for child in node.children:
            if child.type == "constant_identifier":
                const_name = _extract_text(source_code, child.start_byte, child.end_byte).strip()
            elif child.type in ("primitive_type", "type_", "apply_type"):
                const_type = _extract_text(source_code, child.start_byte, child.end_byte).strip()
            elif child.type == "num_literal":
                const_value_raw = _extract_text(source_code, child.start_byte, child.end_byte).strip()
                try:
                    const_value_parsed = int(const_value_raw.replace("_", ""))
                except ValueError:
                    const_value_parsed = const_value_raw
            elif child.type == "bool_literal":
                const_value_raw = _extract_text(source_code, child.start_byte, child.end_byte).strip()
                const_value_parsed = const_value_raw == "true"
            elif child.type == "address_literal":
                const_value_raw = _extract_text(source_code, child.start_byte, child.end_byte).strip()
                const_value_parsed = const_value_raw
            elif child.type == "byte_string_literal":
                const_value_raw = _extract_text(source_code, child.start_byte, child.end_byte).strip()
                const_value_parsed = const_value_raw
            elif child.type == "hex_string_literal":
                const_value_raw = _extract_text(source_code, child.start_byte, child.end_byte).strip()
                const_value_parsed = const_value_raw

        if const_name and const_value_raw is not None:
            constants.append(
                (const_name, node.start_byte, const_type or "unknown", const_value_raw, const_value_parsed)
            )


# =============================================================================
# Event emit detection helpers
# =============================================================================


def _collect_pack_bindings(
    root, source_code: str, import_map: dict[str, str], module_path: str
) -> dict[str, List[Tuple[int, str]]]:
    """
    Collect variable bindings where the value is a struct pack expression.

    Returns a dict mapping variable names to list of (byte_position, struct_type).
    This handles the case where the same variable name (like 'event') is reused
    in multiple functions with different struct types.

    E.g., for `let event = MyEvent { ... }` at pos 100, returns {"event": [(100, "module::MyEvent")]}
    """
    bindings: dict[str, List[Tuple[int, str]]] = {}

    def traverse(node):
        if node.type == "let_statement":
            var_name = None
            struct_type = None
            pos = node.start_byte

            for child in node.children:
                if child.type == "bind_list":
                    for bind_child in child.children:
                        if bind_child.type == "bind_var":
                            for var_child in bind_child.children:
                                if var_child.type == "variable_identifier":
                                    var_name = _extract_text(
                                        source_code, var_child.start_byte, var_child.end_byte
                                    ).strip()
                                    break
                elif child.type == "pack_expression":
                    for pack_child in child.children:
                        if pack_child.type == "name_expression":
                            for access_child in pack_child.children:
                                if access_child.type == "module_access":
                                    name_parts = []
                                    for name_child in access_child.children:
                                        if name_child.type == "identifier":
                                            name_parts.append(
                                                _extract_text(
                                                    source_code, name_child.start_byte, name_child.end_byte
                                                ).strip()
                                            )
                                        elif name_child.type == "module_identifier":
                                            name_parts.append(
                                                _extract_text(
                                                    source_code, name_child.start_byte, name_child.end_byte
                                                ).strip()
                                            )
                                    if name_parts:
                                        struct_name = "::".join(name_parts) if len(name_parts) > 1 else name_parts[0]
                                        struct_name = _replace_import_alias(struct_name, import_map)
                                        if "::" not in struct_name and module_path:
                                            struct_name = f"{module_path}::{struct_name}"
                                        struct_type = struct_name
                                    break
                            break

            if var_name and struct_type:
                if var_name not in bindings:
                    bindings[var_name] = []
                bindings[var_name].append((pos, struct_type))

        for child in node.children:
            traverse(child)

    traverse(root)
    return bindings


def _extract_pack_struct_name(
    arg_list_node, source_code: str, import_map: dict[str, str], module_path: str
) -> Optional[str]:
    """Extract struct name from a pack_expression in an arg_list."""
    for child in arg_list_node.children:
        if child.type == "pack_expression":
            for subchild in child.children:
                if subchild.type == "name_expression":
                    for access_child in subchild.children:
                        if access_child.type == "module_access":
                            name_parts = []
                            for name_child in access_child.children:
                                if name_child.type == "identifier":
                                    name_parts.append(
                                        _extract_text(source_code, name_child.start_byte, name_child.end_byte).strip()
                                    )
                                elif name_child.type == "module_identifier":
                                    name_parts.append(
                                        _extract_text(source_code, name_child.start_byte, name_child.end_byte).strip()
                                    )
                            if name_parts:
                                struct_name = "::".join(name_parts) if len(name_parts) > 1 else name_parts[0]
                                struct_name = _replace_import_alias(struct_name, import_map)
                                if "::" not in struct_name and module_path:
                                    struct_name = f"{module_path}::{struct_name}"
                                return struct_name
    return None


def _extract_type_from_node(type_node, source_code: str, import_map: dict[str, str], module_path: str) -> Optional[str]:
    """Extract a type name from a type node."""
    if type_node.type == "apply_type":
        for child in type_node.children:
            if child.type == "module_access":
                name_parts = []
                for name_child in child.children:
                    if name_child.type == "identifier":
                        name_parts.append(
                            _extract_text(source_code, name_child.start_byte, name_child.end_byte).strip()
                        )
                    elif name_child.type == "module_identifier":
                        name_parts.append(
                            _extract_text(source_code, name_child.start_byte, name_child.end_byte).strip()
                        )
                    elif name_child.type == "module_identity":
                        mod_parts = []
                        for mod_child in name_child.children:
                            if mod_child.type == "module_identifier":
                                mod_parts.append(
                                    _extract_text(source_code, mod_child.start_byte, mod_child.end_byte).strip()
                                )
                        if mod_parts:
                            name_parts.append("::".join(mod_parts))
                if name_parts:
                    type_name = "::".join(name_parts) if len(name_parts) > 1 else name_parts[0]
                    type_name = _replace_import_alias(type_name, import_map)
                    if "::" not in type_name and module_path:
                        type_name = f"{module_path}::{type_name}"
                    return type_name
    elif type_node.type == "ref_type":
        for child in type_node.children:
            result = _extract_type_from_node(child, source_code, import_map, module_path)
            if result:
                return result
    else:
        raw = _extract_text(source_code, type_node.start_byte, type_node.end_byte).strip()
        if raw and not raw.startswith("&"):
            raw = _replace_import_alias(raw, import_map)
            if "::" not in raw and module_path and raw[0].isupper():
                raw = f"{module_path}::{raw}"
            return raw
    return None


def _extract_type_arguments(
    name_expr_node, source_code: str, import_map: dict[str, str], module_path: str
) -> List[str]:
    """Extract type arguments from a name_expression node."""
    type_args = []

    def find_type_arguments(node):
        if node.type == "type_arguments":
            for type_child in node.children:
                if type_child.type in ("apply_type", "ref_type", "primitive_type", "tuple_type"):
                    type_name = _extract_type_from_node(type_child, source_code, import_map, module_path)
                    if type_name:
                        type_args.append(type_name)
        for child in node.children:
            find_type_arguments(child)

    find_type_arguments(name_expr_node)
    return type_args


def _collect_calls(
    node,
    source_code: str,
    calls: list,
    import_map: dict[str, str],
    module_path: str,
    pack_bindings: Optional[dict[str, List[Tuple[int, str]]]] = None,
) -> None:
    """Collect function call expressions, including method call syntax."""
    # Handle method call syntax: obj.method(args) - stored as dot_expression
    # Also handles chained field access: self.storage.method(args)
    if node.type == "dot_expression":
        base_var = None
        method_call = None

        for child in node.children:
            if child.type == ".":
                continue
            elif child.type == "name_expression":
                # This is the receiver/base (e.g., 'ctx' in ctx.epoch())
                for sub in child.children:
                    if sub.type == "module_access":
                        for ident in sub.children:
                            if ident.type == "identifier":
                                base_var = _extract_text(source_code, ident.start_byte, ident.end_byte).strip()
                                break
            elif child.type == "dot_expression":
                # Chained field access: self.storage.method()
                # Extract the receiver path (e.g., "self.storage")
                base_var = _extract_text(source_code, child.start_byte, child.end_byte).strip()
            elif child.type == "call_expression":
                # This is the method call (e.g., 'epoch()' in ctx.epoch())
                method_call = child

        if base_var and method_call:
            # Extract method name from the call_expression
            method_name = None
            for sub in method_call.children:
                if sub.type == "name_expression":
                    for subsub in sub.children:
                        if subsub.type == "module_access":
                            for ident in subsub.children:
                                if ident.type == "identifier":
                                    method_name = _extract_text(source_code, ident.start_byte, ident.end_byte).strip()
                                    break

            if method_name:
                # Known TxContext methods (from sui-framework tx_context.move)
                TXCONTEXT_METHODS = {
                    "sender",
                    "digest",
                    "epoch",
                    "epoch_timestamp_ms",
                    "sponsor",
                    "fresh_object_address",
                    "reference_gas_price",
                    "gas_price",
                }

                # Construct callee name based on whether it's a TxContext method
                if method_name in TXCONTEXT_METHODS:
                    # For TxContext methods, use tx_context:: prefix
                    # This will be matched against TXCONTEXT_USAGE_FUNCTIONS
                    callee_name = f"tx_context::{method_name}"
                else:
                    # For other method calls, use module_path like regular calls
                    callee_name = f"{module_path}::{method_name}" if module_path else method_name

                # Parse arguments
                args = []
                for sub in method_call.children:
                    if sub.type == "arg_list":
                        args = _parse_call_arguments(sub, source_code, import_map)
                        break

                # Add the receiver as first argument (implicit self)
                receiver_args = [(0, base_var)] + [(idx + 1, arg) for idx, arg in args]
                calls.append((callee_name, node.start_byte, receiver_args, None, base_var))

    elif node.type == "call_expression":
        # Skip if this call_expression is part of a dot_expression (method call)
        # It will be handled by the dot_expression case above
        if node.parent and node.parent.type == "dot_expression":
            return

        callee_name = None
        args = []
        emitted_event_type = None
        type_args = []
        call_pos = node.start_byte

        for child in node.children:
            if child.type == "name_expression":
                type_args = _extract_type_arguments(child, source_code, import_map, module_path)
                for subchild in child.children:
                    if subchild.type == "module_access":
                        name_parts = []
                        for name_child in subchild.children:
                            if name_child.type == "identifier":
                                name_parts.append(
                                    _extract_text(source_code, name_child.start_byte, name_child.end_byte).strip()
                                )
                            elif name_child.type == "module_identifier":
                                name_parts.append(
                                    _extract_text(source_code, name_child.start_byte, name_child.end_byte).strip()
                                )
                            elif name_child.type == "module_identity":
                                mod_parts = []
                                for mod_child in name_child.children:
                                    if mod_child.type == "module_identifier":
                                        mod_parts.append(
                                            _extract_text(source_code, mod_child.start_byte, mod_child.end_byte).strip()
                                        )
                                if mod_parts:
                                    name_parts.append("::".join(mod_parts))
                        if name_parts:
                            if len(name_parts) == 1:
                                if "::" not in name_parts[0]:
                                    callee_name = f"{module_path}::{name_parts[0]}"
                                else:
                                    callee_name = name_parts[0]
                            else:
                                callee_name = "::".join(name_parts)
                            if callee_name:
                                callee_name = _replace_import_alias(callee_name, import_map)
                        break

        arg_list_node = None
        for child in node.children:
            if child.type == "arg_list":
                arg_list_node = child
                args = _parse_call_arguments(child, source_code, import_map)
                break

        if callee_name:
            callee_simple = get_simple_name(callee_name)
            if callee_simple == "emit" and ("event::" in callee_name or callee_name.endswith("::emit")):
                # Try 1: Direct pack expression in arg list - emit(MyEvent { ... })
                if arg_list_node:
                    emitted_event_type = _extract_pack_struct_name(arg_list_node, source_code, import_map, module_path)
                # Try 2: Type argument - emit<MyEvent>(value)
                if not emitted_event_type and type_args:
                    emitted_event_type = type_args[0]
                # Try 3: Variable from pack binding - let e = MyEvent { ... }; emit(e)
                # Find the nearest preceding binding for this variable
                if not emitted_event_type and pack_bindings and args:
                    first_arg_name = args[0][1] if args else None
                    if first_arg_name and first_arg_name in pack_bindings:
                        # Find nearest binding that precedes this call
                        nearest_type = None
                        nearest_pos = -1
                        for bind_pos, bind_type in pack_bindings[first_arg_name]:
                            if bind_pos < call_pos and bind_pos > nearest_pos:
                                nearest_pos = bind_pos
                                nearest_type = bind_type
                        if nearest_type:
                            emitted_event_type = nearest_type

        if callee_name:
            calls.append((callee_name, node.start_byte, args, emitted_event_type, None))


def _collect_field_accesses(node, source_code: str, field_accesses: list) -> None:
    """
    Collect all field accesses (base_var, field_path, code_snippet, byte_pos).

    Filtering by param type is done later in parse.py.
    """

    def _extract_name(n) -> Optional[str]:
        """Extract identifier from name_expression."""
        if n.type == "name_expression":
            for child in n.children:
                if child.type == "module_access":
                    for subchild in child.children:
                        if subchild.type == "identifier":
                            return _extract_text(source_code, subchild.start_byte, subchild.end_byte).strip()
        return None

    def _get_field_chain(n) -> Optional[Tuple[str, str]]:
        """
        Extract (base_var, field_path) from a field access chain.
        E.g., pool.config.fee -> ("pool", "config.fee")
        """
        if n.type == "dot_expression":
            # dot_expression: base_expr, ".", field_name_expr
            parts = [c for c in n.children if c.type != "."]
            if len(parts) == 2:
                base_node, field_node = parts
                field_name = _extract_name(field_node)
                if not field_name:
                    return None

                if base_node.type == "name_expression":
                    base_var = _extract_name(base_node)
                    if base_var:
                        return (base_var, field_name)
                elif base_node.type == "dot_expression":
                    result = _get_field_chain(base_node)
                    if result:
                        base_var, inner_path = result
                        return (base_var, f"{inner_path}.{field_name}")
        return None

    if node.type == "dot_expression":
        result = _get_field_chain(node)
        if result:
            base_var, field_path = result
            line_start = source_code.rfind("\n", 0, node.start_byte) + 1
            line_end = source_code.find("\n", node.end_byte)
            if line_end == -1:
                line_end = len(source_code)
            code_snippet = source_code[line_start:line_end].strip()
            field_accesses.append((base_var, field_path, code_snippet, node.start_byte))


def _collect_destructuring_accesses(node, source_code: str, destructure_accesses: list) -> None:
    """
    Collect field accesses from destructuring patterns.

    Pattern: let StructType { field1, field2, .. } = var;
    Collects: (base_var, field_name, code_snippet, byte_pos) for each field

    Filtering by param type is done later in parse.py.
    """
    if node.type != "let_statement":
        return

    # Find bind_unpack (destructuring pattern)
    bind_unpack = None
    rhs_var = None

    for child in node.children:
        if child.type == "bind_list":
            for subchild in child.children:
                if subchild.type == "bind_unpack":
                    bind_unpack = subchild
        elif child.type == "name_expression":
            # RHS variable being destructured
            for subchild in child.children:
                if subchild.type == "module_access":
                    for id_node in subchild.children:
                        if id_node.type == "identifier":
                            rhs_var = _extract_text(source_code, id_node.start_byte, id_node.end_byte).strip()

    if not bind_unpack or not rhs_var:
        return

    # Extract field names with their positions from bind_unpack
    field_entries = []  # [(field_name, field_pos)]
    for child in bind_unpack.children:
        if child.type == "bind_fields":
            for fields_child in child.children:
                if fields_child.type == "bind_named_fields":
                    for field_node in fields_child.children:
                        if field_node.type == "bind_field":
                            for bind_child in field_node.children:
                                if bind_child.type == "bind_list":
                                    for var_child in bind_child.children:
                                        if var_child.type == "bind_var":
                                            for id_node in var_child.children:
                                                if id_node.type == "variable_identifier":
                                                    field_name = _extract_text(
                                                        source_code, id_node.start_byte, id_node.end_byte
                                                    ).strip()
                                                    # Use field's position for unique key
                                                    field_entries.append((field_name, id_node.start_byte))

    if not field_entries:
        return

    # Create field accesses for each destructured field
    line_start = source_code.rfind("\n", 0, node.start_byte) + 1
    line_end = source_code.find("\n", node.end_byte)
    if line_end == -1:
        line_end = len(source_code)
    code_snippet = source_code[line_start:line_end].strip()

    for field_name, field_pos in field_entries:
        destructure_accesses.append((rhs_var, field_name, code_snippet, field_pos))


def _collect_pack_expressions(
    node, source_code: str, pack_exprs: list, import_map: dict[str, str], module_path: str
) -> None:
    """
    Collect all pack expressions (struct instantiations).

    Collects: (struct_name, byte_pos) for each pack expression.
    Used to generate PacksStruct facts for structural role detection.
    """
    if node.type == "pack_expression":
        struct_name = None
        for child in node.children:
            if child.type == "name_expression":
                for subchild in child.children:
                    if subchild.type == "module_access":
                        name_parts = []
                        for name_child in subchild.children:
                            if name_child.type == "identifier":
                                name_parts.append(
                                    _extract_text(source_code, name_child.start_byte, name_child.end_byte).strip()
                                )
                            elif name_child.type == "module_identifier":
                                name_parts.append(
                                    _extract_text(source_code, name_child.start_byte, name_child.end_byte).strip()
                                )
                            elif name_child.type == "module_identity":
                                mod_parts = []
                                for mod_child in name_child.children:
                                    if mod_child.type == "module_identifier":
                                        mod_parts.append(
                                            _extract_text(source_code, mod_child.start_byte, mod_child.end_byte).strip()
                                        )
                                if mod_parts:
                                    name_parts.append("::".join(mod_parts))
                        if name_parts:
                            struct_name = "::".join(name_parts) if len(name_parts) > 1 else name_parts[0]
                            struct_name = _replace_import_alias(struct_name, import_map)
                            if "::" not in struct_name and module_path:
                                struct_name = f"{module_path}::{struct_name}"
                        break
                break

        if struct_name:
            pack_exprs.append((struct_name, node.start_byte))
