"""
Source code extraction utilities for Move.

Contains:
- Function source extraction
- Struct source extraction
- Function docstring extraction
- Argument type extraction and checking
"""

from typing import Optional, Set

from core.utils import error, get_simple_name
from move.utils import _extract_text


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


def is_reference_type(typ: str) -> bool:
    """Check if type is a reference (&T or &mut T).

    Reference params represent object access, not user-provided data.
    They should NOT be taint sources for value-based attacks.
    """
    typ = typ.strip()
    return typ.startswith("&mut ") or typ.startswith("&")


def get_simple_type_name(type_str: str) -> str:
    """
    Extract simple type name from a full type string.

    Strips: reference modifiers (&mut, &), generics (<T>), module path (foo::bar::).

    Examples:
        "&mut Pool" -> "Pool"
        "Coin<SUI>" -> "Coin"
        "foo::bar::Vault<T>" -> "Vault"
        "&Balance<SUI>" -> "Balance"
    """
    # Strip reference modifiers
    type_str = strip_ref_modifiers(type_str)

    # Strip generics
    if "<" in type_str:
        type_str = type_str[: type_str.index("<")]

    return get_simple_name(type_str).strip()


def resolve_to_fqn(
    name: str,
    fqn_set: Set[str],
    module_path: str | None = None,
    import_map: dict[str, str] | None = None,
) -> str | None:
    """
    Resolve name to matching FQN from set.

    Resolution order:
    1. Exact FQN match
    2. Import map resolution
    3. Same-module match (module_path::name)

    Args:
        name: Name to resolve (may be simple or FQN)
        fqn_set: Set of fully-qualified names to match against
        module_path: Current module path for same-module resolution
        import_map: Import alias -> FQN mapping

    Returns matched FQN or None if no match.
    """
    # Exact match
    if name in fqn_set:
        return name

    simple = get_simple_name(name)

    # Import map resolution
    if import_map and simple in import_map:
        resolved = import_map[simple]
        if resolved in fqn_set:
            return resolved

    # Same-module match
    if module_path:
        qualified = f"{module_path}::{simple}"
        if qualified in fqn_set:
            return qualified

    return None


def extract_function_source(source_code: str, func_name: str, root) -> Optional[str]:
    """
    Extract the source code of a function by name.

    Args:
        source_code: The full source code
        func_name: Name of the function to extract (may be fully-qualified)
        root: tree-sitter root node

    Returns:
        Function source code as string, or None if not found
    """
    try:
        simple_func_name = get_simple_name(func_name)

        func_def_node = None

        def find_func_def(node):
            nonlocal func_def_node
            if node.type == "function_definition":
                for child in node.children:
                    if child.type == "function_identifier":
                        found_name = _extract_text(source_code, child.start_byte, child.end_byte)
                        if found_name == simple_func_name:
                            func_def_node = node
                            return

            for child in node.children:
                find_func_def(child)
                if func_def_node:
                    return

        find_func_def(root)

        if not func_def_node:
            return None

        return _extract_text(source_code, func_def_node.start_byte, func_def_node.end_byte)

    except Exception as e:
        error(f"extracting function source: {e}")
        return None


def extract_function_docstring(source_code: str, func_name: str, root) -> Optional[str]:
    """
    Extract docstring/comments preceding a function.

    Args:
        source_code: The full source code
        func_name: Name of the function (may be fully-qualified)
        root: tree-sitter root node

    Returns:
        Docstring as string, or None if not found
    """
    try:
        simple_func_name = get_simple_name(func_name)

        func_def_node = None

        def find_func_def(node):
            nonlocal func_def_node
            if node.type == "function_definition":
                for child in node.children:
                    if child.type == "function_identifier":
                        found_name = _extract_text(source_code, child.start_byte, child.end_byte)
                        if found_name == simple_func_name:
                            func_def_node = node
                            return
            for child in node.children:
                find_func_def(child)
                if func_def_node:
                    return

        find_func_def(root)

        if not func_def_node:
            return None

        comments = []
        prev = func_def_node.prev_sibling

        while prev is not None:
            if prev.type in ("line_comment", "comment"):
                comment_text = _extract_text(source_code, prev.start_byte, prev.end_byte).strip()
                comments.insert(0, comment_text)
            elif prev.type == "block_comment":
                comment_text = _extract_text(source_code, prev.start_byte, prev.end_byte).strip()
                comments.insert(0, comment_text)
            elif prev.type in ("newline",):
                pass
            elif prev.type == "annotation":
                pass
            else:
                break
            prev = prev.prev_sibling

        if not comments:
            return None

        return "\n".join(comments)

    except Exception as e:
        error(f"extracting function docstring: {e}")
        return None


def extract_function_signature(source_code: str, func_name: str, root) -> Optional[str]:
    """
    Extract function signature (header only, no body) with preceding docstring.

    Args:
        source_code: The full source code
        func_name: Name of the function (may be fully-qualified)
        root: tree-sitter root node

    Returns:
        Function signature as string (docstring + header), or None if not found
    """
    try:
        simple_func_name = get_simple_name(func_name)

        func_def_node = None

        def find_func_def(node):
            nonlocal func_def_node
            if node.type == "function_definition":
                for child in node.children:
                    if child.type == "function_identifier":
                        found_name = _extract_text(source_code, child.start_byte, child.end_byte)
                        if found_name == simple_func_name:
                            func_def_node = node
                            return
            for child in node.children:
                find_func_def(child)
                if func_def_node:
                    return

        find_func_def(root)

        if not func_def_node:
            return None

        # Find the opening brace to get just the signature
        sig_end = func_def_node.end_byte
        for child in func_def_node.children:
            if child.type == "block" or child.type == "{":
                sig_end = child.start_byte
                break

        signature = _extract_text(source_code, func_def_node.start_byte, sig_end).strip()

        # Get docstring
        docstring = extract_function_docstring(source_code, func_name, root)
        if docstring:
            return f"{docstring}\n{signature}"

        return signature

    except Exception as e:
        error(f"extracting function signature: {e}")
        return None


def extract_struct_source(source_code: str, struct_name: str, root) -> Optional[str]:
    """
    Extract the source code of a struct by name.

    Args:
        source_code: The full source code
        struct_name: Name of the struct to extract (may be fully-qualified)
        root: tree-sitter root node

    Returns:
        Struct source code as string, or None if not found
    """
    try:
        simple_struct_name = get_simple_name(struct_name)

        struct_def_node = None

        def find_struct_def(node):
            nonlocal struct_def_node
            if node.type == "struct_definition":
                for child in node.children:
                    if child.type == "struct_identifier":
                        found_name = _extract_text(source_code, child.start_byte, child.end_byte)
                        if found_name == simple_struct_name:
                            struct_def_node = node
                            return

            for child in node.children:
                find_struct_def(child)
                if struct_def_node:
                    return

        find_struct_def(root)

        if not struct_def_node:
            return None

        return _extract_text(source_code, struct_def_node.start_byte, struct_def_node.end_byte)

    except Exception as e:
        error(f"extracting struct source: {e}")
        return None
