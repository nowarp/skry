"""
Move import/alias resolution.

Contains:
- Module declaration parsing
- Use statement parsing
- Import alias resolution
"""

from typing import Optional

from core.utils import get_simple_name
from move.utils import _extract_text


def _parse_module_declaration(source_code: str, root) -> Optional[str]:
    """Parse module declaration and return the fully qualified module path, or None if not found."""
    module_path: Optional[str] = None

    def traverse_module(node):
        nonlocal module_path
        if node.type == "module_definition":
            for child in node.children:
                if child.type == "module_identity":
                    path_parts = []
                    for subchild in child.children:
                        if subchild.type == "module_identifier":
                            path_parts.append(_extract_text(source_code, subchild.start_byte, subchild.end_byte))
                    if path_parts:
                        module_path = "::".join(path_parts)
                        return

        for child in node.children:
            traverse_module(child)

    traverse_module(root)
    return module_path


def _parse_imports(source_code: str, root) -> dict[str, str]:
    """Parse use statements and build a mapping from aliases to fully qualified paths."""
    import_map: dict[str, str] = {}

    def traverse_imports(node):
        if node.type == "use_declaration":
            base_path: Optional[str] = None

            for child in node.children:
                if child.type in ("use_module", "use_module_members", "use_module_member"):
                    for subchild in child.children:
                        if subchild.type == "module_identity":
                            parts: list[str] = []
                            for mi_child in subchild.children:
                                if mi_child.type == "module_identifier":
                                    parts.append(_extract_text(source_code, mi_child.start_byte, mi_child.end_byte))
                            if parts:
                                base_path = "::".join(parts)

                    if child.type == "use_module" and base_path:
                        alias = get_simple_name(base_path)
                        import_map[alias] = base_path

                    elif child.type in ("use_module_members", "use_module_member") and base_path:
                        for member in child.children:
                            if member.type != "use_member":
                                continue

                            member_name: Optional[str] = None
                            alias: Optional[str] = None
                            seen_as = False

                            for m_child in member.children:
                                if m_child.type == "as":
                                    seen_as = True
                                elif m_child.type == "identifier":
                                    text = _extract_text(source_code, m_child.start_byte, m_child.end_byte).strip()
                                    if seen_as:
                                        alias = text
                                    elif member_name is None:
                                        member_name = text

                            if not member_name:
                                continue

                            if member_name in ("Self", "self"):
                                if alias:
                                    import_map[alias] = base_path
                                else:
                                    module_name = get_simple_name(base_path)
                                    import_map[module_name] = base_path
                            else:
                                target_alias = alias or member_name
                                import_map[target_alias] = f"{base_path}::{member_name}"

        for child in node.children:
            traverse_imports(child)

    traverse_imports(root)
    return import_map


def _replace_import_alias(name: str, import_map: dict[str, str]) -> str:
    """Replace import aliases in a qualified name with their fully qualified paths."""
    if not import_map or not name:
        return name

    # Extract generic suffix if present: "TreasuryCap<COIN>" -> ("TreasuryCap", "<COIN>")
    generic_suffix = ""
    base_name = name
    if "<" in name:
        idx = name.index("<")
        base_name = name[:idx]
        generic_suffix = name[idx:]

    if "::" in base_name:
        first_part = base_name.split("::")[0]
        if first_part in import_map:
            resolved = import_map[first_part] + base_name[len(first_part) :]
            return resolved + generic_suffix
    elif base_name in import_map:
        return import_map[base_name] + generic_suffix

    return name
