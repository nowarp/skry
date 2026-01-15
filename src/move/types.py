"""
Centralized Move type manipulation utilities.

Type string operations used across the codebase for:
- Stripping reference modifiers (&, &mut)
- Stripping generic parameters (<T>)
- Extracting base type names
- FQN handling
"""


def strip_references(type_str: str) -> str:
    """
    Strip reference modifiers from type string.

    Examples:
        "&mut Pool" -> "Pool"
        "&Pool" -> "Pool"
        "Pool" -> "Pool"
    """
    if type_str.startswith("&mut "):
        return type_str[5:].strip()
    elif type_str.startswith("&"):
        return type_str[1:].strip()
    return type_str.strip()


def strip_generics(type_str: str) -> str:
    """
    Strip generic parameters from type string with proper bracket matching.

    Handles nested generics correctly.

    Examples:
        "Pool<T>" -> "Pool"
        "Map<Key, Vec<Value>>" -> "Map"
        "module::Type<T>" -> "module::Type"
    """
    if "<" not in type_str:
        return type_str

    # Find first '<' and extract everything before it
    idx = type_str.index("<")
    return type_str[:idx].strip()


def get_simple_name(fqn: str) -> str:
    """
    Extract simple name from FQN.

    Examples:
        "module::path::Type" -> "Type"
        "Type" -> "Type"
    """
    if "::" in fqn:
        return fqn.split("::")[-1]
    return fqn


def extract_base_type(type_str: str, keep_fqn: bool = False) -> str:
    """
    Extract base type name from type string.

    Strips:
    - Reference modifiers (&, &mut)
    - Generic parameters (<T>)
    - Optionally: module path (if keep_fqn=False)

    Args:
        type_str: Type string (e.g., "&mut module::Pool<T>")
        keep_fqn: If True, preserve module path; if False, return simple name

    Examples:
        extract_base_type("&mut Pool<T>") -> "Pool"
        extract_base_type("&module::Pool<T>") -> "Pool"
        extract_base_type("&module::Pool<T>", keep_fqn=True) -> "module::Pool"
    """
    result = strip_references(type_str)
    result = strip_generics(result)

    if not keep_fqn:
        result = get_simple_name(result)

    return result.strip()


def get_module_path(fqn: str) -> str:
    """
    Extract module path from FQN.

    Examples:
        "test::module::Type" -> "test::module"
        "test::module::func" -> "test::module"
        "Type" -> ""
    """
    if "::" not in fqn:
        return ""
    return "::".join(fqn.split("::")[:-1])


def qualify_type(simple_name: str, module_path: str) -> str:
    """
    Qualify a simple type name with module path.

    Only qualifies if not already qualified and looks like a type name.

    Args:
        simple_name: Type name (e.g., "Pool")
        module_path: Module path (e.g., "protocol::pool")

    Returns:
        Qualified name (e.g., "protocol::pool::Pool")
    """
    # Already qualified
    if "::" in simple_name:
        return simple_name

    # Doesn't look like a type name (not capitalized)
    if not simple_name or not simple_name[0].isupper():
        return simple_name

    return f"{module_path}::{simple_name}"


def extract_tuple_elements(type_str: str) -> list[str]:
    """
    Extract individual type elements from a tuple type string.

    Handles nested generics correctly by tracking bracket depth.

    Examples:
        "(Type1, Type2)" -> ["Type1", "Type2"]
        "(A, B<C>, D)" -> ["A", "B<C>", "D"]
        "NotATuple" -> ["NotATuple"]
        "(vector<Item>, u64)" -> ["vector<Item>", "u64"]
    """
    type_str = type_str.strip()

    # Not a tuple
    if not type_str.startswith("("):
        return [type_str]

    # Remove outer parens
    inner = type_str[1:]
    if inner.endswith(")"):
        inner = inner[:-1]

    # Split by comma, respecting nested generics
    elements = []
    current: list[str] = []
    depth = 0

    for char in inner:
        if char == "<":
            depth += 1
            current.append(char)
        elif char == ">":
            depth -= 1
            current.append(char)
        elif char == "," and depth == 0:
            elements.append("".join(current).strip())
            current = []
        else:
            current.append(char)

    if current:
        elements.append("".join(current).strip())

    return [e for e in elements if e]


def extract_generic_args(type_str: str) -> list[str]:
    """
    Extract type arguments from a generic type.

    Examples:
        "vector<Item>" -> ["Item"]
        "Map<Key, Value>" -> ["Key", "Value"]
        "Option<Vec<Item>>" -> ["Vec<Item>"]
        "SimpleType" -> []
    """
    type_str = type_str.strip()

    if "<" not in type_str:
        return []

    start = type_str.index("<")
    # Find matching closing bracket
    depth = 0
    end = -1
    for i in range(start, len(type_str)):
        if type_str[i] == "<":
            depth += 1
        elif type_str[i] == ">":
            depth -= 1
            if depth == 0:
                end = i
                break

    if end == -1:
        return []

    inner = type_str[start + 1 : end]

    # Split by comma at depth 0
    elements = []
    current: list[str] = []
    depth = 0

    for char in inner:
        if char == "<":
            depth += 1
            current.append(char)
        elif char == ">":
            depth -= 1
            current.append(char)
        elif char == "," and depth == 0:
            elements.append("".join(current).strip())
            current = []
        else:
            current.append(char)

    if current:
        elements.append("".join(current).strip())

    return [e for e in elements if e]


def extract_all_types(type_str: str) -> list[str]:
    """
    Extract all types from a type string, including nested types.

    Handles tuples, generics, and references. Returns all types found.

    Examples:
        "vector<Item>" -> ["vector", "Item"]
        "(A, B<C>)" -> ["A", "B", "C"]
        "&mut Option<Type>" -> ["Option", "Type"]
    """
    type_str = type_str.strip()

    # Strip references
    if type_str.startswith("&mut "):
        type_str = type_str[5:]
    elif type_str.startswith("&"):
        type_str = type_str[1:]
    type_str = type_str.strip()

    result: list[str] = []

    # Handle tuples
    for elem in extract_tuple_elements(type_str):
        # Get base type (before <)
        base = strip_generics(elem)
        if base:
            result.append(strip_references(base))

        # Recursively extract from generic args
        for arg in extract_generic_args(elem):
            result.extend(extract_all_types(arg))

    return result
