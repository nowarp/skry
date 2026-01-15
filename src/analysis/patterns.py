"""
Pattern detection: self-recursion, same-module, struct instantiations, asset creation.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional

from core.context import ProjectContext
from core.facts import Fact
from core.utils import debug, get_module_path, get_simple_name
from move.sui_patterns import (
    SUI_CAPABILITY_RETURNING_FUNCTIONS,
    detect_transfer_patterns,
    is_stdlib_freeze_call,
    is_stdlib_sender_call,
    is_stdlib_share_call,
    is_stdlib_transfer_call,
)


@dataclass
class CreationSite:
    """Information about where a struct is created."""

    func_name: str  # e.g., "mod::init", "mod::create_cap"
    is_init: bool  # Function has IsInit fact or called from init
    transferred_to: str  # "sender" | "param" | "none"
    shared: bool  # share_object called
    frozen: bool  # freeze_object called
    called_from_init: Optional[str] = None  # Name of init that calls this (if transitive)


def detect_self_recursive_calls(ctx: ProjectContext) -> None:
    """
    Detect self-recursive function calls.
    Pattern: Function f contains a call to itself (direct recursion).
    """
    recursive_count = 0

    for source_file in ctx.source_files.values():
        func_calls: dict[str, set[str]] = {}

        # Collect method call IDs for quick lookup
        method_calls: set[str] = set()
        for fact in source_file.facts:
            if fact.name == "IsMethodCall":
                method_calls.add(fact.args[0])

        for fact in source_file.facts:
            if fact.name == "InFun" and "@" in fact.args[1]:
                func_name = fact.args[0]
                call_id = fact.args[1]

                # Skip method calls - they cannot be self-recursive
                if call_id in method_calls:
                    continue

                callee = call_id.split("@")[0]
                if func_name not in func_calls:
                    func_calls[func_name] = set()
                func_calls[func_name].add(callee)

        for func_name, callees in func_calls.items():
            func_simple = get_simple_name(func_name)

            for callee in callees:
                is_self_call = callee == func_name

                if not is_self_call:
                    callee_has_module = "::" in callee
                    if not callee_has_module:
                        if callee == func_simple:
                            is_self_call = True

                if is_self_call:
                    recursive_fact = Fact("SelfRecursive", (func_name,))
                    if not any(f.name == "SelfRecursive" and f.args[0] == func_name for f in source_file.facts):
                        source_file.facts.append(recursive_fact)
                        recursive_count += 1
                        debug(f"  SelfRecursive({func_name}) [calls itself]")

                        if func_name in ctx.global_facts_index:
                            for file_path, func_facts in ctx.global_facts_index[func_name].items():
                                if not any(f.name == "SelfRecursive" and f.args[0] == func_name for f in func_facts):
                                    func_facts.append(recursive_fact)
                    break

    if recursive_count > 0:
        debug(f"Generated {recursive_count} SelfRecursive facts")


def generate_same_module_facts(ctx: ProjectContext) -> None:
    """
    Generate SameModule facts.
    Only generates for public/entry functions.
    """
    func_to_file: Dict[str, str] = {}
    module_funcs: Dict[str, List[str]] = {}

    for file_path, file_ctx in ctx.source_files.items():
        public_funcs: Set[str] = set()
        entry_funcs: Set[str] = set()

        for fact in file_ctx.facts:
            if fact.name == "IsPublic":
                public_funcs.add(fact.args[0])
            elif fact.name == "IsEntry":
                entry_funcs.add(fact.args[0])

        for fact in file_ctx.facts:
            if fact.name == "Fun":
                func_name = fact.args[0]
                func_to_file[func_name] = file_path

                if func_name not in public_funcs and func_name not in entry_funcs:
                    continue

                parts = func_name.rsplit("::", 1)
                if len(parts) == 2:
                    module = parts[0]
                    if module not in module_funcs:
                        module_funcs[module] = []
                    module_funcs[module].append(func_name)

    same_module_count = 0
    for module, funcs in module_funcs.items():
        if len(funcs) < 2:
            continue

        for i, f1 in enumerate(funcs):
            for f2 in funcs[i + 1 :]:
                fact1 = Fact("SameModule", (f1, f2))
                fact2 = Fact("SameModule", (f2, f1))

                files_to_update: Set[str] = set()
                if f1 in func_to_file:
                    files_to_update.add(func_to_file[f1])
                if f2 in func_to_file:
                    files_to_update.add(func_to_file[f2])

                for file_path in files_to_update:
                    file_ctx = ctx.source_files[file_path]
                    file_ctx.facts.append(fact1)
                    file_ctx.facts.append(fact2)
                    same_module_count += 2

    if same_module_count > 0:
        debug(f"Generated {same_module_count} SameModule facts")


def find_struct_instantiations(source_code: str, root, target_structs: Set[str]) -> List[Tuple[str, str]]:
    """
    Find struct instantiations (pack expressions) in source code.
    Returns list of (func_name, struct_name) tuples.
    """
    from move.imports import _parse_module_declaration

    module_path = _parse_module_declaration(source_code, root)
    results: List[Tuple[str, str]] = []
    current_function: Optional[str] = None

    def qualify_name(name: str) -> str:
        if "::" in name:
            return name
        if module_path:
            return f"{module_path}::{name}"
        return name

    def extract_struct_name_from_pack(node) -> Optional[str]:
        for child in node.children:
            if child.type == "name_expression":
                for subchild in child.children:
                    if subchild.type == "module_access":
                        name_parts = []
                        for name_child in subchild.children:
                            if name_child.type == "identifier":
                                name_parts.append(source_code[name_child.start_byte : name_child.end_byte])
                            elif name_child.type in ("module_identifier", "module_identity"):
                                # module_identity for FQN like test::module_a::Factory
                                # module_identifier for simple module::Struct
                                name_parts.append(source_code[name_child.start_byte : name_child.end_byte])
                        if name_parts:
                            return "::".join(name_parts)
        return None

    def traverse(node):
        nonlocal current_function

        if node.type == "function_definition":
            for child in node.children:
                if child.type == "function_identifier":
                    func_name = source_code[child.start_byte : child.end_byte]
                    current_function = qualify_name(func_name)
                    break

            for child in node.children:
                traverse(child)

            current_function = None
            return

        if node.type == "pack_expression" and current_function:
            struct_name = extract_struct_name_from_pack(node)
            if struct_name:
                qualified_struct = qualify_name(struct_name)
                simple_struct_name = get_simple_name(struct_name)
                for target in target_structs:
                    # Priority 1: Exact FQN match
                    if qualified_struct == target:
                        results.append((current_function, target))
                        break
                    # Priority 2: Simple name match ONLY if same module
                    # (pack uses unqualified name like `Factory` in module that defines it)
                    simple_target = get_simple_name(target)
                    target_module = get_module_path(target)
                    if simple_struct_name == simple_target and module_path == target_module:
                        results.append((current_function, target))
                        break

        for child in node.children:
            traverse(child)

    traverse(root)
    return results


# =============================================================================
# SHARED OBJECT DETECTION
# =============================================================================


def build_shared_object_facts(ctx: ProjectContext) -> None:
    """
    Detect structs that are shared via transfer::share_object.

    Looks for patterns like:
        1. Direct instantiation: let pool = Pool { id: object::new(ctx), ... }; transfer::share_object(pool);
        2. Cross-module: let cap = module::create_admin_cap(ctx); transfer::share_object(cap);

    Generates IsSharedObject(struct_name) facts in the file where the struct is DEFINED.
    """
    # Build return type index: func_name -> return_type
    return_types: Dict[str, str] = {}
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "FunReturnType":
                func_name, return_type = fact.args
                return_types[func_name] = return_type

    # Collect all shared types (FQNs) from all files
    all_shared: Set[str] = set()

    for file_path, file_ctx in ctx.source_files.items():
        if file_ctx.is_test_only or file_ctx.source_code is None:
            continue

        file_shared = _find_shared_objects_in_file(
            file_ctx.source_code, file_ctx.root, return_types, file_ctx.import_map, file_ctx.module_path
        )
        all_shared.update(file_shared)

    # Also derive from SharesObject facts (AST detection may miss generic pack expressions)
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "SharesObject":
                struct_type = fact.args[1]
                all_shared.add(struct_type)

    if not all_shared:
        debug("No shared objects detected")
        return

    debug(f"Detected {len(all_shared)} shared object types: {all_shared}")

    # Add IsSharedObject fact to the file where each struct is DEFINED
    for file_path, file_ctx in ctx.source_files.items():
        if file_ctx.is_test_only:
            continue

        for struct_fqn in all_shared:
            # Check if this file defines this struct (exact FQN match)
            for fact in file_ctx.facts:
                if fact.name == "Struct" and fact.args[0] == struct_fqn:
                    # This file defines the shared struct - add IsSharedObject fact
                    already_has = any(f.name == "IsSharedObject" and f.args[0] == struct_fqn for f in file_ctx.facts)
                    if not already_has:
                        file_ctx.facts.append(Fact("IsSharedObject", (struct_fqn,)))
                        debug(f"  IsSharedObject({struct_fqn}) in {Path(file_path).name}")


def _find_shared_objects_in_file(
    source_code: str,
    root,
    return_types: Dict[str, str],
    import_map: Dict[str, str],
    module_path: Optional[str],
) -> Set[str]:
    """
    Find struct types passed to share_object calls in a file.

    Strategy:
    1. Find all share_object(var) calls
    2. Track var assignments backwards to find struct instantiation OR function call
    3. Extract struct type from pack_expression OR function return type (FunReturnType fact)

    Args:
        source_code: Source code of the file
        root: Tree-sitter root node
        return_types: Mapping of func_name -> return_type from FunReturnType facts
        import_map: Mapping of alias -> FQN for imports
        module_path: Fully qualified module path for the current file
    """
    from move.imports import _replace_import_alias

    shared_types: Set[str] = set()

    # Track: var_name -> struct_type (from pack expressions OR function returns)
    var_to_type: Dict[str, str] = {}

    def qualify_name(name: str) -> str:
        """
        Qualify a name (struct or function) to FQN.
        1. Resolve through import_map (handles aliases like `cap_module::create_admin_cap`)
        2. If no :: and we have module_path, add it
        """
        resolved = _replace_import_alias(name, import_map)
        if "::" not in resolved and module_path:
            return f"{module_path}::{resolved}"
        return resolved

    def extract_struct_name_from_pack(node) -> Optional[str]:
        """Extract struct name from pack_expression."""
        for child in node.children:
            if child.type == "name_expression":
                for subchild in child.children:
                    if subchild.type == "module_access":
                        name_parts = []
                        for name_child in subchild.children:
                            if name_child.type == "identifier":
                                name_parts.append(source_code[name_child.start_byte : name_child.end_byte])
                            elif name_child.type == "module_identifier":
                                name_parts.append(source_code[name_child.start_byte : name_child.end_byte])
                        if name_parts:
                            return "::".join(name_parts)
                    elif subchild.type == "identifier":
                        return source_code[subchild.start_byte : subchild.end_byte]
        return None

    def extract_callee(node) -> Optional[str]:
        """Extract callee name from call_expression."""
        for child in node.children:
            if child.type == "name_expression":
                for subchild in child.children:
                    if subchild.type == "module_access":
                        # Handle both simple (module::func) and complex (pkg::module::func)
                        parts = []
                        for name_child in subchild.children:
                            if name_child.type == "identifier":
                                parts.append(source_code[name_child.start_byte : name_child.end_byte])
                            elif name_child.type == "module_identifier":
                                parts.append(source_code[name_child.start_byte : name_child.end_byte])
                            elif name_child.type == "module_identity":
                                # sui::transfer style - collect all identifiers
                                for id_child in name_child.children:
                                    if id_child.type == "module_identifier":
                                        parts.append(source_code[id_child.start_byte : id_child.end_byte])
                        if parts:
                            return "::".join(parts)
        return None

    def extract_call_args(node) -> List[str]:
        """Extract argument names from call_expression."""
        args = []
        for child in node.children:
            # arg_list is the actual node type in tree-sitter-move
            if child.type == "arg_list":
                for arg_child in child.children:
                    if arg_child.type == "name_expression":
                        for subchild in arg_child.children:
                            if subchild.type == "module_access":
                                # Simple identifier: module_access -> identifier
                                for id_child in subchild.children:
                                    if id_child.type == "identifier":
                                        args.append(source_code[id_child.start_byte : id_child.end_byte])
                                        break
        return args

    def extract_let_binding(node) -> Optional[str]:
        """Extract variable name from let_statement."""
        for child in node.children:
            if child.type == "bind_list":
                for bind_child in child.children:
                    if bind_child.type == "bind_var":
                        for var_child in bind_child.children:
                            if var_child.type == "variable_identifier":
                                return source_code[var_child.start_byte : var_child.end_byte]
                    elif bind_child.type == "variable_identifier":
                        return source_code[bind_child.start_byte : bind_child.end_byte]
        return None

    def find_pack_expression(node):
        """Recursively find pack_expression in a node."""
        if node.type == "pack_expression":
            return node
        for child in node.children:
            result = find_pack_expression(child)
            if result:
                return result
        return None

    def find_call_expression(node):
        """Recursively find call_expression in a node."""
        if node.type == "call_expression":
            return node
        for child in node.children:
            result = find_call_expression(child)
            if result:
                return result
        return None

    def traverse(node):
        nonlocal var_to_type

        if node.type == "function_definition":
            # Reset var tracking per function
            var_to_type = {}
            for child in node.children:
                traverse(child)
            return

        # Track let var = StructName { ... } OR let var = module::create_func()
        # AST: let_statement, not let_expression
        if node.type == "let_statement":
            var_name = extract_let_binding(node)
            if var_name:
                # First, look for pack_expression (direct instantiation)
                pack_node = find_pack_expression(node)
                if pack_node:
                    struct_name = extract_struct_name_from_pack(pack_node)
                    if struct_name:
                        var_to_type[var_name] = qualify_name(struct_name)
                else:
                    # Look for call_expression (function call)
                    call_node = find_call_expression(node)
                    if call_node:
                        callee = extract_callee(call_node)
                        if callee:
                            # Look up return type in the return_types dict
                            qualified_callee = qualify_name(callee)
                            # Try both FQN and simple name
                            if qualified_callee in return_types:
                                return_type = return_types[qualified_callee]
                                var_to_type[var_name] = return_type
                            elif callee in return_types:
                                return_type = return_types[callee]
                                var_to_type[var_name] = return_type

        # Detect share_object(var) calls
        if node.type == "call_expression":
            callee = extract_callee(node)
            if callee and is_stdlib_share_call(callee):
                args = extract_call_args(node)
                if args:
                    var_name = args[0]
                    if var_name in var_to_type:
                        shared_types.add(var_to_type[var_name])

        for child in node.children:
            traverse(child)

    traverse(root)
    return shared_types


# =============================================================================
# PER-STRUCT TRANSFER PATTERN DETECTION
# =============================================================================


@dataclass
class StructTransferPattern:
    """Per-struct transfer pattern within a function."""

    transferred_to: str  # "sender" | "param" | "none"
    shared: bool
    frozen: bool


def _find_per_struct_transfer_patterns(
    source_code: str,
    root,
    func_name: str,
    target_structs: Set[str],
    import_map: Dict[str, str],
    module_path: Optional[str],
    sender_derived_params: Optional[Set[int]] = None,
) -> Dict[str, StructTransferPattern]:
    """
    Find per-struct transfer patterns within a specific function.

    Unlike detect_transfer_patterns() which returns function-level patterns,
    this tracks which specific struct goes to which sink.

    Args:
        source_code: Source code of the file
        root: Tree-sitter root node
        func_name: Fully qualified function name to analyze
        target_structs: Set of struct FQNs to track
        import_map: Module import alias mapping
        module_path: Current module path for FQN resolution
        sender_derived_params: Set of parameter indices that receive sender values at call sites

    Returns:
        Dict mapping struct FQN to its specific transfer pattern
    """
    from move.imports import _replace_import_alias

    result: Dict[str, StructTransferPattern] = {}

    # Track: var_name -> struct_type
    var_to_type: Dict[str, str] = {}
    # Track: struct_type -> set of sink types ("transfer", "share", "freeze")
    struct_sinks: Dict[str, Set[str]] = {}
    # Track: struct_type -> has_sender_in_transfer (for transfer to sender detection)
    struct_transfer_to_sender: Dict[str, bool] = {}

    func_simple = get_simple_name(func_name)
    current_function: Optional[str] = None

    def qualify_name(name: str) -> str:
        resolved = _replace_import_alias(name, import_map)
        if "::" not in resolved and module_path:
            return f"{module_path}::{resolved}"
        return resolved

    def extract_struct_name_from_pack(node) -> Optional[str]:
        for child in node.children:
            if child.type == "name_expression":
                for subchild in child.children:
                    if subchild.type == "module_access":
                        name_parts = []
                        for name_child in subchild.children:
                            if name_child.type == "identifier":
                                name_parts.append(source_code[name_child.start_byte : name_child.end_byte])
                            elif name_child.type in ("module_identifier", "module_identity"):
                                # module_identity for FQN like test::module_a::Factory
                                # module_identifier for simple module::Struct
                                name_parts.append(source_code[name_child.start_byte : name_child.end_byte])
                        if name_parts:
                            return "::".join(name_parts)
                    elif subchild.type == "identifier":
                        return source_code[subchild.start_byte : subchild.end_byte]
        return None

    def extract_callee(node) -> Optional[str]:
        for child in node.children:
            if child.type == "name_expression":
                for subchild in child.children:
                    if subchild.type == "module_access":
                        parts = []
                        for name_child in subchild.children:
                            if name_child.type == "identifier":
                                parts.append(source_code[name_child.start_byte : name_child.end_byte])
                            elif name_child.type == "module_identifier":
                                parts.append(source_code[name_child.start_byte : name_child.end_byte])
                            elif name_child.type == "module_identity":
                                for id_child in name_child.children:
                                    if id_child.type == "module_identifier":
                                        parts.append(source_code[id_child.start_byte : id_child.end_byte])
                        if parts:
                            return "::".join(parts)
        return None

    def extract_call_args(node) -> List[str]:
        args = []
        for child in node.children:
            if child.type == "arg_list":
                for arg_child in child.children:
                    if arg_child.type == "name_expression":
                        for subchild in arg_child.children:
                            if subchild.type == "module_access":
                                for id_child in subchild.children:
                                    if id_child.type == "identifier":
                                        args.append(source_code[id_child.start_byte : id_child.end_byte])
                                        break
                    # Handle call expressions as arguments (e.g., tx_context::sender(ctx))
                    elif arg_child.type == "call_expression":
                        callee = extract_callee(arg_child)
                        if callee:
                            if is_stdlib_sender_call(callee):
                                args.append("__sender__")  # Special marker
                            else:
                                args.append(f"__call:{callee}__")
        return args

    def extract_let_binding(node) -> Optional[str]:
        for child in node.children:
            if child.type == "bind_list":
                for bind_child in child.children:
                    if bind_child.type == "bind_var":
                        for var_child in bind_child.children:
                            if var_child.type == "variable_identifier":
                                return source_code[var_child.start_byte : var_child.end_byte]
                    elif bind_child.type == "variable_identifier":
                        return source_code[bind_child.start_byte : bind_child.end_byte]
        return None

    def find_pack_expression(node):
        if node.type == "pack_expression":
            return node
        for child in node.children:
            result = find_pack_expression(child)
            if result:
                return result
        return None

    def is_sender_call(node) -> bool:
        """Check if node is a tx_context::sender() call."""
        if node.type == "call_expression":
            callee = extract_callee(node)
            if callee:
                return is_stdlib_sender_call(callee)
        return False

    def check_second_arg_is_sender(node) -> bool:
        """Check if second argument to transfer call is sender()."""
        for child in node.children:
            if child.type == "arg_list":
                arg_count = 0
                for arg_child in child.children:
                    if arg_child.type in ("name_expression", "call_expression"):
                        arg_count += 1
                        if arg_count == 2:
                            # Check if this arg is a sender call or a variable
                            if is_sender_call(arg_child):
                                return True
                            # Check if it's a variable that holds sender result
                            if arg_child.type == "name_expression":
                                for subchild in arg_child.children:
                                    if subchild.type == "module_access":
                                        for id_child in subchild.children:
                                            if id_child.type == "identifier":
                                                var_name = source_code[id_child.start_byte : id_child.end_byte]
                                                # Common patterns: authority, sender, owner, admin
                                                # Note: This is a heuristic, but it works for most cases
                                                # A more precise approach would track sender assignments
                                                return var_name in var_to_sender
        return False

    # Track variables assigned from sender()
    var_to_sender: Set[str] = set()

    # Extract function parameters if sender_derived_params is provided
    func_param_names: List[str] = []

    def extract_function_params(func_def_node):
        """Extract parameter names from function definition."""
        params = []
        for child in func_def_node.children:
            if child.type == "function_parameters":
                for param_child in child.children:
                    if param_child.type == "function_parameter":
                        for param_subchild in param_child.children:
                            if param_subchild.type == "variable_identifier":
                                param_name = source_code[param_subchild.start_byte : param_subchild.end_byte]
                                params.append(param_name)
                                break
        return params

    def traverse(node):
        nonlocal current_function, var_to_type, var_to_sender, func_param_names

        if node.type == "function_definition":
            # Find function name
            for child in node.children:
                if child.type == "function_identifier":
                    fn = source_code[child.start_byte : child.end_byte]
                    current_function = qualify_name(fn)
                    break

            # Only process the target function
            if current_function is not None and (
                current_function == func_name or get_simple_name(current_function) == func_simple
            ):
                var_to_type = {}
                var_to_sender = set()

                # Extract function parameters
                func_param_names = extract_function_params(node)

                # Initialize var_to_sender with sender-derived parameters
                if sender_derived_params:
                    for param_idx in sender_derived_params:
                        if param_idx < len(func_param_names):
                            param_name = func_param_names[param_idx]
                            var_to_sender.add(param_name)
                            debug(f"    Marking param {param_idx} ({param_name}) as sender-derived in {func_name}")

                for child in node.children:
                    traverse(child)

            current_function = None
            return

        if current_function is None:
            for child in node.children:
                traverse(child)
            return

        # Track let var = sender() pattern
        if node.type == "let_statement":
            var_name = extract_let_binding(node)
            if var_name:
                # Check for sender call (direct or method call syntax)
                for child in node.children:
                    if child.type == "call_expression":
                        if is_sender_call(child):
                            var_to_sender.add(var_name)
                            break
                    # Handle method call syntax: ctx.sender()
                    # CST: dot_expression -> call_expression (sender())
                    elif child.type == "dot_expression":
                        for subchild in child.children:
                            if subchild.type == "call_expression":
                                callee = extract_callee(subchild)
                                if callee and get_simple_name(callee) == "sender":
                                    var_to_sender.add(var_name)
                                    break

                # Track struct instantiation
                pack_node = find_pack_expression(node)
                if pack_node:
                    struct_name = extract_struct_name_from_pack(pack_node)
                    if struct_name:
                        qualified = qualify_name(struct_name)
                        # Match against target structs - FQN first, then same-module simple name
                        for target in target_structs:
                            # Priority 1: Exact FQN match
                            if qualified == target:
                                var_to_type[var_name] = target
                                break
                            # Priority 2: Simple name match ONLY if same module
                            simple_name = get_simple_name(qualified)
                            simple_target = get_simple_name(target)
                            target_module = get_module_path(target)
                            if simple_name == simple_target and module_path == target_module:
                                var_to_type[var_name] = target
                                break

        # Detect transfer/share/freeze calls
        if node.type == "call_expression":
            callee = extract_callee(node)
            if callee:
                args = extract_call_args(node)

                if args:
                    first_arg = args[0]
                    struct_type = var_to_type.get(first_arg)

                    if struct_type:
                        if struct_type not in struct_sinks:
                            struct_sinks[struct_type] = set()

                        # Check which sink type
                        if is_stdlib_transfer_call(callee):
                            struct_sinks[struct_type].add("transfer")
                            # Check if second arg is sender
                            if check_second_arg_is_sender(node):
                                struct_transfer_to_sender[struct_type] = True
                            elif len(args) > 1 and args[1] == "__sender__":
                                struct_transfer_to_sender[struct_type] = True
                            elif len(args) > 1 and args[1] in var_to_sender:
                                struct_transfer_to_sender[struct_type] = True

                        elif is_stdlib_share_call(callee):
                            struct_sinks[struct_type].add("share")

                        elif is_stdlib_freeze_call(callee):
                            struct_sinks[struct_type].add("freeze")

        for child in node.children:
            traverse(child)

    traverse(root)

    # Build result from collected data
    for struct_type in target_structs:
        sinks = struct_sinks.get(struct_type, set())
        has_transfer = "transfer" in sinks
        has_share = "share" in sinks
        has_freeze = "freeze" in sinks

        if has_transfer:
            if struct_transfer_to_sender.get(struct_type, False):
                transferred_to = "sender"
            else:
                transferred_to = "param"
        else:
            transferred_to = "none"

        result[struct_type] = StructTransferPattern(
            transferred_to=transferred_to,
            shared=has_share,
            frozen=has_freeze,
        )

    return result


# =============================================================================
# CREATION SITE DETECTION
# =============================================================================


def collect_creation_sites(ctx: ProjectContext) -> Dict[str, List[CreationSite]]:
    """
    Collect creation sites for all structs with key ability.

    For each struct, identifies:
    - Which functions create it (pack_expression)
    - Whether creating function is init or called from init
    - Transfer patterns (sender, shared, frozen)

    Returns:
        Dict mapping struct FQN to list of CreationSite objects.
    """
    from analysis.call_graph import build_global_call_graph, is_transitively_called_from

    # Get all structs with key ability
    struct_types: Set[str] = set()
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "HasKeyAbility":
                struct_types.add(fact.args[0])

    if not struct_types:
        return {}

    # Get init functions
    init_funcs: Set[str] = set()
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "IsInit":
                init_funcs.add(fact.args[0])

    # Build call graph for init reachability check
    call_graph = build_global_call_graph(ctx)

    # Collect known functions (non-test functions)
    known_funcs: Set[str] = set()
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "Fun":
                known_funcs.add(fact.args[0])

    # Collect SenderDerivedParam facts
    sender_derived_params_map: Dict[str, Set[int]] = {}
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "SenderDerivedParam":
                func_name, param_idx = fact.args
                sender_derived_params_map.setdefault(func_name, set()).add(param_idx)

    # Find struct instantiations and group by function
    result: Dict[str, List[CreationSite]] = {}

    for file_path, file_ctx in ctx.source_files.items():
        if file_ctx.is_test_only or file_ctx.source_code is None:
            continue

        instantiations = find_struct_instantiations(file_ctx.source_code, file_ctx.root, struct_types)

        # Group instantiations by function for efficient per-struct pattern detection
        func_to_structs: Dict[str, Set[str]] = {}
        for func_name, struct_type in instantiations:
            if func_name not in known_funcs:
                continue
            if func_name not in func_to_structs:
                func_to_structs[func_name] = set()
            func_to_structs[func_name].add(struct_type)

        # Process each function with per-struct transfer pattern detection
        for func_name, func_struct_types in func_to_structs.items():
            # Check if function is init or called from init
            is_init_func = func_name in init_funcs
            init_caller: Optional[str] = None
            if not is_init_func:
                init_caller = is_transitively_called_from(func_name, init_funcs, call_graph)
            is_init = is_init_func or init_caller is not None

            # Get sender-derived params for this function
            sender_params = sender_derived_params_map.get(func_name, None)

            # Detect per-struct transfer patterns (not function-level!)
            per_struct_patterns = _find_per_struct_transfer_patterns(
                file_ctx.source_code,
                file_ctx.root,
                func_name,
                func_struct_types,
                file_ctx.import_map,
                file_ctx.module_path,
                sender_params,
            )

            for struct_type in func_struct_types:
                pattern = per_struct_patterns.get(struct_type)
                if pattern:
                    transferred_to = pattern.transferred_to
                    shared = pattern.shared
                    frozen = pattern.frozen
                else:
                    # Fallback to function-level detection if per-struct failed
                    transferred_to, shared, frozen = detect_transfer_patterns(func_name, file_ctx.facts)

                site = CreationSite(
                    func_name=func_name,
                    is_init=is_init,
                    transferred_to=transferred_to,
                    shared=shared,
                    frozen=frozen,
                    called_from_init=init_caller,
                )

                if struct_type not in result:
                    result[struct_type] = []
                result[struct_type].append(site)

    return result


def generate_creates_capability_facts(ctx: ProjectContext) -> None:
    """
    Generate CreatesCapability facts for functions that instantiate role structs.

    A function gets CreatesCapability(func, Type) if:
    - It has PacksStruct(func, Type) fact
    - Type is a role (has IsCapability fact)

    This leverages existing PacksStruct and IsCapability facts.
    """
    count = 0

    # Collect all role types
    role_types: Set[str] = set()
    for source_file in ctx.source_files.values():
        for fact in source_file.facts:
            if fact.name == "IsCapability":
                role_types.add(fact.args[0])

    if not role_types:
        debug("No roles found, skipping CreatesCapability generation")
        return

    debug(f"Found {len(role_types)} role types for CreatesCapability detection")

    # Find all PacksStruct facts and check if they pack a role
    for source_file in ctx.source_files.values():
        if source_file.is_test_only:
            continue

        for fact in source_file.facts:
            if fact.name == "PacksStruct":
                func_name = fact.args[0]
                struct_type = fact.args[1]

                # Check if struct_type is a role - use EXACT FQN match
                # Do NOT fall back to simple name matching to avoid FQN collisions
                if struct_type in role_types:
                    creates_fact = Fact("CreatesCapability", (func_name, struct_type))
                    if creates_fact not in source_file.facts:
                        source_file.facts.append(creates_fact)
                        count += 1

    # Also handle stdlib capability-returning functions (e.g., coin::create_currency)
    for source_file in ctx.source_files.values():
        if source_file.is_test_only:
            continue

        for fact in source_file.facts:
            if fact.name == "CallResult":
                func_name, _stmt_id, _var_name, callee = fact.args
                if callee in SUI_CAPABILITY_RETURNING_FUNCTIONS:
                    for _tuple_idx, cap_type in SUI_CAPABILITY_RETURNING_FUNCTIONS[callee]:
                        creates_fact = Fact("CreatesCapability", (func_name, cap_type))
                        if creates_fact not in source_file.facts:
                            source_file.facts.append(creates_fact)
                            count += 1

    if count > 0:
        debug(f"Generated {count} CreatesCapability facts")


def propagate_creates_capability_facts(ctx: ProjectContext) -> None:
    """
    Propagate CreatesCapability facts to callers via IPA (Interprocedural Analysis).

    If function A calls function B, and B creates capability C, then A also
    effectively creates C (transitively). This propagation is done via fixed-point
    iteration over the call graph.
    """
    # TODO: cross-module IPA - helper creating cap dosn't propgate to caller
    if not ctx.call_graph:
        debug("No call graph available, skipping CreatesCapability propagation")
        return

    # Collect initial CreatesCapability facts: func -> {cap_types}
    creates_cap: Dict[str, Set[str]] = {}
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "CreatesCapability":
                func_name, cap_type = fact.args
                creates_cap.setdefault(func_name, set()).add(cap_type)

    if not creates_cap:
        debug("No CreatesCapability facts to propagate")
        return

    debug(f"Starting IPA propagation for {len(creates_cap)} functions with CreatesCapability")

    # Fixed-point propagation: if caller calls callee, caller inherits callee's CreatesCapability
    changed = True
    iterations = 0
    while changed:
        changed = False
        iterations += 1
        for caller, callees in ctx.call_graph.callees.items():
            for callee in callees:
                if callee not in creates_cap:
                    continue
                # Propagate all cap types from callee to caller
                for cap_type in creates_cap[callee]:
                    if caller not in creates_cap or cap_type not in creates_cap[caller]:
                        creates_cap.setdefault(caller, set()).add(cap_type)
                        changed = True
                        # Add fact to caller's file
                        for file_ctx in ctx.source_files.values():
                            if any(f.name == "Fun" and f.args[0] == caller for f in file_ctx.facts):
                                new_fact = Fact("CreatesCapability", (caller, cap_type))
                                if new_fact not in file_ctx.facts:
                                    file_ctx.facts.append(new_fact)
                                break

    debug(f"CreatesCapability IPA propagation completed in {iterations} iterations")


def generate_sender_derived_param_facts(ctx: ProjectContext) -> None:
    """
    Generate SenderDerivedParam facts for function parameters that receive sender values.

    Analyzes call sites where sender-derived variables are passed as arguments,
    marking the corresponding function parameters.

    Algorithm:
    1. Collect all sender-derived variables (from TrackedDerived facts)
    2. Find call sites where these variables are passed as arguments
    3. Generate SenderDerivedParam(callee, param_idx) for each such call
    4. Use fixed-point iteration to propagate transitively
    """
    count = 0

    # Step 1: Collect sender-derived variables per function
    sender_vars: Dict[str, Set[str]] = {}
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "TrackedDerived" and fact.args[2] == "sender":
                func_name = fact.args[0]
                var_name = fact.args[1]
                sender_vars.setdefault(func_name, set()).add(var_name)

    if not sender_vars:
        debug("No sender-derived variables found, skipping SenderDerivedParam generation")
        return

    debug(
        f"Found {sum(len(v) for v in sender_vars.values())} sender-derived variables across {len(sender_vars)} functions"
    )

    # Step 2: Analyze call sites and generate initial facts
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name != "CallArg":
                continue

            func_name, stmt_id, callee, arg_idx, arg_vars = fact.args

            # Check if any argument variable is sender-derived in the caller
            caller_sender_vars = sender_vars.get(func_name, set())
            for arg_var in arg_vars:
                if arg_var in caller_sender_vars:
                    # Generate SenderDerivedParam fact for the callee
                    new_fact = Fact("SenderDerivedParam", (callee, arg_idx))
                    if new_fact not in file_ctx.facts:
                        file_ctx.facts.append(new_fact)
                        count += 1
                        debug(f"  SenderDerivedParam({callee}, {arg_idx}) [from {func_name}]")
                    break

    # Step 3: Collect function parameters and propagate transitively
    # If func has SenderDerivedParam(func, N), and func passes param N to another function,
    # mark that param as sender-derived in the callee
    func_params: Dict[str, Dict[int, str]] = {}
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "FormalArg":
                func_name, param_idx, param_name, _ = fact.args
                func_params.setdefault(func_name, {})[param_idx] = param_name

    # Fixed-point iteration for transitive propagation
    changed = True
    iterations = 0
    max_iterations = 10

    while changed and iterations < max_iterations:
        changed = False
        iterations += 1

        # Collect current SenderDerivedParam facts
        sender_derived_params: Dict[str, Set[int]] = {}
        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name == "SenderDerivedParam":
                    func_name, param_idx = fact.args
                    sender_derived_params.setdefault(func_name, set()).add(param_idx)

        # For each function with sender-derived params, check if those params are passed to callees
        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name != "CallArg":
                    continue

                func_name, stmt_id, callee, arg_idx, arg_vars = fact.args

                # Check if this function has sender-derived params
                if func_name not in sender_derived_params:
                    continue

                # Get parameter names for this function
                params = func_params.get(func_name, {})

                # Check if any arg_var matches a sender-derived parameter
                for arg_var in arg_vars:
                    # Find param index for this arg_var
                    param_idx = None
                    for idx, pname in params.items():
                        if pname == arg_var:
                            param_idx = idx
                            break

                    if param_idx is not None and param_idx in sender_derived_params.get(func_name, set()):
                        # This param is sender-derived, propagate to callee
                        new_fact = Fact("SenderDerivedParam", (callee, arg_idx))
                        if new_fact not in file_ctx.facts:
                            file_ctx.facts.append(new_fact)
                            count += 1
                            changed = True
                            debug(f"  SenderDerivedParam({callee}, {arg_idx}) [transitive from {func_name}]")
                        break

    if count > 0:
        debug(f"Generated {count} SenderDerivedParam facts in {iterations} iterations")
