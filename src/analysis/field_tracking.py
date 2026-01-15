"""
Field write detection from IR.

Detects WritesField facts by analyzing AssignStmt nodes where the target is a FieldAccess.
Propagates field writes transitively through call graph for indirect setter detection.
"""

from typing import List, Dict, Set, Tuple, Optional

from core.context import ProjectContext
from core.facts import Fact, names_match
from core.utils import debug
from move.ir import Function, AssignStmt, FieldAccess as IRFieldAccess, VarRef, Deref, ExprStmt, Call
from move.types import extract_base_type, qualify_type
from move.sui_patterns import COLLECTION_MUTATION_METHODS, GENERIC_SETTER_METHOD_NAMES


def _extract_field_chain(fa: IRFieldAccess) -> Optional[Tuple[str, str]]:
    """
    Extract (base_var, field_path) from nested FieldAccess chain.

    Examples:
        pool.fee_config -> ("pool", "fee_config")
        cfg.settings.inner -> ("cfg", "settings.inner")
    """
    fields = []
    current = fa

    while isinstance(current, IRFieldAccess):
        fields.append(current.field)
        current = current.base

    # Get the base variable name
    if isinstance(current, VarRef):
        base_var = current.name
        field_path = ".".join(reversed(fields))
        return (base_var, field_path)
    elif isinstance(current, Deref):
        # Handle *ref.field case - extract from the Deref's inner
        if isinstance(current.inner, VarRef):
            base_var = current.inner.name
            field_path = ".".join(reversed(fields))
            return (base_var, field_path)

    return None


def _extract_field_write(target) -> Optional[Tuple[str, str]]:
    """
    Extract (base_var, field_path) from assignment target if it's a field write.

    Returns None if target is not a field access.
    """
    if isinstance(target, IRFieldAccess):
        return _extract_field_chain(target)

    return None


def _extract_method_mutation(stmt) -> Optional[Tuple[str, str]]:
    """
    Extract (base_var, field_path) from struct.field.set(value) pattern.

    Detects method calls on nested fields that mutate the field's value:
        pool.fee_config.set(v) -> ("pool", "fee_config")
        cfg.settings.inner.set(v) -> ("cfg", "settings.inner")

    Only recognizes known mutation methods (set, put, swap, etc.).
    """
    if not isinstance(stmt, ExprStmt):
        return None

    expr = stmt.expr
    if not isinstance(expr, Call):
        return None

    # Check if method call (has receiver)
    if not expr.receiver:
        return None

    # Check if the method is a known mutation method
    # 1. FQN match for Sui stdlib collection methods
    is_stdlib_mutation = any(names_match(expr.callee, m) for m in COLLECTION_MUTATION_METHODS)
    # 2. Simple name match for generic setter methods (user-defined)
    callee_simple = expr.callee.split("::")[-1]
    is_generic_setter = callee_simple in GENERIC_SETTER_METHOD_NAMES

    if not is_stdlib_mutation and not is_generic_setter:
        return None

    # Extract field chain from the receiver
    if isinstance(expr.receiver, IRFieldAccess):
        return _extract_field_chain(expr.receiver)

    return None


def generate_writes_field_facts(ctx: ProjectContext) -> int:
    """
    Generate WritesField facts by analyzing AssignStmt nodes in IR.

    Matches patterns:
    1. param.field = value (parameter field write)
    2. local_var.field = value where local_var = function_call() (local variable from call result)

    Returns:
        Number of WritesField facts generated
    """
    count = 0

    # Build global FunReturnType map: func_name -> return_type
    fun_return_types: Dict[str, str] = {}
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "FunReturnType":
                fun_return_types[fact.args[0]] = fact.args[1]

    # Iterate over all IR functions in the module index
    for func_name, func in ctx.module_index.items():
        # Get function parameters to map var names to types
        var_types: Dict[str, str] = {}

        # Add parameters
        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name == "FormalArg":
                    fn, param_idx, param_name, param_type = fact.args
                    if fn == func_name:
                        var_types[param_name] = param_type

        # Add local variables from CallResult facts
        for file_ctx in ctx.source_files.values():
            for fact in file_ctx.facts:
                if fact.name == "CallResult":
                    fn, stmt_id, var_name, callee = fact.args
                    if fn == func_name:
                        # Look up callee's return type
                        if callee in fun_return_types:
                            var_types[var_name] = fun_return_types[callee]

        # Analyze all assignment statements
        field_writes = _analyze_function_for_writes(func)

        for base_var, field_path in field_writes:
            # Resolve base_var to struct type via var_types map (params + locals)
            if base_var in var_types:
                var_type = var_types[base_var]
                # Extract base type, preserving FQN if already qualified
                struct_type = extract_base_type(var_type, keep_fqn=True)

                # Qualify struct type if not already qualified
                if "::" in func_name:
                    module_path = "::".join(func_name.split("::")[:-1])
                    struct_type = qualify_type(struct_type, module_path)

                # Generate WritesField fact - find the file containing this function
                for file_ctx in ctx.source_files.values():
                    if any(f.name == "Fun" and f.args[0] == func_name for f in file_ctx.facts):
                        # Avoid duplicates
                        if not any(
                            f.name == "WritesField"
                            and f.args[0] == func_name
                            and f.args[1] == struct_type
                            and f.args[2] == field_path
                            for f in file_ctx.facts
                        ):
                            writes_fact = Fact("WritesField", (func_name, struct_type, field_path))
                            file_ctx.facts.append(writes_fact)
                            count += 1
                            debug(f"  WritesField({func_name}, {struct_type}, {field_path})")
                        break

    if count > 0:
        debug(f"[field_tracking] Generated {count} WritesField facts")

    return count


def _analyze_function_for_writes(func: Function) -> List[Tuple[str, str]]:
    """
    Analyze function IR to find field writes.

    Detects two patterns:
    1. Direct assignment: pool.field = value
    2. Method mutation: pool.field.set(value)

    Returns:
        List of (base_var, field_path) tuples for all field writes in the function
    """
    writes: List[Tuple[str, str]] = []

    def visit_stmt(stmt):
        # Pattern 1: Direct assignment to field
        if isinstance(stmt, AssignStmt):
            result = _extract_field_write(stmt.target)
            if result:
                writes.append(result)

        # Pattern 2: Method mutation on nested field
        if isinstance(stmt, ExprStmt):
            result = _extract_method_mutation(stmt)
            if result:
                writes.append(result)

        # Recursively visit nested statements
        if hasattr(stmt, "then_branch") and stmt.then_branch:
            for s in stmt.then_branch:
                visit_stmt(s)
        if hasattr(stmt, "else_branch") and stmt.else_branch:
            for s in stmt.else_branch:
                visit_stmt(s)
        if hasattr(stmt, "body") and stmt.body:
            for s in stmt.body:
                visit_stmt(s)

    for stmt in func.body:
        visit_stmt(stmt)

    return writes


def propagate_writes_field_to_callers(ctx: ProjectContext) -> int:
    """
    Propagate WritesField facts through call graph to callers.

    If function A calls function B, and B writes to a field,
    then A transitively writes to that field (via B).

    This enables detecting privileged setters that delegate to internal functions:
        public fun update_config(cap: &AdminCap, pool: &mut Pool, rate: u64) {
            internal_set_fee(pool, rate);  // Now detected as transitive write
        }
        fun internal_set_fee(pool: &mut Pool, rate: u64) {
            pool.fee_rate = rate;  // Direct write
        }

    Returns:
        Number of TransitiveWritesField facts generated
    """
    from analysis.call_graph import build_global_call_graph

    call_graph = build_global_call_graph(ctx)  # caller -> {callees}

    # Build reverse graph: callee -> {callers}
    reverse_graph: Dict[str, Set[str]] = {}
    for caller, callees in call_graph.items():
        for callee in callees:
            reverse_graph.setdefault(callee, set()).add(caller)

    # Collect direct writes: func -> {(struct, field)}
    direct_writes: Dict[str, Set[Tuple[str, str]]] = {}
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == "WritesField":
                func, struct_type, field_path = fact.args
                direct_writes.setdefault(func, set()).add((struct_type, field_path))

    if not direct_writes:
        return 0

    # Fixed-point propagation: transitive_writes[func][(struct, field)] = via_callee
    transitive_writes: Dict[str, Dict[Tuple[str, str], str]] = {}

    # Worklist: start with functions that have direct writes
    worklist = list(direct_writes.keys())
    processed: Set[str] = set()

    while worklist:
        func = worklist.pop()
        if func in processed:
            continue
        processed.add(func)

        # Get all writes for this function (direct + transitive)
        writes = direct_writes.get(func, set()) | set(transitive_writes.get(func, {}).keys())

        # Propagate to callers
        for caller in reverse_graph.get(func, set()):
            if caller not in transitive_writes:
                transitive_writes[caller] = {}

            changed = False
            for struct_type, field_path in writes:
                key = (struct_type, field_path)
                # Only add if not already a direct write and not already transitive
                if key not in direct_writes.get(caller, set()) and key not in transitive_writes[caller]:
                    transitive_writes[caller][key] = func
                    changed = True

            if changed and caller not in processed:
                worklist.append(caller)

    # Generate TransitiveWritesField facts
    count = 0
    for func, writes in transitive_writes.items():
        if not writes:
            continue

        # Find the file containing this function
        for file_ctx in ctx.source_files.values():
            if any(f.name == "Fun" and f.args[0] == func for f in file_ctx.facts):
                for (struct_type, field_path), via_callee in writes.items():
                    # Avoid duplicates
                    if not any(
                        f.name == "TransitiveWritesField"
                        and f.args[0] == func
                        and f.args[1] == struct_type
                        and f.args[2] == field_path
                        for f in file_ctx.facts
                    ):
                        fact = Fact("TransitiveWritesField", (func, struct_type, field_path, via_callee))
                        file_ctx.facts.append(fact)
                        count += 1
                        debug(f"  TransitiveWritesField({func}, {struct_type}, {field_path}, via {via_callee})")
                break

    if count > 0:
        debug(f"[field_tracking] Generated {count} TransitiveWritesField facts")

    return count
