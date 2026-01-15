"""
CST to IR Transformer - Converts tree-sitter CST to Move IR.

This module transforms the concrete syntax tree from tree-sitter
into our minimal IR suitable for taint analysis.
"""

from typing import List, Optional, Dict

from core.utils import error
from .utils import _extract_text
from .collectors import _is_abort_only_function
from .ir import (
    Expr,
    VarRef,
    FieldAccess,
    Borrow,
    Deref,
    Call,
    BinOp,
    UnaryOp,
    Literal,
    Vector,
    StructPack,
    IfExpr,
    Block,
    Cast,
    Unknown,
    Stmt,
    LetStmt,
    AssignStmt,
    ExprStmt,
    ReturnStmt,
    AbortStmt,
    IfStmt,
    WhileStmt,
    LoopStmt,
    BreakStmt,
    ContinueStmt,
    Param,
    Function,
    Module,
)


class IRBuilder:
    """
    Transforms tree-sitter CST nodes into Move IR.

    Usage:
        builder = IRBuilder(source_code)
        module = builder.build_module(root_node)
    """

    def __init__(self, source_code: str, module_path: str = ""):
        self.source = source_code
        self.module_path = module_path
        self._expr_counter = 0
        self._stmt_counter = 0
        self._import_map: Dict[str, str] = {}

    def _next_expr_id(self) -> str:
        self._expr_counter += 1
        return f"expr_{self._expr_counter}"

    def _next_stmt_id(self) -> str:
        self._stmt_counter += 1
        return f"stmt_{self._stmt_counter}"

    def _get_text(self, node) -> str:
        """Extract source text for a node using correct byte-to-char conversion."""
        return _extract_text(self.source, node.start_byte, node.end_byte)

    def _get_line(self, node) -> int:
        """Get 1-indexed line number for a node."""
        return node.start_point[0] + 1

    def _qualify_name(self, name: str) -> str:
        """Qualify a name with module path if needed."""
        if "::" in name:
            # Check if first part is an import alias
            parts = name.split("::", 1)
            if parts[0] in self._import_map:
                return f"{self._import_map[parts[0]]}::{parts[1]}"
            return name
        if name in self._import_map:
            return self._import_map[name]
        if self.module_path:
            return f"{self.module_path}::{name}"
        return name

    # =========================================================================
    # Module and Function building
    # =========================================================================

    def build_module(self, root) -> Optional[Module]:
        """Build a Module IR from the root CST node."""
        module_def = None
        for child in root.children:
            if child.type == "module_definition":
                module_def = child
                break

        if module_def is None:
            return None

        # Extract module path
        for child in module_def.children:
            if child.type == "module_identity":
                parts = []
                for sub in child.children:
                    if sub.type == "module_identifier":
                        parts.append(self._get_text(sub))
                if parts:
                    self.module_path = "::".join(parts)
                break

        # Parse imports
        self._parse_imports(module_def)

        # Collect functions
        functions: List[Function] = []
        structs: List[str] = []

        for child in module_def.children:
            if child.type == "module_body":
                for item in child.children:
                    if item.type == "function_definition":
                        func = self._build_function(item)
                        if func:
                            functions.append(func)
                    elif item.type == "struct_definition":
                        # Just collect struct names for context
                        for sub in item.children:
                            if sub.type == "struct_identifier":
                                structs.append(self._get_text(sub))
                                break

        return Module(name=self.module_path, functions=functions, structs=structs)

    def _parse_imports(self, module_def) -> None:
        """Parse use declarations to build import map."""
        for child in module_def.children:
            if child.type == "module_body":
                for item in child.children:
                    if item.type == "use_declaration":
                        self._parse_use_declaration(item)

    def _parse_use_declaration(self, use_node) -> None:
        """Parse a single use declaration."""
        for child in use_node.children:
            if child.type in ("use_module", "use_module_members"):
                base_path = None

                for sub in child.children:
                    if sub.type == "module_identity":
                        parts = []
                        for mi in sub.children:
                            if mi.type == "module_identifier":
                                parts.append(self._get_text(mi))
                        if parts:
                            base_path = "::".join(parts)

                if child.type == "use_module" and base_path:
                    # Simple import: use path;
                    alias = base_path.split("::")[-1]
                    self._import_map[alias] = base_path

                elif child.type == "use_module_members" and base_path:
                    # Grouped import: use path::{Self, Type1, Type2};
                    for member in child.children:
                        if member.type != "use_member":
                            continue

                        member_name = None
                        alias = None
                        seen_as = False

                        for m_child in member.children:
                            if m_child.type == "as":
                                seen_as = True
                            elif m_child.type == "identifier":
                                text = self._get_text(m_child)
                                if seen_as:
                                    alias = text
                                elif member_name is None:
                                    member_name = text

                        if not member_name:
                            continue

                        if member_name in ("Self", "self"):
                            target_alias = alias or base_path.split("::")[-1]
                            self._import_map[target_alias] = base_path
                        else:
                            target_alias = alias or member_name
                            self._import_map[target_alias] = f"{base_path}::{member_name}"

    def _build_function(self, func_node) -> Optional[Function]:
        """Build a Function IR from a function_definition node."""
        # Skip abort-only stub functions - they generate false positives
        if _is_abort_only_function(func_node):
            return None

        func_name = None
        is_public = False
        is_entry = False
        params: List[Param] = []
        body: List[Stmt] = []
        ret_type: Optional[str] = None
        line = self._get_line(func_node)

        for child in func_node.children:
            if child.type == "function_identifier":
                func_name = self._get_text(child)
            elif child.type == "modifier":
                mod_text = self._get_text(child)
                if "public" in mod_text:
                    is_public = True
                if "entry" in mod_text:
                    is_entry = True
            elif child.type == "function_parameters":
                params = self._parse_parameters(child)
            elif child.type == "ret_type":
                ret_type = self._get_text(child).lstrip(":").strip()
            elif child.type == "block":
                body = self._parse_block_stmts(child)

        if func_name is None:
            return None

        qualified_name = self._qualify_name(func_name)

        return Function(
            name=qualified_name,
            params=params,
            ret_type=ret_type,
            body=body,
            is_public=is_public,
            is_entry=is_entry,
            line=line,
        )

    def _parse_parameters(self, params_node) -> List[Param]:
        """Parse function parameters."""
        params = []
        idx = 0

        for child in params_node.children:
            if child.type == "function_parameter":
                var_name = None
                param_type = None
                is_mut = False

                for sub in child.children:
                    if sub.type == "variable_identifier":
                        var_name = self._get_text(sub)
                    elif sub.type == "ref_type":
                        param_type = self._get_text(sub)
                        if "&mut" in param_type:
                            is_mut = True
                    elif sub.type in ("apply_type", "module_access", "identifier", "primitive_type"):
                        param_type = self._get_text(sub)

                if var_name and param_type:
                    params.append(Param(name=var_name, typ=param_type, is_mut=is_mut, idx=idx))
                    idx += 1

        return params

    # =========================================================================
    # Statement parsing
    # =========================================================================

    def _parse_block_stmts(self, block_node) -> List[Stmt]:
        """Parse statements from a block node."""
        stmts = []

        for child in block_node.children:
            if child.type == "block_item":
                stmt = self._parse_block_item(child)
                if stmt:
                    stmts.append(stmt)
            elif child.type == "while_expression":
                # while not wrapped in block_item
                stmt = self._parse_while_stmt(child)
                if stmt:
                    stmts.append(stmt)
            elif child.type == "loop_expression":
                # loop not wrapped in block_item
                stmt = self._parse_loop_stmt(child)
                if stmt:
                    stmts.append(stmt)
            elif child.type == "if_expression":
                # if not wrapped in block_item
                stmt = self._parse_if_stmt(child)
                if stmt:
                    stmts.append(stmt)
            elif child.type not in ("{", "}", "newline", ";"):
                # Final expression without semicolon (implicit return)
                # Treat as an expression statement for taint tracking
                expr = self._parse_expr(child)
                if expr:
                    stmts.append(ExprStmt(id=self._next_stmt_id(), line=self._get_line(child), expr=expr))

        return stmts

    def _parse_block_item(self, item_node) -> Optional[Stmt]:
        """Parse a block_item into a statement."""
        for child in item_node.children:
            if child.type == "let_statement":
                return self._parse_let_stmt(child)
            elif child.type == "assign_expression":
                return self._parse_assign_stmt(child)
            elif child.type == "call_expression":
                return self._make_expr_stmt(child)
            elif child.type == "macro_call_expression":
                # Handle assert! and other macros as function calls
                return self._parse_macro_call(child)
            elif child.type == "if_expression":
                return self._parse_if_stmt(child)
            elif child.type == "while_expression":
                return self._parse_while_stmt(child)
            elif child.type == "loop_expression":
                return self._parse_loop_stmt(child)
            elif child.type == "return_expression":
                return self._parse_return_stmt(child)
            elif child.type == "abort_expression":
                return self._parse_abort_stmt(child)
            elif child.type == "break_expression":
                return BreakStmt(id=self._next_stmt_id(), line=self._get_line(child))
            elif child.type == "continue_expression":
                return ContinueStmt(id=self._next_stmt_id(), line=self._get_line(child))
            elif child.type == "dereference_expression":
                # *ref = value is a deref assignment
                return self._parse_deref_assign(child)
            # Handle any expression as expression statement
            elif child.type not in (";", "newline"):
                expr = self._parse_expr(child)
                if expr:
                    return ExprStmt(id=self._next_stmt_id(), line=self._get_line(child), expr=expr)
        return None

    def _parse_let_stmt(self, let_node) -> LetStmt:
        """Parse a let statement."""
        bindings: List[str] = []
        value: Optional[Expr] = None
        type_ann: Optional[str] = None
        line = self._get_line(let_node)
        binds_node = let_node.child_by_field_name("binds")
        if binds_node is not None:
            bindings = self._parse_bind_list(binds_node)
        type_node = let_node.child_by_field_name("type")
        if type_node is not None:
            type_ann = self._get_text(type_node)
        expr_node = let_node.child_by_field_name("expr")
        if expr_node is not None:
            value = self._parse_expr(expr_node)
        if not bindings:
            error("empty let bindings:", let_node.start_point, "->", let_node.end_point)
        return LetStmt(id=self._next_stmt_id(), line=line, bindings=bindings, value=value, type_ann=type_ann)

    def _parse_bind_list(self, node) -> list[str]:
        names: list[str] = []

        def visit(n):
            t = n.type
            if t == "bind_var":
                ident = None
                for ch in n.children:
                    if "identifier" in ch.type:
                        ident = self._get_text(ch)
                        break
                if ident is not None:
                    names.append(ident)
                return
            if "identifier" in t:
                names.append(self._get_text(n))
                return
            for child in n.children:
                visit(child)

        visit(node)
        return names

    def _parse_assign_stmt(self, assign_node) -> AssignStmt:
        """Parse an assignment statement."""
        target: Optional[Expr] = None
        value: Optional[Expr] = None
        line = self._get_line(assign_node)

        children = [c for c in assign_node.children if c.type not in ("=",)]
        if len(children) >= 2:
            target = self._parse_expr(children[0])
            value = self._parse_expr(children[1])

        return AssignStmt(
            id=self._next_stmt_id(),
            line=line,
            target=target or Unknown(id=self._next_expr_id(), raw="<missing target>"),
            value=value or Unknown(id=self._next_expr_id(), raw="<missing value>"),
        )

    def _parse_deref_assign(self, deref_node) -> Stmt:
        """Parse *ref = value assignment."""
        line = self._get_line(deref_node)

        # Structure: dereference_expression -> * assign_expression
        for child in deref_node.children:
            if child.type == "assign_expression":
                # The target is what's after *, wrapped in Deref
                assign = self._parse_assign_stmt(child)
                # Wrap target in Deref
                deref_target = Deref(id=self._next_expr_id(), inner=assign.target)
                return AssignStmt(id=assign.id, line=line, target=deref_target, value=assign.value)

        # Fallback: just a deref expression
        expr = self._parse_expr(deref_node)
        return ExprStmt(id=self._next_stmt_id(), line=line, expr=expr)

    def _make_expr_stmt(self, node) -> ExprStmt:
        """Create an expression statement from an expression node."""
        expr = self._parse_expr(node)
        return ExprStmt(id=self._next_stmt_id(), line=self._get_line(node), expr=expr)

    def _parse_macro_call_expr(self, macro_node) -> Call:
        """Parse a macro call as a Call expression.

        Macro calls are treated as function calls for taint analysis purposes.
        Example: assert!(x > 0, E_ERROR) -> Call(callee="assert!", args=[x > 0, E_ERROR])
        """
        macro_name = None
        args: List[Expr] = []

        for child in macro_node.children:
            if child.type == "macro_module_access":
                # Extract the macro name from macro_module_access
                # The child structure is: module_access, ERROR, "!"
                for sub in child.children:
                    if sub.type == "module_access":
                        macro_name = self._get_text(sub) + "!"
                        break
                    if sub.type == "identifier":
                        macro_name = self._get_text(sub) + "!"
                        break
            elif child.type == "arg_list":
                args = self._parse_arg_list(child)

        if macro_name is None:
            macro_name = "unknown_macro!"

        return Call(id=self._next_expr_id(), callee=macro_name, args=args)

    def _parse_macro_call(self, macro_node) -> ExprStmt:
        """Parse a macro call as an expression statement (for standalone macro calls)."""
        line = self._get_line(macro_node)
        call = self._parse_macro_call_expr(macro_node)
        return ExprStmt(id=self._next_stmt_id(), line=line, expr=call)

    def _parse_if_stmt(self, if_node) -> IfStmt:
        """Parse an if statement."""
        condition: Optional[Expr] = None
        then_body: List[Stmt] = []
        else_body: Optional[List[Stmt]] = None
        line = self._get_line(if_node)

        seen_else = False
        for child in if_node.children:
            if child.type == "else":
                seen_else = True
            elif child.type == "block":
                if not seen_else:
                    then_body = self._parse_block_stmts(child)
                else:
                    else_body = self._parse_block_stmts(child)
            elif child.type == "if_expression":
                # else if case
                else_body = [self._parse_if_stmt(child)]
            elif child.type == "break_expression":
                # if (cond) break - no block, direct break
                if not seen_else:
                    then_body = [BreakStmt(id=self._next_stmt_id(), line=self._get_line(child))]
                else:
                    else_body = [BreakStmt(id=self._next_stmt_id(), line=self._get_line(child))]
            elif child.type == "continue_expression":
                # if (cond) continue - no block, direct continue
                if not seen_else:
                    then_body = [ContinueStmt(id=self._next_stmt_id(), line=self._get_line(child))]
                else:
                    else_body = [ContinueStmt(id=self._next_stmt_id(), line=self._get_line(child))]
            elif child.type not in ("if", "(", ")"):
                # Must be condition (first non-keyword expression after 'if')
                if condition is None:
                    condition = self._parse_expr(child)

        return IfStmt(
            id=self._next_stmt_id(),
            line=line,
            condition=condition or Unknown(id=self._next_expr_id(), raw="<missing condition>"),
            then_body=then_body,
            else_body=else_body,
        )

    def _parse_while_stmt(self, while_node) -> WhileStmt:
        """Parse a while statement."""
        condition: Optional[Expr] = None
        body: List[Stmt] = []
        line = self._get_line(while_node)

        for child in while_node.children:
            if child.type == "block":
                body = self._parse_block_stmts(child)
            elif child.type not in ("while", "(", ")"):
                if condition is None:
                    condition = self._parse_expr(child)

        return WhileStmt(
            id=self._next_stmt_id(),
            line=line,
            condition=condition or Unknown(id=self._next_expr_id(), raw="<missing condition>"),
            body=body,
        )

    def _parse_loop_stmt(self, loop_node) -> LoopStmt:
        """Parse an infinite loop statement."""
        body: List[Stmt] = []
        line = self._get_line(loop_node)

        for child in loop_node.children:
            if child.type == "block":
                body = self._parse_block_stmts(child)

        return LoopStmt(id=self._next_stmt_id(), line=line, body=body)

    def _parse_return_stmt(self, return_node) -> ReturnStmt:
        """Parse a return statement."""
        value: Optional[Expr] = None
        line = self._get_line(return_node)

        for child in return_node.children:
            if child.type not in ("return",):
                expr = self._parse_expr(child)
                if expr:
                    value = expr
                    break

        return ReturnStmt(id=self._next_stmt_id(), line=line, value=value)

    def _parse_abort_stmt(self, abort_node) -> AbortStmt:
        """Parse an abort statement."""
        code: Optional[Expr] = None
        line = self._get_line(abort_node)

        for child in abort_node.children:
            if child.type not in ("abort",):
                expr = self._parse_expr(child)
                if expr:
                    code = expr
                    break

        return AbortStmt(id=self._next_stmt_id(), line=line, code=code)

    # =========================================================================
    # Expression parsing
    # =========================================================================

    def _parse_expr(self, node) -> Expr:
        """Parse an expression node into IR."""
        if node is None:
            return Unknown(id=self._next_expr_id(), raw="<null>")

        node_type = node.type

        if node_type == "name_expression":
            return self._parse_name_expr(node)

        elif node_type == "dot_expression":
            return self._parse_dot_expr(node)

        elif node_type == "call_expression":
            return self._parse_call_expr(node)

        elif node_type == "binary_expression":
            return self._parse_binary_expr(node)

        elif node_type == "unary_expression":
            return self._parse_unary_expr(node)

        elif node_type == "borrow_expression":
            return self._parse_borrow_expr(node)

        elif node_type == "dereference_expression":
            return self._parse_deref_expr(node)

        elif node_type == "num_literal":
            return Literal(id=self._next_expr_id(), value=self._get_text(node), kind="int")

        elif node_type in ("true", "false"):
            return Literal(id=self._next_expr_id(), value=node_type == "true", kind="bool")

        elif node_type == "address_literal":
            return Literal(id=self._next_expr_id(), value=self._get_text(node), kind="address")

        elif node_type == "byte_string_literal":
            return Literal(id=self._next_expr_id(), value=self._get_text(node), kind="bytes")

        elif node_type == "vector_expression":
            return self._parse_vector_expr(node)

        elif node_type == "pack_expression":
            return self._parse_pack_expr(node)

        elif node_type == "if_expression":
            return self._parse_if_expr(node)

        elif node_type == "block":
            return self._parse_block_expr(node)

        elif node_type == "module_access":
            # Simple identifier wrapped in module_access
            return self._parse_module_access(node)

        elif node_type == "identifier":
            return VarRef(id=self._next_expr_id(), name=self._get_text(node))

        elif node_type == "expression_list":
            return self._parse_expression_list(node)

        elif node_type == "cast_expression":
            return self._parse_cast_expr(node)

        elif node_type == "lambda_expression":
            return self._parse_lambda_expr(node)

        # Fallback: return as Unknown
        return Unknown(id=self._next_expr_id(), raw=self._get_text(node))

    def _parse_name_expr(self, node) -> Expr:
        """Parse a name_expression (variable reference)."""
        for child in node.children:
            if child.type == "module_access":
                return self._parse_module_access(child)
        return Unknown(id=self._next_expr_id(), raw=self._get_text(node))

    def _parse_module_access(self, node) -> Expr:
        """Parse a module_access node (simple name or qualified name)."""
        parts = []
        for child in node.children:
            if child.type in ("identifier", "module_identifier"):
                parts.append(self._get_text(child))

        if len(parts) == 1:
            return VarRef(id=self._next_expr_id(), name=parts[0])
        else:
            # Qualified name: module::name
            qualified = "::".join(parts)
            return VarRef(id=self._next_expr_id(), name=self._qualify_name(qualified))

    def _parse_dot_expr(self, node) -> Expr:
        """
        Parse a dot_expression.

        This can be either:
        1. Field access: obj.field
        2. Method call: obj.method(args) - parsed as Call with receiver
        """
        base: Optional[Expr] = None
        field_or_call = None

        for child in node.children:
            if child.type == ".":
                continue
            elif base is None:
                base = self._parse_expr(child)
            else:
                # After the dot, we have either a field name or a call_expression
                if child.type == "call_expression":
                    # Method call syntax: obj.method(args)
                    # Parse the call and set the base as receiver
                    call = self._parse_call_expr(child)
                    if base:
                        call.receiver = base
                    return call
                elif child.type == "index_expression":
                    # Index syntax: obj.field[x, y]
                    # The index_expression contains the field name (e.g., "data" in grid.data[x])
                    # We need to wrap that as a FieldAccess on our base
                    call = self._parse_index_expr(child)
                    if base and call.receiver:
                        # Replace the receiver with a proper FieldAccess chain
                        if isinstance(call.receiver, VarRef):
                            call.receiver = FieldAccess(id=self._next_expr_id(), base=base, field=call.receiver.name)
                        else:
                            # For complex receivers, just set base as the outer receiver
                            call.receiver = base
                    return call
                elif child.type == "macro_call_expression":
                    # Macro call syntax: obj.macro!(args)
                    call = self._parse_macro_call_expr(child)
                    if base:
                        call.receiver = base
                    return call
                elif child.type == "name_expression":
                    # Could be a simple field or part of a method name
                    for sub in child.children:
                        if sub.type == "module_access":
                            for ident in sub.children:
                                if ident.type == "identifier":
                                    field_or_call = self._get_text(ident)
                                    break
                elif child.type == "identifier":
                    field_or_call = self._get_text(child)
                else:
                    field_or_call = self._get_text(child)

        if base and field_or_call:
            return FieldAccess(id=self._next_expr_id(), base=base, field=field_or_call)

        return Unknown(id=self._next_expr_id(), raw=self._get_text(node))

    def _parse_call_expr(self, node) -> Call:
        """Parse a call_expression."""
        callee: Optional[str] = None
        args: List[Expr] = []
        type_args: List[str] = []

        for child in node.children:
            if child.type == "name_expression":
                # Get callee name
                for sub in child.children:
                    if sub.type == "module_access":
                        parts = []
                        for ident in sub.children:
                            if ident.type in ("identifier", "module_identifier"):
                                parts.append(self._get_text(ident))
                            # Handle type arguments case: module_access contains module_identity
                            elif ident.type == "module_identity":
                                for id_part in ident.children:
                                    if id_part.type in ("identifier", "module_identifier"):
                                        parts.append(self._get_text(id_part))
                        callee = "::".join(parts)
                # Extract type arguments from name_expression
                type_args = self._extract_type_arguments(child)
            elif child.type == "arg_list":
                args = self._parse_arg_list(child)

        if callee:
            callee = self._qualify_name(callee)

        return Call(id=self._next_expr_id(), callee=callee or "<unknown>", args=args, type_args=type_args)

    def _parse_index_expr(self, node) -> Call:
        """Parse index expression as Call: grid[x, y] -> Call(callee='[]', args=[x, y], receiver=grid)."""
        base_expr: Optional[Expr] = None
        indices: List[Expr] = []

        for child in node.children:
            if child.type in ("[", "]", ",", "newline"):
                continue
            elif base_expr is None:
                base_expr = self._parse_expr(child)
            else:
                indices.append(self._parse_expr(child))

        return Call(id=self._next_expr_id(), callee="[]", args=indices, receiver=base_expr)

    def _parse_lambda_expr(self, node) -> Expr:
        """Parse lambda expression: |x| {...} -> Block with lambda body.

        We parse the body so captured variables are tracked for unused-arg detection.
        """
        for child in node.children:
            if child.type == "block":
                return self._parse_block_expr(child)
        # Fallback for simple lambdas without block: |x| expr
        return Unknown(id=self._next_expr_id(), raw=self._get_text(node))

    def _parse_arg_list(self, node) -> List[Expr]:
        """Parse an arg_list into expressions."""
        args = []
        for child in node.children:
            if child.type in ("(", ")", ",", "newline"):
                continue
            expr = self._parse_expr(child)
            args.append(expr)
        return args

    def _parse_binary_expr(self, node) -> BinOp:
        """Parse a binary expression."""
        left: Optional[Expr] = None
        right: Optional[Expr] = None
        op: str = ""

        for child in node.children:
            if child.type == "binary_operator":
                op = self._get_text(child)
            elif left is None:
                left = self._parse_expr(child)
            else:
                right = self._parse_expr(child)

        return BinOp(
            id=self._next_expr_id(),
            op=op,
            left=left or Unknown(id=self._next_expr_id(), raw="<missing>"),
            right=right or Unknown(id=self._next_expr_id(), raw="<missing>"),
        )

    def _parse_unary_expr(self, node) -> UnaryOp:
        """Parse a unary expression."""
        op: str = ""
        operand: Optional[Expr] = None

        for child in node.children:
            if child.type == "unary_operator":
                op = self._get_text(child)
            elif child.type in ("!", "-"):
                op = self._get_text(child)
            else:
                operand = self._parse_expr(child)

        return UnaryOp(
            id=self._next_expr_id(), op=op, operand=operand or Unknown(id=self._next_expr_id(), raw="<missing>")
        )

    def _parse_borrow_expr(self, node) -> Borrow:
        """Parse a borrow expression (&x or &mut x)."""
        inner: Optional[Expr] = None
        mutable = False

        for child in node.children:
            if child.type == "imm_ref":
                mutable = False
            elif child.type == "mut_ref":
                mutable = True
            elif child.type not in ("&", "mut"):
                inner = self._parse_expr(child)

        return Borrow(
            id=self._next_expr_id(), inner=inner or Unknown(id=self._next_expr_id(), raw="<missing>"), mutable=mutable
        )

    def _parse_deref_expr(self, node) -> Deref:
        """Parse a dereference expression (*x)."""
        inner: Optional[Expr] = None

        for child in node.children:
            if child.type != "*":
                inner = self._parse_expr(child)
                break

        return Deref(id=self._next_expr_id(), inner=inner or Unknown(id=self._next_expr_id(), raw="<missing>"))

    def _parse_vector_expr(self, node) -> Vector:
        """Parse a vector literal."""
        elements: List[Expr] = []

        for child in node.children:
            if child.type in ("vector[", "]", ","):
                continue
            elements.append(self._parse_expr(child))

        return Vector(id=self._next_expr_id(), elements=elements)

    def _parse_expression_list(self, node) -> Expr:
        """Parse expression_list (tuple or parenthesized expression).

        Tree-sitter uses expression_list for:
        1. Tuple literals: (a, b, c)
        2. Parenthesized expressions: (a * b)

        For single expression (a * b), we unwrap and return the inner expression.
        For multiple expressions (a, b, c), we return as Vector (tuple).
        """
        elements: List[Expr] = []

        for child in node.children:
            if child.type in ("(", ")", ",", "newline"):
                continue
            expr = self._parse_expr(child)
            elements.append(expr)

        if len(elements) == 1:
            # Parenthesized expression: (a * b) -> unwrap
            return elements[0]
        else:
            # Tuple: (a, b, c) -> Vector IR type
            return Vector(id=self._next_expr_id(), elements=elements)

    def _parse_pack_expr(self, node) -> StructPack:
        """Parse a struct pack expression (MyStruct { f1: v1, f2: v2 })."""
        struct_name: str = ""
        fields: List[tuple] = []

        for child in node.children:
            if child.type == "name_expression":
                for sub in child.children:
                    if sub.type == "module_access":
                        parts = []
                        for ident in sub.children:
                            if ident.type in ("identifier", "module_identifier"):
                                parts.append(self._get_text(ident))
                        struct_name = "::".join(parts)
            elif child.type == "field_initialize_list":
                fields = self._parse_field_init_list(child)

        return StructPack(id=self._next_expr_id(), struct_name=self._qualify_name(struct_name), fields=fields)

    def _parse_field_init_list(self, node) -> List[tuple]:
        """Parse field initializations.

        Handles both explicit and shorthand syntax:
        - Explicit: `field: value`
        - Shorthand: `field` (equivalent to `field: field`)
        """
        fields = []

        for child in node.children:
            if child.type == "exp_field":
                field_name: Optional[str] = None
                field_value: Optional[Expr] = None

                for sub in child.children:
                    if sub.type == "field_identifier":
                        field_name = self._get_text(sub)
                    elif sub.type != ":":
                        field_value = self._parse_expr(sub)

                if field_name is not None:
                    # Handle shorthand syntax: `field` means `field: field`
                    # Create a VarRef so the variable usage is tracked
                    if field_value is None:
                        field_value = VarRef(id=self._next_expr_id(), name=field_name)
                    fields.append((field_name, field_value))

        return fields

    def _parse_if_expr(self, node) -> IfExpr:
        """Parse an if expression."""
        condition: Optional[Expr] = None
        then_branch: Optional[Expr] = None
        else_branch: Optional[Expr] = None

        seen_else = False
        for child in node.children:
            if child.type == "else":
                seen_else = True
            elif child.type == "block":
                block_expr = self._parse_block_expr(child)
                if not seen_else:
                    then_branch = block_expr
                else:
                    else_branch = block_expr
            elif child.type == "if_expression":
                # else if case
                else_branch = self._parse_if_expr(child)
            elif child.type not in ("if", "(", ")"):
                if condition is None:
                    condition = self._parse_expr(child)

        return IfExpr(
            id=self._next_expr_id(),
            condition=condition or Unknown(id=self._next_expr_id(), raw="<missing>"),
            then_branch=then_branch or Unknown(id=self._next_expr_id(), raw="<missing>"),
            else_branch=else_branch,
        )

    def _parse_block_expr(self, node) -> Block:
        """Parse a block as an expression."""
        stmts: List[Stmt] = []
        final_expr: Optional[Expr] = None

        for child in node.children:
            if child.type == "block_item":
                stmt = self._parse_block_item(child)
                if stmt:
                    stmts.append(stmt)
            elif child.type not in ("{", "}", "newline"):
                # Final expression without semicolon
                final_expr = self._parse_expr(child)

        return Block(id=self._next_expr_id(), stmts=stmts, final_expr=final_expr)

    def _parse_cast_expr(self, node) -> Cast:
        """Parse a cast_expression: (expr as Type)"""
        inner_expr: Optional[Expr] = None
        target_type: str = ""

        for child in node.children:
            if child.type == "as":
                # Skip the 'as' keyword
                continue
            elif child.type in ("primitive_type", "u8", "u16", "u32", "u64", "u128", "u256"):
                # The target type (u8, u64, u128, etc.)
                target_type = self._get_text(child)
            elif child.type == "apply_type":
                # Generic type like Option<u64>
                target_type = self._get_text(child)
            else:
                # Any other child is the expression being cast
                # Recursively parse it (handles nested casts, binary ops, etc.)
                inner_expr = self._parse_expr(child)

        if not inner_expr:
            # Fallback if we couldn't parse the inner expression
            inner_expr = Unknown(id=self._next_expr_id(), raw=self._get_text(node))

        return Cast(id=self._next_expr_id(), inner=inner_expr, target_type=target_type)

    def _extract_type_arguments(self, name_expr_node) -> List[str]:
        """Extract type arguments from a name_expression node.

        For nested types like Balance<T>, extracts inner type parameters.
        Returns flattened list of all type parameters found.
        """
        type_args = []

        def find_type_arguments(node):
            if node.type == "type_arguments":
                for type_child in node.children:
                    if type_child.type in ("apply_type", "ref_type", "primitive_type", "tuple_type", "identifier"):
                        # Extract all type params (including nested ones)
                        extracted = self._extract_type_params_from_node(type_child)
                        type_args.extend(extracted)
            for child in node.children:
                find_type_arguments(child)

        find_type_arguments(name_expr_node)
        return type_args

    def _extract_type_params_from_node(self, type_node) -> List[str]:
        """Extract all type parameters from a type node, including nested ones.

        For simple type params: T -> ["T"]
        For simple nested types: Balance<T> -> ["T"]
        For multi-param nested types: LP<T0, T1> -> ["T0", "T1"]
        For deeply nested: Wrapper<Balance<T>> -> ["T"]

        Returns flattened list of type parameters found.
        If the node IS a simple type param (not nested), returns it directly.
        If the node IS a nested type (apply_type), extracts inner type params recursively.
        """
        result = []

        if type_node.type == "apply_type":
            # apply_type has: module_access (outer type) + type_arguments (inner params)
            # Extract the inner type params recursively
            has_inner_params = False
            for child in type_node.children:
                if child.type == "type_arguments":
                    has_inner_params = True
                    # Recursively extract from nested type_arguments
                    for inner_child in child.children:
                        if inner_child.type in (
                            "apply_type",
                            "ref_type",
                            "primitive_type",
                            "tuple_type",
                            "identifier",
                            "module_access",
                        ):
                            result.extend(self._extract_type_params_from_node(inner_child))

            # If no inner params found, this might be a bare type name - check module_access
            if not has_inner_params:
                for child in type_node.children:
                    if child.type == "module_access":
                        # Check if it's a simple identifier (type param like T)
                        parts = []
                        for name_child in child.children:
                            if name_child.type in ("identifier", "module_identifier"):
                                parts.append(self._get_text(name_child))
                        if len(parts) == 1 and "::" not in parts[0]:
                            # Single identifier = type param reference
                            result.append(parts[0])
        elif type_node.type == "module_access":
            # module_access might be a simple type param like T
            parts = []
            for name_child in type_node.children:
                if name_child.type in ("identifier", "module_identifier"):
                    parts.append(self._get_text(name_child))
            if len(parts) == 1 and "::" not in parts[0]:
                # Single identifier = type param reference
                result.append(parts[0])
        elif type_node.type == "ref_type":
            # Recurse through reference types (&T, &mut T)
            for child in type_node.children:
                result.extend(self._extract_type_params_from_node(child))
        elif type_node.type == "identifier":
            # This is a simple type parameter reference (T, U, etc.)
            type_name = self._get_text(type_node).strip()
            if type_name and type_name not in ("<", ">", ","):
                result.append(type_name)
        elif type_node.type == "primitive_type":
            # Primitive types like u64, bool - not type params
            pass
        else:
            # For other node types, try to extract as text if it looks like a type param
            raw = self._get_text(type_node).strip()
            if raw and not raw.startswith("&") and raw not in ("<", ">", ",") and "::" not in raw:
                # Single identifier without :: = likely a type param
                result.append(raw)

        return result

    def _extract_type_from_node(self, type_node) -> Optional[str]:
        """Extract a type name from a type node.

        For type arguments in calls, single identifiers (like T, U) are type parameter
        references and should NOT be qualified. Only multi-part names need qualification.

        NOTE: This extracts only the OUTER type name from nested types.
        For Balance<T>, returns "Balance". Use _extract_type_params_from_node() for inner params.
        """
        if type_node.type == "apply_type":
            for child in type_node.children:
                if child.type == "module_access":
                    parts = []
                    for name_child in child.children:
                        if name_child.type in ("identifier", "module_identifier"):
                            parts.append(self._get_text(name_child))
                    if parts:
                        # Single identifier = type param reference (T, U) - don't qualify
                        # Multi-part = module path (sui::coin::Coin) - qualify
                        if len(parts) == 1:
                            return parts[0]
                        type_name = "::".join(parts)
                        return self._qualify_name(type_name)
        elif type_node.type == "ref_type":
            for child in type_node.children:
                result = self._extract_type_from_node(child)
                if result:
                    return result
        else:
            raw = self._get_text(type_node).strip()
            if raw and not raw.startswith("&") and raw not in ("<", ">", ","):
                # Single identifier = type param reference - don't qualify
                if "::" not in raw:
                    return raw
                return raw
        return None


def build_ir_from_source(source_code: str, root_node) -> Optional[Module]:
    """
    Convenience function to build IR from source code and pre-parsed root node.

    Args:
        source_code: The Move source code
        root_node: tree-sitter root node from parse_move_source()

    Returns:
        Module IR or None if parsing failed
    """
    builder = IRBuilder(source_code)
    return builder.build_module(root_node)
