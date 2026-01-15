"""
Move IR - Minimal typed AST for taint analysis.

This IR is designed specifically for dataflow analysis, not full Move semantics.
We care about:
- Variable bindings and assignments (data flow)
- Function calls with arguments (taint propagation)
- Field accesses (object state)
- Control flow structure (for future dominance analysis)

We deliberately ignore:
- Type parameters / generics
- Abilities (copy, drop, store, key)
- Visibility modifiers beyond public/entry
- Macro expansion
- Specs / invariants
"""

from dataclasses import dataclass, field
from typing import List, Optional, Any, Dict, Tuple


# =============================================================================
# Expressions
# =============================================================================


@dataclass
class Expr:
    """Base expression. All expressions have unique IDs for fact generation."""

    id: str  # e.g., "expr_42"


@dataclass
class VarRef(Expr):
    """Variable reference: `x`, `recipient`"""

    name: str


@dataclass
class FieldAccess(Expr):
    """Field access: `obj.field`, `vault.balance`"""

    base: Expr
    field: str


@dataclass
class Borrow(Expr):
    """Borrow expression: `&x`, `&mut obj.field`"""

    inner: Expr
    mutable: bool


@dataclass
class Deref(Expr):
    """Dereference: `*x`"""

    inner: Expr


@dataclass
class Call(Expr):
    """
    Function call: `foo(a, b)`, `module::func(x)`, or method call: `obj.method(a, b)`

    callee is fully qualified when possible: "sui::transfer::public_transfer"
    type_args contains type parameters: `foo<T, U>(a, b)` -> ["T", "U"]
    receiver is set for method call syntax: `obj.method(args)` -> receiver=obj
    """

    callee: str
    args: List[Expr]
    type_args: List[str] = field(default_factory=list)
    receiver: Optional[Expr] = None


@dataclass
class BinOp(Expr):
    """Binary operation: `a + b`, `x < y`"""

    op: str  # "+", "-", "*", "/", "%", "<", ">", "<=", ">=", "==", "!=", "&&", "||"
    left: Expr
    right: Expr


@dataclass
class UnaryOp(Expr):
    """Unary operation: `!x`, `-y`"""

    op: str  # "!", "-"
    operand: Expr


@dataclass
class Literal(Expr):
    """Literal value: `42`, `@0x1`, `true`, `b"hello"`"""

    value: Any
    kind: str  # "int", "address", "bool", "bytes", "vector"


@dataclass
class Vector(Expr):
    """Vector literal: `vector[a, b, c]`"""

    elements: List[Expr]


@dataclass
class StructPack(Expr):
    """Struct instantiation: `Foo { field1: val1, field2: val2 }`"""

    struct_name: str
    fields: List[tuple]  # [(field_name, Expr), ...]


@dataclass
class IfExpr(Expr):
    """If expression (Move if can be expression): `if (cond) a else b`"""

    condition: Expr
    then_branch: Expr
    else_branch: Optional[Expr]


@dataclass
class Block(Expr):
    """Block expression: `{ stmt1; stmt2; expr }`"""

    stmts: List["Stmt"]
    final_expr: Optional[Expr]  # the expression value of the block, if any


@dataclass
class Cast(Expr):
    """Type cast expression: `(expr as Type)`"""

    inner: Expr
    target_type: str


@dataclass
class Unknown(Expr):
    """Placeholder for expressions we can't/don't parse."""

    raw: str  # original source text


# =============================================================================
# Statements
# =============================================================================


@dataclass
class Stmt:
    """Base statement. All statements have unique IDs and source location."""

    id: str  # e.g., "stmt_7"
    line: int  # source line number


@dataclass
class LetStmt(Stmt):
    """
    Let binding: `let x = expr`, `let (a, b) = tuple_expr`
    For destructuring, bindings contains multiple names.
    """

    bindings: List[str]  # variable name(s) being bound
    value: Optional[Expr]  # None for `let x;` without initializer
    type_ann: Optional[str]  # optional type annotation


@dataclass
class AssignStmt(Stmt):
    """Assignment: `x = expr`, `obj.field = expr`, `*ref = expr`"""

    target: Expr  # VarRef, FieldAccess, or Deref
    value: Expr


@dataclass
class ExprStmt(Stmt):
    """Expression statement: `foo();`, `x + 1;` (result discarded)"""

    expr: Expr


@dataclass
class ReturnStmt(Stmt):
    """Return: `return expr`, `return`"""

    value: Optional[Expr]


@dataclass
class AbortStmt(Stmt):
    """Abort: `abort code`, `abort`"""

    code: Optional[Expr]


@dataclass
class IfStmt(Stmt):
    """
    If statement (when used as statement, not expression).

    For taint: we need to know what's checked in condition,
    and what happens in each branch.
    """

    condition: Expr
    then_body: List[Stmt]
    else_body: Optional[List[Stmt]]


@dataclass
class WhileStmt(Stmt):
    """While loop: `while (cond) { body }`"""

    condition: Expr
    body: List[Stmt]


@dataclass
class LoopStmt(Stmt):
    """Infinite loop: `loop { body }`"""

    body: List[Stmt]


@dataclass
class BreakStmt(Stmt):
    """Break: `break`"""

    pass


@dataclass
class ContinueStmt(Stmt):
    """Continue: `continue`"""

    pass


# =============================================================================
# Function and Module
# =============================================================================


@dataclass
class Param:
    """Function parameter."""

    name: str
    typ: str
    is_mut: bool  # &mut reference
    idx: int  # position in parameter list


@dataclass
class Function:
    """
    Move function definition.

    This is the unit of taint analysis - we analyze each function independently,
    with inter-procedural summary propagation later.
    """

    name: str  # fully qualified: "module::func"
    params: List[Param]
    ret_type: Optional[str]
    body: List[Stmt]
    is_public: bool
    is_entry: bool
    line: int  # source line of function definition


@dataclass
class ConstantDef:
    """Move constant definition: const NAME: TYPE = VALUE;"""

    name: str  # constant name (simple, not qualified)
    value: Any  # parsed value (int, bool, str for address)
    type_str: str  # type as string: "u64", "bool", "address", etc.
    raw_value: str  # original source text of value


@dataclass
class Module:
    """Move module - container for functions."""

    name: str  # fully qualified: "package::module"
    functions: List[Function]
    structs: List[str]  # struct names defined in this module (for context)
    constants: Dict[str, ConstantDef] = field(default_factory=dict)  # name -> ConstantDef


# =============================================================================
# Helpers
# =============================================================================


def expr_vars(expr: Expr) -> List[str]:
    """
    Extract all variable names referenced in an expression.
    Used for taint propagation: if any var is tainted, expression is tainted.
    """
    if isinstance(expr, VarRef):
        return [expr.name]
    elif isinstance(expr, FieldAccess):
        return expr_vars(expr.base)
    elif isinstance(expr, Borrow):
        return expr_vars(expr.inner)
    elif isinstance(expr, Deref):
        return expr_vars(expr.inner)
    elif isinstance(expr, Call):
        result = []
        if expr.receiver:
            result.extend(expr_vars(expr.receiver))
        for arg in expr.args:
            result.extend(expr_vars(arg))
        return result
    elif isinstance(expr, BinOp):
        return expr_vars(expr.left) + expr_vars(expr.right)
    elif isinstance(expr, UnaryOp):
        return expr_vars(expr.operand)
    elif isinstance(expr, Vector):
        result = []
        for elem in expr.elements:
            result.extend(expr_vars(elem))
        return result
    elif isinstance(expr, StructPack):
        result = []
        for _, val in expr.fields:
            result.extend(expr_vars(val))
        return result
    elif isinstance(expr, IfExpr):
        result = expr_vars(expr.condition) + expr_vars(expr.then_branch)
        if expr.else_branch:
            result.extend(expr_vars(expr.else_branch))
        return result
    elif isinstance(expr, Block):
        result = []
        for stmt in expr.stmts:
            result.extend(stmt_vars(stmt))
        if expr.final_expr:
            result.extend(expr_vars(expr.final_expr))
        return result
    elif isinstance(expr, Cast):
        return expr_vars(expr.inner)
    elif isinstance(expr, Literal):
        return []
    elif isinstance(expr, Unknown):
        # Extract variable names from raw string for unparsed expressions (like match)
        return _extract_vars_from_raw(expr.raw)
    return []


def _extract_vars_from_raw(raw: str) -> List[str]:
    """
    Extract variable names from unparsed expression text.

    Used for Unknown expressions (like match) to detect variable usage.
    Conservative: may include more names than actual variables.
    """
    import re

    # Skip if this is just a comment
    stripped = raw.strip()
    if stripped.startswith("//") or stripped.startswith("/*"):
        return []

    # Remove comments from the raw string
    # Remove single-line comments
    raw = re.sub(r"//[^\n]*", "", raw)
    # Remove multi-line comments
    raw = re.sub(r"/\*.*?\*/", "", raw, flags=re.DOTALL)

    # Match Move identifiers that could be variable references
    # Exclude keywords and type names (start with uppercase)
    identifier_pattern = re.compile(r"\b([a-z_][a-zA-Z0-9_]*)\b")

    # Keywords to exclude
    keywords = {
        "match",
        "if",
        "else",
        "while",
        "loop",
        "break",
        "continue",
        "return",
        "let",
        "mut",
        "fun",
        "public",
        "entry",
        "struct",
        "module",
        "use",
        "true",
        "false",
        "abort",
        "as",
        "copy",
        "move",
        "has",
        "acquires",
        "friend",
        "native",
        "const",
        "spec",
        "schema",
        "apply",
        "pragma",
        "assert",
        "assume",
        "ensures",
        "requires",
        "invariant",
        "include",
        "aborts_if",
        "succeeds_if",
        "modifies",
        "emits",
        "forall",
        "exists",
        "where",
        "with",
        "update",
        "pack",
        "unpack",
        "borrow_global",
        "borrow_global_mut",
        "move_from",
        "move_to",
        "vector",
        "option",
    }

    matches = identifier_pattern.findall(raw)
    return [m for m in matches if m not in keywords]


def stmt_vars(stmt: Stmt) -> List[str]:
    """Extract all variable names referenced in a statement."""
    if isinstance(stmt, LetStmt):
        return expr_vars(stmt.value) if stmt.value else []
    elif isinstance(stmt, AssignStmt):
        return expr_vars(stmt.target) + expr_vars(stmt.value)
    elif isinstance(stmt, ExprStmt):
        return expr_vars(stmt.expr)
    elif isinstance(stmt, ReturnStmt):
        return expr_vars(stmt.value) if stmt.value else []
    elif isinstance(stmt, AbortStmt):
        return expr_vars(stmt.code) if stmt.code else []
    elif isinstance(stmt, IfStmt):
        result = expr_vars(stmt.condition)
        for s in stmt.then_body:
            result.extend(stmt_vars(s))
        if stmt.else_body:
            for s in stmt.else_body:
                result.extend(stmt_vars(s))
        return result
    elif isinstance(stmt, WhileStmt):
        result = expr_vars(stmt.condition)
        for s in stmt.body:
            result.extend(stmt_vars(s))
        return result
    elif isinstance(stmt, LoopStmt):
        result = []
        for s in stmt.body:
            result.extend(stmt_vars(s))
        return result
    return []


def expr_field_accesses(expr: Expr) -> List[Tuple[List[str], str]]:
    """
    Extract all field accesses from an expression.
    Returns list of (base_vars, field) tuples.

    Example: `config.paused` returns [(['config'], 'paused')]
    Example: `a.x && b.y` returns [(['a'], 'x'), (['b'], 'y')]
    """
    if isinstance(expr, FieldAccess):
        base_vars = expr_vars(expr.base)
        # Recursively check base for nested field accesses
        nested = expr_field_accesses(expr.base)
        return nested + [(base_vars, expr.field)]
    elif isinstance(expr, Borrow):
        return expr_field_accesses(expr.inner)
    elif isinstance(expr, Deref):
        return expr_field_accesses(expr.inner)
    elif isinstance(expr, Call):
        result = []
        for arg in expr.args:
            result.extend(expr_field_accesses(arg))
        return result
    elif isinstance(expr, BinOp):
        return expr_field_accesses(expr.left) + expr_field_accesses(expr.right)
    elif isinstance(expr, UnaryOp):
        return expr_field_accesses(expr.operand)
    elif isinstance(expr, Vector):
        result = []
        for elem in expr.elements:
            result.extend(expr_field_accesses(elem))
        return result
    elif isinstance(expr, StructPack):
        result = []
        for _, val in expr.fields:
            result.extend(expr_field_accesses(val))
        return result
    elif isinstance(expr, IfExpr):
        result = expr_field_accesses(expr.condition) + expr_field_accesses(expr.then_branch)
        if expr.else_branch:
            result.extend(expr_field_accesses(expr.else_branch))
        return result
    elif isinstance(expr, Block):
        # For blocks, we only care about the final expression for field access purposes
        if expr.final_expr:
            return expr_field_accesses(expr.final_expr)
        return []
    elif isinstance(expr, Cast):
        return expr_field_accesses(expr.inner)
    return []


def expr_calls(expr: Expr) -> List["Call"]:
    """
    Extract all Call expressions nested within an expression.
    Used for generating GenericCallArg facts from calls inside struct initializers.

    Example: `Foo { field: bar<T>() }` returns [Call(bar, type_args=[T])]
    """
    if isinstance(expr, Call):
        result = [expr]
        if expr.receiver:
            result.extend(expr_calls(expr.receiver))
        for arg in expr.args:
            result.extend(expr_calls(arg))
        return result
    elif isinstance(expr, FieldAccess):
        return expr_calls(expr.base)
    elif isinstance(expr, Borrow):
        return expr_calls(expr.inner)
    elif isinstance(expr, Deref):
        return expr_calls(expr.inner)
    elif isinstance(expr, BinOp):
        return expr_calls(expr.left) + expr_calls(expr.right)
    elif isinstance(expr, UnaryOp):
        return expr_calls(expr.operand)
    elif isinstance(expr, Vector):
        result = []
        for elem in expr.elements:
            result.extend(expr_calls(elem))
        return result
    elif isinstance(expr, StructPack):
        result = []
        for _, val in expr.fields:
            result.extend(expr_calls(val))
        return result
    elif isinstance(expr, IfExpr):
        result = expr_calls(expr.condition) + expr_calls(expr.then_branch)
        if expr.else_branch:
            result.extend(expr_calls(expr.else_branch))
        return result
    elif isinstance(expr, Block):
        result = []
        for stmt in expr.stmts:
            if isinstance(stmt, ExprStmt):
                result.extend(expr_calls(stmt.expr))
            elif isinstance(stmt, LetStmt) and stmt.value:
                result.extend(expr_calls(stmt.value))
        if expr.final_expr:
            result.extend(expr_calls(expr.final_expr))
        return result
    elif isinstance(expr, Cast):
        return expr_calls(expr.inner)
    return []


def expr_field_chain(expr: Expr) -> Optional[Tuple[str, List[str]]]:
    """Extract (base_var, field_path) from nested FieldAccess.

    For account.profile.private_key:
    Returns ('account', ['profile', 'private_key'])

    Returns None if expr is not a FieldAccess or base is not a simple VarRef.
    """
    if not isinstance(expr, FieldAccess):
        return None

    fields: List[str] = []
    current: Expr = expr
    while isinstance(current, FieldAccess):
        fields.append(current.field)
        current = current.base

    if isinstance(current, VarRef):
        return (current.name, list(reversed(fields)))
    return None


def find_calls(expr: Expr) -> List[Call]:
    """Find all Call expressions within an expression tree."""
    calls = []
    if isinstance(expr, Call):
        calls.append(expr)
        if expr.receiver:
            calls.extend(find_calls(expr.receiver))
        for arg in expr.args:
            calls.extend(find_calls(arg))
    elif isinstance(expr, FieldAccess):
        calls.extend(find_calls(expr.base))
    elif isinstance(expr, Borrow):
        calls.extend(find_calls(expr.inner))
    elif isinstance(expr, Deref):
        calls.extend(find_calls(expr.inner))
    elif isinstance(expr, BinOp):
        calls.extend(find_calls(expr.left))
        calls.extend(find_calls(expr.right))
    elif isinstance(expr, UnaryOp):
        calls.extend(find_calls(expr.operand))
    elif isinstance(expr, Vector):
        for elem in expr.elements:
            calls.extend(find_calls(elem))
    elif isinstance(expr, StructPack):
        for _, val in expr.fields:
            calls.extend(find_calls(val))
    elif isinstance(expr, IfExpr):
        calls.extend(find_calls(expr.condition))
        calls.extend(find_calls(expr.then_branch))
        if expr.else_branch:
            calls.extend(find_calls(expr.else_branch))
    elif isinstance(expr, Block):
        for stmt in expr.stmts:
            calls.extend(find_calls_in_stmt(stmt))
        if expr.final_expr:
            calls.extend(find_calls(expr.final_expr))
    return calls


def find_calls_in_stmt(stmt: Stmt) -> List[Call]:
    """Find all Call expressions within a statement."""
    if isinstance(stmt, LetStmt) and stmt.value:
        return find_calls(stmt.value)
    elif isinstance(stmt, AssignStmt):
        return find_calls(stmt.target) + find_calls(stmt.value)
    elif isinstance(stmt, ExprStmt):
        return find_calls(stmt.expr)
    elif isinstance(stmt, ReturnStmt) and stmt.value:
        return find_calls(stmt.value)
    elif isinstance(stmt, AbortStmt) and stmt.code:
        return find_calls(stmt.code)
    elif isinstance(stmt, IfStmt):
        calls = find_calls(stmt.condition)
        for s in stmt.then_body:
            calls.extend(find_calls_in_stmt(s))
        if stmt.else_body:
            for s in stmt.else_body:
                calls.extend(find_calls_in_stmt(s))
        return calls
    elif isinstance(stmt, WhileStmt):
        calls = find_calls(stmt.condition)
        for s in stmt.body:
            calls.extend(find_calls_in_stmt(s))
        return calls
    elif isinstance(stmt, LoopStmt):
        calls = []
        for s in stmt.body:
            calls.extend(find_calls_in_stmt(s))
        return calls
    return []
