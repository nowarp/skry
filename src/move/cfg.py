"""
Minimal Control Flow Graph for dataflow analysis.

This CFG is intentionally minimal - it only tracks:
- Control flow structure (branches, merges)
- Function call sites (callee names only)

We don't track variables, expressions, or assignments.
This is sufficient for "must-call-before" style analyses.

This module also includes the CFGBuilder that converts Move IR to CFG.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Literal

from .ir import (
    Function,
    Stmt,
    LetStmt,
    ExprStmt,
    IfStmt,
    WhileStmt,
    LoopStmt,
    ReturnStmt,
    AbortStmt,
    BreakStmt,
    ContinueStmt,
    AssignStmt,
    Call,
)


# =============================================================================
# CFG Data Structures
# =============================================================================


@dataclass
class CFGNode:
    """A node in the control flow graph."""

    id: str
    kind: Literal["entry", "exit", "call", "branch", "merge"]
    callee: Optional[str] = None  # Only for kind="call"
    line: int = 0
    succs: List[str] = field(default_factory=list)
    preds: List[str] = field(default_factory=list)

    def __repr__(self):
        if self.kind == "call":
            return f"CFGNode({self.id}, call:{self.callee})"
        return f"CFGNode({self.id}, {self.kind})"


@dataclass
class FunctionCFG:
    """Control flow graph for a single function."""

    func_name: str
    nodes: Dict[str, CFGNode] = field(default_factory=dict)
    entry_id: str = "entry"
    exit_id: str = "exit"

    def add_node(self, node: CFGNode):
        """Add a node to the CFG."""
        self.nodes[node.id] = node

    def link(self, from_id: str, to_id: str):
        """Add an edge from one node to another."""
        if from_id in self.nodes and to_id in self.nodes:
            if to_id not in self.nodes[from_id].succs:
                self.nodes[from_id].succs.append(to_id)
            if from_id not in self.nodes[to_id].preds:
                self.nodes[to_id].preds.append(from_id)

    def __repr__(self):
        return f"FunctionCFG({self.func_name}, {len(self.nodes)} nodes)"


# =============================================================================
# =============================================================================
# CFG Builder - converts Move IR to CFG
# =============================================================================


class CFGBuilder:
    """Builds a CFG from a Move IR Function."""

    def __init__(self):
        self._node_counter = 0
        self._cfg_internal: Optional[FunctionCFG] = None
        # For handling break/continue in loops
        self._loop_exit_stack: List[str] = []
        self._loop_header_stack: List[str] = []

    @property
    def _cfg(self) -> FunctionCFG:
        """Access CFG with assertion - always set during build()."""
        assert self._cfg_internal is not None, "CFG not initialized"
        return self._cfg_internal

    def _next_id(self, prefix: str) -> str:
        self._node_counter += 1
        return f"{prefix}_{self._node_counter}"

    def build(self, func: Function) -> FunctionCFG:
        """Build CFG for a function."""
        self._node_counter = 0
        self._cfg_internal = FunctionCFG(func_name=func.name)
        self._loop_exit_stack = []
        self._loop_header_stack = []

        # Create entry and exit nodes
        entry = CFGNode(id="entry", kind="entry", line=func.line)
        exit_node = CFGNode(id="exit", kind="exit", line=func.line)
        self._cfg.add_node(entry)
        self._cfg.add_node(exit_node)

        # Process function body
        if func.body:
            last_id = self._process_stmts(func.body, "entry")
            if last_id:
                self._cfg.link(last_id, "exit")
        else:
            self._cfg.link("entry", "exit")

        return self._cfg

    def _process_stmts(self, stmts: List[Stmt], pred_id: str) -> Optional[str]:
        """
        Process a list of statements, linking them in sequence.
        Returns the ID of the last node, or None if control doesn't reach the end.
        """
        curr = pred_id

        for stmt in stmts:
            result = self._process_stmt(stmt, curr)
            if result is None:
                # Control flow doesn't continue (return, abort, break, continue)
                return None
            curr = result

        return curr

    def _process_stmt(self, stmt: Stmt, pred_id: str) -> Optional[str]:
        """
        Process a single statement.
        Returns the ID of the node to continue from, or None if control doesn't continue.
        """
        if isinstance(stmt, LetStmt):
            return self._process_let(stmt, pred_id)
        elif isinstance(stmt, ExprStmt):
            return self._process_expr_stmt(stmt, pred_id)
        elif isinstance(stmt, AssignStmt):
            return self._process_assign(stmt, pred_id)
        elif isinstance(stmt, IfStmt):
            return self._process_if(stmt, pred_id)
        elif isinstance(stmt, WhileStmt):
            return self._process_while(stmt, pred_id)
        elif isinstance(stmt, LoopStmt):
            return self._process_loop(stmt, pred_id)
        elif isinstance(stmt, ReturnStmt):
            return self._process_return(stmt, pred_id)
        elif isinstance(stmt, AbortStmt):
            return self._process_abort(stmt, pred_id)
        elif isinstance(stmt, BreakStmt):
            return self._process_break(stmt, pred_id)
        elif isinstance(stmt, ContinueStmt):
            return self._process_continue(stmt, pred_id)
        else:
            # Unknown statement type - just continue
            return pred_id

    def _process_let(self, stmt: LetStmt, pred_id: str) -> str:
        """Process let statement - extract calls from the value."""
        if stmt.value and isinstance(stmt.value, Call):
            node = CFGNode(id=self._next_id("call"), kind="call", callee=stmt.value.callee, line=stmt.line)
            self._cfg.add_node(node)
            self._cfg.link(pred_id, node.id)
            return node.id
        # For non-call lets, just continue
        return pred_id

    def _process_expr_stmt(self, stmt: ExprStmt, pred_id: str) -> str:
        """Process expression statement - extract calls."""
        if isinstance(stmt.expr, Call):
            node = CFGNode(id=self._next_id("call"), kind="call", callee=stmt.expr.callee, line=stmt.line)
            self._cfg.add_node(node)
            self._cfg.link(pred_id, node.id)
            return node.id
        return pred_id

    def _process_assign(self, stmt: AssignStmt, pred_id: str) -> str:
        """Process assignment - extract calls from RHS."""
        if stmt.value and isinstance(stmt.value, Call):
            node = CFGNode(id=self._next_id("call"), kind="call", callee=stmt.value.callee, line=stmt.line)
            self._cfg.add_node(node)
            self._cfg.link(pred_id, node.id)
            return node.id
        return pred_id

    def _process_if(self, stmt: IfStmt, pred_id: str) -> Optional[str]:
        """Process if statement with branches."""
        # Create branch node
        branch = CFGNode(id=self._next_id("branch"), kind="branch", line=stmt.line)
        self._cfg.add_node(branch)
        self._cfg.link(pred_id, branch.id)

        # Create merge node
        merge = CFGNode(id=self._next_id("merge"), kind="merge", line=stmt.line)
        self._cfg.add_node(merge)

        # Process then branch
        then_end = self._process_stmts(stmt.then_body, branch.id)
        if then_end:
            self._cfg.link(then_end, merge.id)

        # Process else branch (or empty path)
        if stmt.else_body:
            else_end = self._process_stmts(stmt.else_body, branch.id)
            if else_end:
                self._cfg.link(else_end, merge.id)
        else:
            # Empty else - direct link from branch to merge
            self._cfg.link(branch.id, merge.id)

        # If both branches don't reach merge, merge is unreachable
        if not merge.preds:
            return None

        return merge.id

    def _process_while(self, stmt: WhileStmt, pred_id: str) -> str:
        """Process while loop."""
        # Create loop header (condition check)
        header = CFGNode(id=self._next_id("loop_header"), kind="branch", line=stmt.line)
        self._cfg.add_node(header)
        self._cfg.link(pred_id, header.id)

        # Create exit node for the loop
        exit_node = CFGNode(id=self._next_id("loop_exit"), kind="merge", line=stmt.line)
        self._cfg.add_node(exit_node)

        # Push loop context
        self._loop_header_stack.append(header.id)
        self._loop_exit_stack.append(exit_node.id)

        # Process body
        body_end = self._process_stmts(stmt.body, header.id)
        if body_end:
            # Back edge to header
            self._cfg.link(body_end, header.id)

        # Pop loop context
        self._loop_header_stack.pop()
        self._loop_exit_stack.pop()

        # False branch exits the loop
        self._cfg.link(header.id, exit_node.id)

        return exit_node.id

    def _process_loop(self, stmt: LoopStmt, pred_id: str) -> Optional[str]:
        """Process infinite loop (exits via break)."""
        # Create loop header
        header = CFGNode(id=self._next_id("loop_header"), kind="branch", line=stmt.line)
        self._cfg.add_node(header)
        self._cfg.link(pred_id, header.id)

        # Create exit node
        exit_node = CFGNode(id=self._next_id("loop_exit"), kind="merge", line=stmt.line)
        self._cfg.add_node(exit_node)

        # Push loop context
        self._loop_header_stack.append(header.id)
        self._loop_exit_stack.append(exit_node.id)

        # Process body
        body_end = self._process_stmts(stmt.body, header.id)
        if body_end:
            # Back edge
            self._cfg.link(body_end, header.id)

        # Pop loop context
        self._loop_header_stack.pop()
        self._loop_exit_stack.pop()

        # If no breaks, loop is infinite (no exit)
        if not exit_node.preds:
            return None

        return exit_node.id

    def _process_return(self, stmt: ReturnStmt, pred_id: str) -> Optional[str]:
        """Process return - links directly to exit."""
        self._cfg.link(pred_id, "exit")
        return None  # Control doesn't continue after return

    def _process_abort(self, stmt: AbortStmt, pred_id: str) -> Optional[str]:
        """Process abort - no successor."""
        # Abort doesn't reach exit - it's a dead end
        return None

    def _process_break(self, stmt: BreakStmt, pred_id: str) -> Optional[str]:
        """Process break - jumps to loop exit."""
        if self._loop_exit_stack:
            self._cfg.link(pred_id, self._loop_exit_stack[-1])
        return None

    def _process_continue(self, stmt: ContinueStmt, pred_id: str) -> Optional[str]:
        """Process continue - jumps to loop header."""
        if self._loop_header_stack:
            self._cfg.link(pred_id, self._loop_header_stack[-1])
        return None
