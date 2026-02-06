"""
Enhanced Control Flow Graph for dataflow analysis.

This CFG tracks:
- Control flow structure (branches, merges, loops)
- Function call sites (callee names)
- All IR statements in basic blocks (for typestate analysis)
- Branch conditions and edge labels (true/false)

This module also includes the CFGBuilder that converts Move IR to CFG.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Literal

from .ir import (
    Expr,
    Function,
    Stmt,
    IfStmt,
    WhileStmt,
    LoopStmt,
    ReturnStmt,
    AbortStmt,
    BreakStmt,
    ContinueStmt,
)


# =============================================================================
# CFG Data Structures
# =============================================================================


@dataclass
class CFGNode:
    """A node in the control flow graph."""

    id: str
    kind: Literal["entry", "exit", "call", "block", "branch", "merge"]
    callee: Optional[str] = None  # Only for kind="call"
    stmts: List[Stmt] = field(default_factory=list)
    condition: Optional[Expr] = None  # Branch condition (for kind="branch")
    edge_labels: Dict[str, str] = field(default_factory=dict)  # {succ_id: "true"/"false"}
    line: int = 0
    succs: List[str] = field(default_factory=list)
    preds: List[str] = field(default_factory=list)

    def __repr__(self):
        if self.kind == "call":
            return f"CFGNode({self.id}, call:{self.callee})"
        if self.kind == "block":
            return f"CFGNode({self.id}, block, {len(self.stmts)} stmts)"
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
# CFG Builder - converts Move IR to CFG
# =============================================================================


def _is_branching(stmt: Stmt) -> bool:
    """Check if statement introduces control flow branching."""
    return isinstance(stmt, (IfStmt, WhileStmt, LoopStmt, ReturnStmt, AbortStmt, BreakStmt, ContinueStmt))


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
        """Process a list of statements, accumulating sequential stmts into block nodes."""
        curr = pred_id
        pending: List[Stmt] = []

        for stmt in stmts:
            if _is_branching(stmt):
                # Flush pending non-branching stmts into a block node
                if pending:
                    curr = self._flush_block(pending, curr)
                    pending = []
                # Process branching statement
                result = self._process_stmt(stmt, curr)
                if result is None:
                    return None
                curr = result
            else:
                # Accumulate non-branching statement
                pending.append(stmt)

        # Flush remaining stmts
        if pending:
            curr = self._flush_block(pending, curr)

        return curr

    def _flush_block(self, stmts: List[Stmt], pred_id: str) -> str:
        """Create a block node from accumulated statements."""
        node = CFGNode(
            id=self._next_id("block"),
            kind="block",
            stmts=list(stmts),
            line=stmts[0].line,
        )
        # Also set callee for call nodes within the block (for backward compat)
        self._cfg.add_node(node)
        self._cfg.link(pred_id, node.id)
        return node.id

    def _process_stmt(self, stmt: Stmt, pred_id: str) -> Optional[str]:
        """Process a single branching statement."""
        if isinstance(stmt, IfStmt):
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
            return pred_id

    def _process_if(self, stmt: IfStmt, pred_id: str) -> Optional[str]:
        """Process if statement with branches."""
        # Create branch node with condition
        branch = CFGNode(id=self._next_id("branch"), kind="branch", condition=stmt.condition, line=stmt.line)
        self._cfg.add_node(branch)
        self._cfg.link(pred_id, branch.id)

        # Create merge node
        merge = CFGNode(id=self._next_id("merge"), kind="merge", line=stmt.line)
        self._cfg.add_node(merge)

        # Process then branch
        then_end = self._process_stmts(stmt.then_body, branch.id)
        if then_end:
            self._cfg.link(then_end, merge.id)

        # Label the true edge (first successor from branch into then-body)
        for succ_id in branch.succs:
            if succ_id != merge.id:
                branch.edge_labels[succ_id] = "true"
                break

        # Process else branch (or empty path)
        if stmt.else_body:
            else_end = self._process_stmts(stmt.else_body, branch.id)
            if else_end:
                self._cfg.link(else_end, merge.id)
            # Label the false edge
            for succ_id in branch.succs:
                if succ_id not in branch.edge_labels:
                    branch.edge_labels[succ_id] = "false"
                    break
        else:
            # Empty else - direct link from branch to merge
            self._cfg.link(branch.id, merge.id)
            branch.edge_labels[merge.id] = "false"

        # If both branches don't reach merge, merge is unreachable
        if not merge.preds:
            return None

        return merge.id

    def _process_while(self, stmt: WhileStmt, pred_id: str) -> str:
        """Process while loop."""
        # Create loop header (condition check)
        header = CFGNode(id=self._next_id("loop_header"), kind="branch", condition=stmt.condition, line=stmt.line)
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

        # Label edges: body entry = true, exit = false
        for succ_id in header.succs:
            if succ_id != exit_node.id:
                header.edge_labels[succ_id] = "true"
                break

        # False branch exits the loop
        self._cfg.link(header.id, exit_node.id)
        header.edge_labels[exit_node.id] = "false"

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

        # Label body entry edge as true
        for succ_id in header.succs:
            if succ_id != exit_node.id:
                header.edge_labels[succ_id] = "true"
                break

        # Pop loop context
        self._loop_header_stack.pop()
        self._loop_exit_stack.pop()

        # If no breaks, loop is infinite (no exit)
        if not exit_node.preds:
            return None

        return exit_node.id

    def _process_return(self, stmt: ReturnStmt, pred_id: str) -> Optional[str]:
        """Process return - add stmt to a block node and link to exit."""
        # Create block node for the return stmt so it's visible in the CFG
        node = CFGNode(id=self._next_id("block"), kind="block", stmts=[stmt], line=stmt.line)
        self._cfg.add_node(node)
        self._cfg.link(pred_id, node.id)
        self._cfg.link(node.id, "exit")
        return None  # Control doesn't continue after return

    def _process_abort(self, stmt: AbortStmt, pred_id: str) -> Optional[str]:
        """Process abort - no successor."""
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
