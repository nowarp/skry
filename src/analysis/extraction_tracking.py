"""
Path-sensitive extraction-transfer typestate analysis.

Tracks whether value extractions (coin::take, balance::split, etc.) are
matched by transfers (transfer::public_transfer, etc.) on ALL control
flow paths. Put-backs (coin::put) do NOT count as matching — they mean
the user doesn't receive the extracted value.

Built on the forward dataflow framework (taint/dataflow.py) and enhanced
CFG (move/cfg.py).
"""

from dataclasses import dataclass
from typing import FrozenSet, List, Optional, Set

from core.context import ProjectContext
from core.facts import Fact
from core.utils import debug
from move.cfg import CFGBuilder, CFGNode
from move.ir import (
    AssignStmt,
    Borrow,
    Call,
    ExprStmt,
    LetStmt,
    ReturnStmt,
    Stmt,
    StructPack,
    VarRef,
    expr_vars,
)
from move.sui_patterns import ALL_TRANSFER_SINKS, is_value_extraction_call
from taint.dataflow import ForwardAnalysis


# =============================================================================
# Extraction State
# =============================================================================


@dataclass(frozen=True)
class ExtractionState:
    """Typestate for extraction-transfer tracking at a CFG point.

    An extraction is "matched" only by transfer (or return for Coin-returning functions).
    Put-back does NOT match an extraction — it means the user doesn't receive the value.
    """

    # Vars holding extracted value not yet transferred
    live: FrozenSet[str]
    # Vars that have been transferred on ALL paths reaching here
    transferred: FrozenSet[str]

    @staticmethod
    def empty() -> "ExtractionState":
        return ExtractionState(frozenset(), frozenset())


# =============================================================================
# Transfer function helpers
# =============================================================================


def _is_transfer_callee(callee: str) -> bool:
    """Check if callee is a transfer function."""
    from core.utils import get_simple_name

    if callee in ALL_TRANSFER_SINKS:
        return True
    simple = get_simple_name(callee)
    return simple in {"transfer", "public_transfer", "share_object", "public_share_object"}


def _get_extraction_var(stmt: Stmt) -> Optional[str]:
    """If stmt is a let/assign with extraction call, return the bound variable name."""
    if isinstance(stmt, LetStmt) and stmt.value and isinstance(stmt.value, Call):
        if is_value_extraction_call(stmt.value.callee):
            return stmt.bindings[0] if stmt.bindings else None
    if isinstance(stmt, AssignStmt) and isinstance(stmt.value, Call):
        if is_value_extraction_call(stmt.value.callee):
            if isinstance(stmt.target, VarRef):
                return stmt.target.name
    return None


def _get_transfer_vars(stmt: Stmt) -> Set[str]:
    """If stmt is a call to a transfer function, return the arg variable names."""
    call = None
    if isinstance(stmt, ExprStmt) and isinstance(stmt.expr, Call):
        call = stmt.expr
    elif isinstance(stmt, LetStmt) and stmt.value and isinstance(stmt.value, Call):
        call = stmt.value

    if call and _is_transfer_callee(call.callee):
        result = set()
        for arg in call.args:
            result.update(expr_vars(arg))
        return result
    return set()


def _get_join_target_and_sources(stmt: Stmt) -> Optional[tuple]:
    """If stmt is coin::join(&mut target, source), return (target_var, source_var)."""
    call = None
    if isinstance(stmt, ExprStmt) and isinstance(stmt.expr, Call):
        call = stmt.expr

    if not call:
        return None

    from core.utils import get_simple_name

    simple = get_simple_name(call.callee)
    if simple != "join":
        return None
    if "coin::" not in call.callee and "balance::" not in call.callee:
        return None

    if len(call.args) >= 2:
        # First arg is &mut target, second is source value
        target_vars = expr_vars(call.args[0])
        source_vars = expr_vars(call.args[1])
        if target_vars and source_vars:
            return (target_vars[0], source_vars[0])
    return None


def _is_return_stmt(stmt: Stmt) -> bool:
    """Check if stmt is a return statement."""
    return isinstance(stmt, ReturnStmt)


def _get_return_vars(stmt: Stmt) -> Set[str]:
    """Get variables referenced in return value."""
    if isinstance(stmt, ReturnStmt) and stmt.value:
        return set(expr_vars(stmt.value))
    return set()


# =============================================================================
# Forward Dataflow Analysis
# =============================================================================


class ExtractionTransferAnalysis(ForwardAnalysis[ExtractionState]):
    """Track extraction variables through the CFG, detecting unmatched extractions."""

    def __init__(self, func_returns_coin: bool = False):
        self._func_returns_coin = func_returns_coin

    def initial_state(self) -> ExtractionState:
        return ExtractionState.empty()

    def transfer(self, node: CFGNode, in_state: ExtractionState) -> ExtractionState:
        live = set(in_state.live)
        transferred = set(in_state.transferred)

        for stmt in node.stmts:
            # Check for extraction: let var = coin::take(...)
            ext_var = _get_extraction_var(stmt)
            if ext_var:
                live.add(ext_var)
                # Consume by-value args that are in live (e.g. balance::split → coin::from_balance chain)
                call = stmt.value if isinstance(stmt, LetStmt) else None
                if call is None and isinstance(stmt, AssignStmt):
                    call = stmt.value
                if isinstance(call, Call):
                    for arg in call.args:
                        if not isinstance(arg, Borrow):
                            for v in expr_vars(arg):
                                live.discard(v)

            # Check for transfer: transfer::public_transfer(var, ...)
            transfer_vars = _get_transfer_vars(stmt)
            for tv in transfer_vars:
                if tv in live:
                    live.discard(tv)
                    transferred.add(tv)

            # Check for coin::join(&mut target, source) — source is consumed, target gets taint
            join_result = _get_join_target_and_sources(stmt)
            if join_result:
                target_var, source_var = join_result
                if source_var in live:
                    live.discard(source_var)
                    live.add(target_var)

            # Check for return: if function returns the extracted value, it's handled
            if _is_return_stmt(stmt) and self._func_returns_coin:
                ret_vars = _get_return_vars(stmt)
                for rv in ret_vars:
                    if rv in live:
                        live.discard(rv)
                        transferred.add(rv)

            # Assignment propagation: let x = y (move semantics)
            if isinstance(stmt, LetStmt) and stmt.value and not ext_var:
                if isinstance(stmt.value, VarRef) and stmt.value.name in live:
                    live.discard(stmt.value.name)
                    if stmt.bindings:
                        live.add(stmt.bindings[0])
                # StructPack consumption: let x = Foo { field: y }
                elif isinstance(stmt.value, StructPack):
                    consumed_any = False
                    for _, field_expr in stmt.value.fields:
                        for v in expr_vars(field_expr):
                            if v in live:
                                live.discard(v)
                                consumed_any = True
                    if consumed_any and stmt.bindings:
                        live.add(stmt.bindings[0])

        return ExtractionState(frozenset(live), frozenset(transferred))

    def merge(self, states: List[ExtractionState]) -> ExtractionState:
        if not states:
            return self.initial_state()
        # live = union (may be live on any path)
        live = frozenset().union(*(s.live for s in states))
        # transferred = intersection (MUST be transferred on ALL paths)
        transferred = states[0].transferred
        for s in states[1:]:
            transferred = transferred & s.transferred
        return ExtractionState(live, transferred)

    def equals(self, a: ExtractionState, b: ExtractionState) -> bool:
        return a == b


# =============================================================================
# Callee-level unmatched extraction check
# =============================================================================


def _check_callee_unmatched(func_name: str, all_facts: List[Fact], ctx: ProjectContext) -> bool:
    """Check if any callee has value extraction without transfer (diamond pattern)."""
    call_graph = getattr(ctx, "call_graph", None)
    if call_graph is None:
        return False

    callees = call_graph.transitive_callees.get(func_name, set())
    for callee in callees:
        has_extraction = any(f.name == "HasValueExtraction" and f.args[0] == callee for f in all_facts)
        has_transfer = any(f.name == "Transfers" and f.args[0] == callee for f in all_facts)
        if has_extraction and not has_transfer:
            debug(f"[extraction_tracking] {func_name}: callee {callee} has extraction without transfer")
            return True

    return False


# =============================================================================
# Entry point
# =============================================================================


def _func_returns_coin_type(func_name: str, facts: List[Fact]) -> bool:
    """Check if function returns Coin/Balance type."""
    return any(f.name == "ReturnsCoinType" and f.args[0] == func_name for f in facts)


def run_extraction_analysis(ctx: ProjectContext) -> None:
    """Run path-sensitive extraction-transfer analysis on all functions.

    Builds enhanced CFG per function, runs ExtractionTransferAnalysis,
    and emits UnmatchedExtraction facts.
    """
    fact_count = 0

    for file_path, file_ctx in ctx.source_files.items():
        # Gather all facts (local + global index) for callee lookup
        all_file_facts = list(file_ctx.facts)

        for func_name, func_ir in ctx.module_index.items():
            # Only analyze functions defined in this file
            if func_name not in ctx.global_facts_index:
                continue
            if file_path not in ctx.global_facts_index[func_name]:
                continue

            # Skip functions that return Coin type (caller handles transfer)
            func_facts = []
            for fp_facts in ctx.global_facts_index[func_name].values():
                func_facts.extend(fp_facts)
            func_facts.extend(all_file_facts)

            returns_coin = _func_returns_coin_type(func_name, func_facts)

            # Check 1: callee-level unmatched extraction (diamond pattern)
            if _check_callee_unmatched(func_name, func_facts, ctx):
                _emit_fact(ctx, file_path, file_ctx, func_name, "callee")
                fact_count += 1
                continue

            # Check 2: path-sensitive intraprocedural analysis
            try:
                cfg = CFGBuilder().build(func_ir)
            except Exception as e:
                debug(f"[extraction_tracking] CFG build failed for {func_name}: {e}")
                continue

            analysis = ExtractionTransferAnalysis(func_returns_coin=returns_coin)
            try:
                out_states = analysis.run(cfg)
            except Exception as e:
                debug(f"[extraction_tracking] analysis failed for {func_name}: {e}")
                continue

            # Check exit node state
            exit_state = out_states.get(cfg.exit_id)
            if exit_state is None:
                continue

            # Any live extraction var at exit that wasn't transferred on all paths
            unmatched = exit_state.live - exit_state.transferred
            if unmatched:
                for var in unmatched:
                    _emit_fact(ctx, file_path, file_ctx, func_name, var)
                    fact_count += 1

    if fact_count > 0:
        debug(f"[extraction_tracking] Generated {fact_count} UnmatchedExtraction facts")


def _emit_fact(ctx: ProjectContext, file_path: str, file_ctx, func_name: str, var: str) -> None:
    """Emit an UnmatchedExtraction fact and register it in indexes."""
    fact = Fact("UnmatchedExtraction", (func_name, var))

    # Add to file facts
    if not any(f.name == "UnmatchedExtraction" and f.args[0] == func_name and f.args[1] == var for f in file_ctx.facts):
        file_ctx.facts.append(fact)

    # Add to global facts index
    if func_name in ctx.global_facts_index:
        for fp, fp_facts in ctx.global_facts_index[func_name].items():
            if not any(
                f.name == "UnmatchedExtraction" and f.args[0] == func_name and f.args[1] == var for f in fp_facts
            ):
                fp_facts.append(fact)
