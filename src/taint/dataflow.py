"""
Generic forward dataflow analysis framework over enhanced CFG.

Provides a worklist-based fixpoint algorithm parameterized by:
- State type S
- Transfer function (node -> state transformation)
- Merge function (join at control flow confluences)
"""

from abc import ABC, abstractmethod
from typing import Dict, Generic, List, TypeVar

from move.cfg import CFGNode, FunctionCFG

S = TypeVar("S")


class ForwardAnalysis(ABC, Generic[S]):
    """Generic forward dataflow analysis over enhanced CFG."""

    @abstractmethod
    def initial_state(self) -> S:
        """Return the initial state at the entry node."""
        ...

    @abstractmethod
    def transfer(self, node: CFGNode, in_state: S) -> S:
        """Apply the transfer function for a node."""
        ...

    @abstractmethod
    def merge(self, states: List[S]) -> S:
        """Merge states at a control flow join point."""
        ...

    @abstractmethod
    def equals(self, a: S, b: S) -> bool:
        """Check if two states are equal (for fixpoint detection)."""
        ...

    def run(self, cfg: FunctionCFG) -> Dict[str, S]:
        """Worklist algorithm. Returns out-state per node ID."""
        out: Dict[str, S] = {}
        worklist = list(cfg.nodes.keys())

        while worklist:
            node_id = worklist.pop(0)
            node = cfg.nodes[node_id]

            # Merge predecessor out-states
            pred_states = [out[p] for p in node.preds if p in out]
            in_state = self.merge(pred_states) if pred_states else self.initial_state()

            new_out = self.transfer(node, in_state)

            if node_id not in out or not self.equals(out[node_id], new_out):
                out[node_id] = new_out
                for succ in node.succs:
                    if succ not in worklist:
                        worklist.append(succ)

        return out
