"""Tests for derived fact generation.

Tests that protective facts are generated directly for functions.
Note: Call graph propagation has been removed - guards are now tracked per-sink.
"""

import textwrap
import tempfile
import os

from core.context import ProjectContext
from analysis import StructuralBuilder
from analysis.derived_facts import compute_derived_facts
from taint import run_structural_taint_analysis


def _build_context_with_propagation(source: str, inject_project_facts: list = None) -> ProjectContext:
    """Helper to build ProjectContext with full pipeline including propagation."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.move', delete=False) as f:
        f.write(textwrap.dedent(source))
        path = f.name

    try:
        ctx = ProjectContext([path])
        StructuralBuilder().build(ctx)
        run_structural_taint_analysis(ctx)

        # Inject project facts before propagation (simulates feature detection)
        if inject_project_facts:
            ctx.project_facts.extend(inject_project_facts)

        compute_derived_facts(ctx)
        return ctx
    finally:
        os.unlink(path)


def _get_facts(ctx: ProjectContext, fact_name: str) -> list:
    """Get all facts of given name from all files."""
    facts = []
    for file_ctx in ctx.source_files.values():
        for fact in file_ctx.facts:
            if fact.name == fact_name:
                facts.append(fact)
    return facts


class TestTransfersFromSenderDirect:
    """Test TransfersFromSender generation for direct transfers."""

    def test_direct_transfer_from_sender(self):
        """Function that transfers to sender gets TransfersFromSender."""
        source = """
            module test::pool {
                use sui::transfer;
                use sui::tx_context::{Self, TxContext};
                use sui::coin::Coin;
                use sui::sui::SUI;

                public fun refund_to_sender(coin: Coin<SUI>, ctx: &TxContext) {
                    let recipient = tx_context::sender(ctx);
                    transfer::public_transfer(coin, recipient);
                }
            }
        """
        ctx = _build_context_with_propagation(source)
        facts = _get_facts(ctx, "TransfersFromSender")
        func_names = [f.args[0] for f in facts]
        assert "test::pool::refund_to_sender" in func_names


class TestHasSenderEqualityCheckDirect:
    """Test HasSenderEqualityCheck generation for direct checks."""

    def test_direct_sender_check(self):
        """Function with sender equality check gets HasSenderEqualityCheck."""
        source = """
            module test::pool {
                use sui::tx_context::{Self, TxContext};

                public struct Pool has key {
                    id: UID,
                    owner: address,
                }

                public fun verify_owner(pool: &Pool, ctx: &TxContext) {
                    let sender = tx_context::sender(ctx);
                    assert!(pool.owner == sender, 0);
                }
            }
        """
        ctx = _build_context_with_propagation(source)
        facts = _get_facts(ctx, "HasSenderEqualityCheck")
        func_names = [f.args[0] for f in facts]
        assert "test::pool::verify_owner" in func_names


