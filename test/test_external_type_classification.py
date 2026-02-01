"""E2E tests for external type classification.

External types (from dependencies, no source code) need special handling because
we can't inspect their structure - only their usage patterns.

These tests run the FULL analysis pipeline including SemanticFactsBuilder to verify
that external types are correctly classified.
"""
import os
import tempfile

from core.context import ProjectContext
from core.facts import Fact
from analysis import run_structural_analysis, run_fact_propagation
from semantic_facts_builder import SemanticFactsBuilder


class TestExternalTypeClassification:
    """E2E tests for external type classification via LLM.

    External types (from dependencies, no source code) are classified by LLM
    based on their semantic meaning and usage context.

    Regression context: Previously, a fast-path heuristic in _is_obvious_external_role()
    incorrectly classified types as capabilities based on:
    1. Co-location with privileged types (removed in earlier fix)
    2. Restricted getter visibility (removed: I32 conversion utilities have
       public(friend) visibility but are NOT capabilities)

    Now all external types are classified by LLM, which correctly identifies
    numeric utilities (I32, U256, etc.) as non-capabilities.
    """

    def _create_temp_move_file(self, content: str) -> str:
        """Create a temporary Move file with given content."""
        fd, path = tempfile.mkstemp(suffix=".move")
        os.write(fd, content.encode())
        os.close(fd)
        return path

    def _run_full_analysis(self, path: str) -> ProjectContext:
        """Run the complete analysis pipeline including semantic facts."""
        ctx = ProjectContext([path])
        run_structural_analysis(ctx)
        SemanticFactsBuilder().build(ctx, [])
        run_fact_propagation(ctx)
        return ctx

    def _get_all_facts(self, ctx: ProjectContext) -> list:
        """Get all facts from all files and semantic facts."""
        all_facts = list(ctx.semantic_facts)
        for file_ctx in ctx.source_files.values():
            all_facts.extend(file_ctx.facts)
        return all_facts

    def test_external_numeric_type_not_capability_when_collocated_with_cap(self):
        """External numeric type co-located with capability should NOT be classified as capability.

        This simulates a DeFi Pool struct that has:
        - admin_cap: AdminCap (privileged capability)
        - tick_index: i32::I32 (external numeric utility type for tick calculations)

        The i32::I32 type should NOT get IsCapability fact just because it's
        stored in the same struct as AdminCap.
        """
        path = self._create_temp_move_file("""
            module defi::pool {
                use sui::object::UID;
                use sui::transfer;
                use sui::tx_context::TxContext;

                /// Admin capability for privileged operations
                public struct AdminCap has key {
                    id: UID,
                }

                /// DeFi pool with tick positions using external i32 library
                public struct Pool has key {
                    id: UID,
                    /// Admin capability stored in pool for access control
                    admin_cap: AdminCap,
                    /// Current tick index (signed integer from external library)
                    tick_index: i32::I32,
                    /// Tick spacing for price calculations
                    tick_spacing: i32::I32,
                }

                fun init(ctx: &mut TxContext) {
                    let cap = AdminCap { id: object::new(ctx) };
                    transfer::transfer(cap, tx_context::sender(ctx));
                }

                /// Update tick index (requires admin)
                public fun update_tick(_cap: &AdminCap, pool: &mut Pool, new_tick: i32::I32) {
                    pool.tick_index = new_tick;
                }
            }
        """)
        try:
            ctx = self._run_full_analysis(path)
            all_facts = self._get_all_facts(ctx)

            # AdminCap SHOULD be classified as capability (created in init, transferred to sender)
            admin_cap_capability = [f for f in all_facts
                                    if f.name == "IsCapability" and "AdminCap" in f.args[0]]
            assert len(admin_cap_capability) >= 1, (
                f"AdminCap should be classified as IsCapability, facts: "
                f"{[f for f in all_facts if f.name == 'IsCapability']}"
            )

            # i32::I32 should NOT be classified as capability
            i32_capability = [f for f in all_facts
                              if f.name == "IsCapability" and "I32" in f.args[0]]
            assert len(i32_capability) == 0, (
                f"BUG: i32::I32 incorrectly classified as capability due to co-location "
                f"with AdminCap. The fast-path heuristic is too aggressive. "
                f"Found: {i32_capability}"
            )

            # i32::I32 should NOT be classified as privileged
            i32_privileged = [f for f in all_facts
                              if f.name == "IsPrivileged" and "I32" in f.args[0]]
            assert len(i32_privileged) == 0, (
                f"BUG: i32::I32 incorrectly classified as privileged. Found: {i32_privileged}"
            )

        finally:
            os.unlink(path)

    def test_restricted_getter_does_not_imply_capability(self):
        """External type with restricted getter should NOT automatically be capability.

        Regression test: The fast-path heuristic incorrectly assumed that any type
        returned by a public(package) or public(friend) getter must be a capability.
        This is wrong - restricted visibility is often used for code organization,
        not access control (e.g., i32 conversion utilities between libraries).

        External types should ONLY be classified as capabilities by LLM analysis,
        which can understand semantic context.
        """
        path = self._create_temp_move_file("""
            module defi::lib {
                use sui::object::UID;
                use sui::tx_context::TxContext;

                public struct Pool has key {
                    id: UID,
                    /// Numeric type from external library
                    tick: i32_utils::I32,
                }

                fun init(ctx: &mut TxContext) {
                    // Pool created
                }

                /// Restricted getter for internal code organization, NOT access control
                public(friend) fun get_tick(pool: &Pool): &i32_utils::I32 {
                    &pool.tick
                }
            }
        """)
        try:
            ctx = self._run_full_analysis(path)
            all_facts = self._get_all_facts(ctx)

            # i32_utils::I32 should NOT be classified as capability just because
            # it has a restricted getter. The LLM correctly identifies it as
            # a numeric utility type.
            i32_capability = [f for f in all_facts
                              if f.name == "IsCapability" and "I32" in f.args[0]]
            assert len(i32_capability) == 0, (
                f"BUG: I32 incorrectly classified as capability due to restricted getter. "
                f"Found: {i32_capability}"
            )

        finally:
            os.unlink(path)

    def test_multiple_external_types_classified_independently(self):
        """Multiple external types in same struct should be classified independently.

        A struct can have multiple external types - some are utilities (I32),
        some are capabilities. Each should be classified by LLM based on its own
        semantic meaning, not based on neighbors or visibility heuristics.
        """
        path = self._create_temp_move_file("""
            module defi::amm {
                use sui::object::UID;
                use sui::transfer;
                use sui::tx_context::TxContext;

                public struct AdminCap has key {
                    id: UID,
                }

                /// AMM pool with multiple external types
                public struct AMMPool has key {
                    id: UID,
                    /// Privileged cap stored in pool
                    admin: AdminCap,
                    /// Numeric types from math library - NOT privileged
                    sqrt_price_x96: math::U256,
                    current_tick: i32::I32,
                    fee_growth: math::U128,
                }

                fun init(ctx: &mut TxContext) {
                    let cap = AdminCap { id: object::new(ctx) };
                    transfer::transfer(cap, tx_context::sender(ctx));
                }

                /// Update tick - public getter, NOT a capability signal
                public fun get_tick(pool: &AMMPool): &i32::I32 {
                    &pool.current_tick
                }
            }
        """)
        try:
            ctx = self._run_full_analysis(path)
            all_facts = self._get_all_facts(ctx)
            is_cap_facts = [f for f in all_facts if f.name == "IsCapability"]

            # AdminCap should be capability (local type with key ability, transferred to sender)
            assert any("AdminCap" in f.args[0] for f in is_cap_facts), (
                f"AdminCap should be IsCapability. Facts: {is_cap_facts}"
            )

            # Numeric utility types should NOT be capabilities
            # LLM correctly identifies these as numeric/math utilities
            for numeric_type in ["I32", "U256", "U128"]:
                numeric_caps = [f for f in is_cap_facts if numeric_type in f.args[0]]
                assert len(numeric_caps) == 0, (
                    f"BUG: {numeric_type} incorrectly classified as capability. "
                    f"Numeric types should not be classified as capabilities. "
                    f"Found: {numeric_caps}"
                )

        finally:
            os.unlink(path)
