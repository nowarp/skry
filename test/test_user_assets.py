"""Tests for user asset container detection."""

import os
import tempfile

from core.context import ProjectContext
from analysis import run_structural_analysis, run_fact_propagation
from semantic_facts_builder import SemanticFactsBuilder


class TestUserAssetDetection:
    """Tests for UserDepositsInto, UserWithdrawsFrom, IsUserAssetContainer facts."""

    def _create_temp_move_file(self, content: str) -> str:
        """Create a temporary Move file with given content."""
        fd, path = tempfile.mkstemp(suffix=".move")
        os.write(fd, content.encode())
        os.close(fd)
        return path

    def _run_analysis(self, path: str) -> ProjectContext:
        """Run structural and propagation analysis."""
        ctx = ProjectContext([path])
        run_structural_analysis(ctx)
        SemanticFactsBuilder().build(ctx, [])
        run_fact_propagation(ctx)
        return ctx

    def test_deposit_pattern_detected(self):
        """Public function with Coin param + &mut SharedStruct = UserDepositsInto."""
        path = self._create_temp_move_file("""
            module test::pool {
                use sui::coin::Coin;
                use sui::transfer;

                public struct Pool has key {
                    id: UID,
                    balance: u64,
                }

                fun init(ctx: &mut TxContext) {
                    let pool = Pool { id: object::new(ctx), balance: 0 };
                    transfer::share_object(pool);
                }

                public fun deposit(pool: &mut Pool, coin: Coin<SUI>, ctx: &TxContext) {
                    pool.balance = pool.balance + coin::value(&coin);
                    coin::destroy_zero(coin);
                }
            }
        """)
        try:
            ctx = self._run_analysis(path)
            file_ctx = ctx.source_files[path]

            # Check IsSharedObject
            shared_facts = [f for f in file_ctx.facts if f.name == "IsSharedObject"]
            assert len(shared_facts) >= 1, "Pool should be detected as shared object"

            # Check UserDepositsInto
            deposit_facts = [f for f in file_ctx.facts if f.name == "UserDepositsInto"]
            assert any("deposit" in f.args[0] for f in deposit_facts), \
                f"deposit function should be detected as UserDepositsInto, got: {deposit_facts}"

        finally:
            os.unlink(path)

    def test_withdraw_pattern_detected(self):
        """Public function with transfer to sender + &mut SharedStruct = UserWithdrawsFrom."""
        path = self._create_temp_move_file("""
            module test::pool {
                use sui::coin::{Coin, Self};
                use sui::transfer;
                use sui::tx_context;

                public struct Pool has key {
                    id: UID,
                    balance: Balance<SUI>,
                }

                fun init(ctx: &mut TxContext) {
                    let pool = Pool { id: object::new(ctx), balance: balance::zero() };
                    transfer::share_object(pool);
                }

                public fun withdraw(pool: &mut Pool, amount: u64, ctx: &TxContext) {
                    let coin = coin::take(&mut pool.balance, amount, ctx);
                    transfer::public_transfer(coin, tx_context::sender(ctx));
                }
            }
        """)
        try:
            ctx = self._run_analysis(path)
            file_ctx = ctx.source_files[path]

            # Check for withdraw pattern (requires TrackedDerived for sender)
            withdraw_facts = [f for f in file_ctx.facts if f.name == "UserWithdrawsFrom"]
            assert any("withdraw" in f.args[0] for f in withdraw_facts), \
                f"withdraw function should be detected as UserWithdrawsFrom, got: {withdraw_facts}"

        finally:
            os.unlink(path)

    def test_user_asset_container_requires_both_patterns(self):
        """IsUserAssetContainer requires both deposit AND withdraw patterns."""
        # Only deposit, no withdraw
        path = self._create_temp_move_file("""
            module test::pool {
                use sui::coin::Coin;
                use sui::transfer;

                public struct Pool has key {
                    id: UID,
                    balance: u64,
                }

                fun init(ctx: &mut TxContext) {
                    let pool = Pool { id: object::new(ctx), balance: 0 };
                    transfer::share_object(pool);
                }

                public fun deposit(pool: &mut Pool, coin: Coin<SUI>) {
                    pool.balance = pool.balance + coin::value(&coin);
                }
            }
        """)
        try:
            ctx = self._run_analysis(path)
            file_ctx = ctx.source_files[path]

            # Should have UserDepositsInto but NOT IsUserAssetContainer (no withdraw)
            deposit_facts = [f for f in file_ctx.facts if f.name == "UserDepositsInto"]
            assert len(deposit_facts) >= 1, "Should detect deposit pattern"

            container_facts = [f for f in file_ctx.facts if f.name == "IsUserAssetContainer"]
            assert len(container_facts) == 0, \
                f"Should NOT be IsUserAssetContainer without withdraw, got: {container_facts}"

        finally:
            os.unlink(path)

    def test_admin_gated_functions_excluded(self):
        """Functions with admin role check should NOT be deposit/withdraw patterns."""
        from unittest.mock import patch

        path = self._create_temp_move_file("""
            module test::pool {
                use sui::coin::Coin;
                use sui::transfer;

                public struct AdminCap has key { id: UID }
                public struct Pool has key { id: UID, balance: u64 }

                fun init(ctx: &mut TxContext) {
                    let admin = AdminCap { id: object::new(ctx) };
                    transfer::transfer(admin, tx_context::sender(ctx));
                    let pool = Pool { id: object::new(ctx), balance: 0 };
                    transfer::share_object(pool);
                }

                public fun admin_deposit(_: &AdminCap, pool: &mut Pool, coin: Coin<SUI>) {
                    pool.balance = pool.balance + coin::value(&coin);
                }
            }
        """)
        try:
            # Mock LLM with new unified classification format (patch where imported)
            with patch("semantic_facts_builder.call_llm_json") as mock_llm:
                def classify_response(prompt, schema, **kwargs):
                    # AdminCap is privileged, Pool is not
                    if "AdminCap" in prompt:
                        return {"is_role": True, "is_privileged": True, "is_user_asset": False, "is_config": False}
                    return {"is_role": False, "is_privileged": False, "is_user_asset": False, "is_config": False}
                mock_llm.side_effect = classify_response

                ctx = self._run_analysis(path)
                file_ctx = ctx.source_files[path]

                # admin_deposit should NOT be UserDepositsInto (admin-gated)
                deposit_facts = [f for f in file_ctx.facts if f.name == "UserDepositsInto"]
                assert not any("admin_deposit" in f.args[0] for f in deposit_facts), \
                    "admin_deposit should NOT be UserDepositsInto (admin-gated)"

        finally:
            os.unlink(path)


    def test_interprocedural_deposit_detected(self):
        """Public function calling private helper with deposit pattern = UserDepositsInto."""
        path = self._create_temp_move_file("""
            module test::pool {
                use sui::coin::Coin;
                use sui::transfer;

                public struct Pool has key {
                    id: UID,
                    balance: u64,
                }

                fun init(ctx: &mut TxContext) {
                    let pool = Pool { id: object::new(ctx), balance: 0 };
                    transfer::share_object(pool);
                }

                // Private helper does the actual deposit
                fun do_deposit(pool: &mut Pool, coin: Coin<SUI>) {
                    pool.balance = pool.balance + coin::value(&coin);
                }

                // Public entry calls the helper
                public fun deposit(pool: &mut Pool, coin: Coin<SUI>) {
                    do_deposit(pool, coin);
                }

                public fun withdraw(pool: &mut Pool, ctx: &TxContext) {
                    let coin = coin::take(&mut pool.balance, 10, ctx);
                    transfer::public_transfer(coin, tx_context::sender(ctx));
                }
            }
        """)
        try:
            ctx = self._run_analysis(path)
            file_ctx = ctx.source_files[path]

            # Public deposit should be detected via IPA (calls do_deposit which has pattern)
            deposit_facts = [f for f in file_ctx.facts if f.name == "UserDepositsInto"]
            assert any("deposit" in f.args[0] and "do_deposit" not in f.args[0] for f in deposit_facts), \
                f"Public deposit should be detected via IPA, got: {deposit_facts}"

            # Should be IsUserAssetContainer (has both patterns)
            container_facts = [f for f in file_ctx.facts if f.name == "IsUserAssetContainer"]
            assert len(container_facts) >= 1, \
                f"Pool should be IsUserAssetContainer, got: {container_facts}"

        finally:
            os.unlink(path)


    def test_same_named_structs_no_collision(self):
        """Two modules with same-named Pool struct should not cause false positives."""
        # Create two files with same-named structs
        fd1, path1 = tempfile.mkstemp(suffix=".move")
        os.write(fd1, b"""
            module alpha::pool {
                use sui::coin::Coin;
                use sui::transfer;
                use sui::tx_context;

                public struct Pool has key { id: UID, balance: u64 }

                fun init(ctx: &mut TxContext) {
                    let pool = Pool { id: object::new(ctx), balance: 0 };
                    transfer::share_object(pool);
                }

                public fun deposit(pool: &mut Pool, coin: Coin<SUI>) {
                    pool.balance = pool.balance + coin::value(&coin);
                }

                public fun withdraw(pool: &mut Pool, ctx: &TxContext) {
                    let coin = coin::take(&mut pool.balance, 10, ctx);
                    transfer::public_transfer(coin, tx_context::sender(ctx));
                }
            }
        """)
        os.close(fd1)

        fd2, path2 = tempfile.mkstemp(suffix=".move")
        os.write(fd2, b"""
            module beta::pool {
                use sui::transfer;

                public struct Pool has key { id: UID, data: vector<u8> }

                fun init(ctx: &mut TxContext) {
                    let pool = Pool { id: object::new(ctx), data: vector::empty() };
                    transfer::share_object(pool);
                }

                // No deposit/withdraw - NOT a user asset container
                public fun set_data(pool: &mut Pool, data: vector<u8>) {
                    pool.data = data;
                }
            }
        """)
        os.close(fd2)

        try:
            ctx = ProjectContext([path1, path2])
            run_structural_analysis(ctx)
            SemanticFactsBuilder().build(ctx, [])
            run_fact_propagation(ctx)

            # Collect all IsUserAssetContainer facts
            all_containers = []
            for file_ctx in ctx.source_files.values():
                for f in file_ctx.facts:
                    if f.name == "IsUserAssetContainer":
                        all_containers.append(f.args[0])

            # Only alpha::pool::Pool should be a user asset container
            # beta::pool::Pool has no deposit/withdraw patterns
            assert len(all_containers) == 1, \
                f"Expected 1 container (alpha::pool::Pool), got: {all_containers}"
            assert "alpha" in all_containers[0] or "Pool" in all_containers[0], \
                f"Expected alpha::pool::Pool, got: {all_containers}"

        finally:
            os.unlink(path1)
            os.unlink(path2)

    def test_cross_module_shared_type_no_false_match(self):
        """Function with &mut Pool should not match different module's shared Pool."""
        # alpha::pool has shared Pool (user asset container)
        # beta::other has function with &mut Pool param but Pool is NOT shared in beta
        # Should NOT get false WritesUserAsset for beta::other::do_something
        fd1, path1 = tempfile.mkstemp(suffix=".move")
        os.write(fd1, b"""
            module alpha::pool {
                use sui::coin::Coin;
                use sui::transfer;
                use sui::tx_context;

                public struct Pool has key { id: UID, balance: u64 }

                fun init(ctx: &mut TxContext) {
                    let pool = Pool { id: object::new(ctx), balance: 0 };
                    transfer::share_object(pool);
                }

                public fun deposit(pool: &mut Pool, coin: Coin<SUI>) {
                    pool.balance = pool.balance + coin::value(&coin);
                }

                public fun withdraw(pool: &mut Pool, ctx: &TxContext) {
                    let coin = coin::take(&mut pool.balance, 10, ctx);
                    transfer::public_transfer(coin, tx_context::sender(ctx));
                }
            }
        """)
        os.close(fd1)

        fd2, path2 = tempfile.mkstemp(suffix=".move")
        os.write(fd2, b"""
            module beta::other {
                // Different Pool struct, NOT shared
                public struct Pool has store { value: u64 }

                // This should NOT match alpha::pool::Pool
                public fun do_something(pool: &mut Pool) {
                    pool.value = 42;
                }
            }
        """)
        os.close(fd2)

        try:
            ctx = ProjectContext([path1, path2])
            run_structural_analysis(ctx)
            SemanticFactsBuilder().build(ctx, [])
            run_fact_propagation(ctx)

            # Collect WritesUserAsset facts
            writes_facts = []
            for file_ctx in ctx.source_files.values():
                for f in file_ctx.facts:
                    if f.name == "WritesUserAsset":
                        writes_facts.append(f.args)

            # beta::other::do_something should NOT have WritesUserAsset
            # because beta::other::Pool is NOT the same as alpha::pool::Pool
            beta_writes = [w for w in writes_facts if "beta" in w[0]]
            assert len(beta_writes) == 0, \
                f"beta::other::do_something should NOT have WritesUserAsset, got: {beta_writes}"

            # alpha functions should have WritesUserAsset
            alpha_writes = [w for w in writes_facts if "alpha" in w[0]]
            assert len(alpha_writes) >= 2, \
                f"alpha functions should have WritesUserAsset, got: {alpha_writes}"

        finally:
            os.unlink(path1)
            os.unlink(path2)

    def test_cross_module_import_resolved(self):
        """Function importing Pool from another module should resolve via import_map."""
        # alpha::pool has shared Pool (user asset container)
        # beta::user imports alpha::pool::Pool and uses it
        # Should get WritesUserAsset for beta::user::update_pool
        fd1, path1 = tempfile.mkstemp(suffix=".move")
        os.write(fd1, b"""
            module alpha::pool {
                use sui::coin::Coin;
                use sui::transfer;
                use sui::tx_context;

                public struct Pool has key { id: UID, balance: u64 }

                fun init(ctx: &mut TxContext) {
                    let pool = Pool { id: object::new(ctx), balance: 0 };
                    transfer::share_object(pool);
                }

                public fun deposit(pool: &mut Pool, coin: Coin<SUI>) {
                    pool.balance = pool.balance + coin::value(&coin);
                }

                public fun withdraw(pool: &mut Pool, ctx: &TxContext) {
                    let coin = coin::take(&mut pool.balance, 10, ctx);
                    transfer::public_transfer(coin, tx_context::sender(ctx));
                }
            }
        """)
        os.close(fd1)

        fd2, path2 = tempfile.mkstemp(suffix=".move")
        os.write(fd2, b"""
            module beta::user {
                use alpha::pool::Pool;

                // Uses imported Pool type - should resolve to alpha::pool::Pool
                public fun update_pool(pool: &mut Pool) {
                    // modify pool
                }

                public fun read_pool(pool: &Pool): u64 {
                    0
                }
            }
        """)
        os.close(fd2)

        try:
            ctx = ProjectContext([path1, path2])
            run_structural_analysis(ctx)
            SemanticFactsBuilder().build(ctx, [])
            run_fact_propagation(ctx)

            # Collect WritesUserAsset and ReadsUserAsset facts
            writes_facts = []
            reads_facts = []
            for file_ctx in ctx.source_files.values():
                for f in file_ctx.facts:
                    if f.name == "WritesUserAsset":
                        writes_facts.append(f.args)
                    elif f.name == "ReadsUserAsset":
                        reads_facts.append(f.args)

            # beta::user::update_pool should have WritesUserAsset via import resolution
            beta_writes = [w for w in writes_facts if "beta" in w[0]]
            assert any("update_pool" in w[0] for w in beta_writes), \
                f"beta::user::update_pool should have WritesUserAsset, got: {beta_writes}"

            # beta::user::read_pool should have ReadsUserAsset via import resolution
            beta_reads = [r for r in reads_facts if "beta" in r[0]]
            assert any("read_pool" in r[0] for r in beta_reads), \
                f"beta::user::read_pool should have ReadsUserAsset, got: {beta_reads}"

        finally:
            os.unlink(path1)
            os.unlink(path2)


class TestWritesReadsUserAsset:
    """Tests for WritesUserAsset and ReadsUserAsset facts."""

    def _create_temp_move_file(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".move")
        os.write(fd, content.encode())
        os.close(fd)
        return path

    def _run_analysis(self, path: str) -> ProjectContext:
        ctx = ProjectContext([path])
        run_structural_analysis(ctx)
        SemanticFactsBuilder().build(ctx, [])
        run_fact_propagation(ctx)
        return ctx

    def test_mut_param_creates_writes_fact(self):
        """&mut UserAssetContainer param creates WritesUserAsset fact."""
        path = self._create_temp_move_file("""
            module test::pool {
                use sui::coin::Coin;
                use sui::transfer;
                use sui::tx_context;

                public struct Pool has key { id: UID, balance: u64 }

                fun init(ctx: &mut TxContext) {
                    let pool = Pool { id: object::new(ctx), balance: 0 };
                    transfer::share_object(pool);
                }

                public fun deposit(pool: &mut Pool, coin: Coin<SUI>) {
                    pool.balance = pool.balance + coin::value(&coin);
                }

                public fun withdraw(pool: &mut Pool, ctx: &TxContext) {
                    let coin = coin::take(&mut pool.balance, 10, ctx);
                    transfer::public_transfer(coin, tx_context::sender(ctx));
                }
            }
        """)
        try:
            ctx = self._run_analysis(path)
            file_ctx = ctx.source_files[path]

            # Must detect IsUserAssetContainer (has both deposit + withdraw)
            container_facts = [f for f in file_ctx.facts if f.name == "IsUserAssetContainer"]
            assert len(container_facts) >= 1, \
                f"Pool should be IsUserAssetContainer (has deposit+withdraw), got: {container_facts}"

            # Both deposit and withdraw have &mut Pool, so should have WritesUserAsset
            writes_facts = [f for f in file_ctx.facts if f.name == "WritesUserAsset"]
            assert len(writes_facts) >= 2, \
                f"Expected WritesUserAsset for deposit and withdraw, got: {writes_facts}"

        finally:
            os.unlink(path)

    def test_ref_param_creates_reads_fact(self):
        """& UserAssetContainer param (read-only) creates ReadsUserAsset fact."""
        path = self._create_temp_move_file("""
            module test::pool {
                use sui::coin::Coin;
                use sui::transfer;
                use sui::tx_context;

                public struct Pool has key { id: UID, balance: u64 }

                fun init(ctx: &mut TxContext) {
                    let pool = Pool { id: object::new(ctx), balance: 0 };
                    transfer::share_object(pool);
                }

                public fun deposit(pool: &mut Pool, coin: Coin<SUI>) {
                    pool.balance = pool.balance + coin::value(&coin);
                }

                public fun withdraw(pool: &mut Pool, ctx: &TxContext) {
                    let coin = coin::take(&mut pool.balance, 10, ctx);
                    transfer::public_transfer(coin, tx_context::sender(ctx));
                }

                // Read-only access to pool
                public fun get_balance(pool: &Pool): u64 {
                    pool.balance
                }
            }
        """)
        try:
            ctx = self._run_analysis(path)
            file_ctx = ctx.source_files[path]

            # Must detect IsUserAssetContainer
            container_facts = [f for f in file_ctx.facts if f.name == "IsUserAssetContainer"]
            assert len(container_facts) >= 1, \
                f"Pool should be IsUserAssetContainer, got: {container_facts}"

            # get_balance has &Pool (read-only), should have ReadsUserAsset
            reads_facts = [f for f in file_ctx.facts if f.name == "ReadsUserAsset"]
            assert any("get_balance" in f.args[0] for f in reads_facts), \
                f"get_balance should have ReadsUserAsset, got: {reads_facts}"

        finally:
            os.unlink(path)
