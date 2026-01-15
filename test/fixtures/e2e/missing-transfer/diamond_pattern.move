/// Diamond pattern test - parallel call paths
/// Tests if analyzer correctly handles branching call graphs
module test::missing_transfer_diamond {
    use sui::coin::{Self, Coin};
    use sui::balance::Balance;
    use sui::sui::SUI;
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    // =========================================================================
    // VULNERABLE: Entry calls two helpers, one extracts without transfer
    // Diamond: entry -> helper_a (extracts) + helper_b (no-op)
    // =========================================================================

    /// VULNERABLE: helper_a extracts, helper_b does nothing
    // @expect: missing-transfer
    public entry fun diamond_one_branch_leaks(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        helper_extracts(pool, amount, ctx);
        helper_noop(pool);
    }

    fun helper_extracts(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        // No transfer - put back
        coin::put(&mut pool.balance, coins);
    }

    fun helper_noop(_pool: &mut Pool) {
        // Does nothing
    }

    // =========================================================================
    // VULNERABLE: Both branches extract, neither transfers
    // =========================================================================

    /// VULNERABLE: Both helpers extract, neither transfers
    // @expect: missing-transfer
    public entry fun diamond_both_branches_leak(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        helper_extracts_a(pool, amount, ctx);
        helper_extracts_b(pool, amount, ctx);
    }

    fun helper_extracts_a(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        // No transfer - put back
        coin::put(&mut pool.balance, coins);
    }

    fun helper_extracts_b(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        // No transfer - put back
        coin::put(&mut pool.balance, coins);
    }

    // =========================================================================
    // SAFE: Both branches extract, both transfer
    // =========================================================================

    public entry fun diamond_both_branches_safe(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        helper_extracts_transfers_a(pool, amount, ctx);
        helper_extracts_transfers_b(pool, amount, ctx);
    }

    fun helper_extracts_transfers_a(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        sui::transfer::public_transfer(coins, sui::tx_context::sender(ctx));
    }

    fun helper_extracts_transfers_b(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        sui::transfer::public_transfer(coins, sui::tx_context::sender(ctx));
    }

    // =========================================================================
    // Edge case: One branch extracts+transfers, other extracts only
    // This is a partial coverage case similar to partial_transfer
    // =========================================================================

    /// FALSE NEGATIVE: One branch safe, one leaks
    /// Rule sees "has transfer" from helper_safe and doesn't flag
    // @false-negative: missing-transfer (one branch leaks but other transfers)
    public entry fun diamond_mixed_branches(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        helper_extracts_and_transfers(pool, amount, ctx);
        helper_extracts_no_transfer(pool, amount, ctx);
    }

    fun helper_extracts_and_transfers(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        sui::transfer::public_transfer(coins, sui::tx_context::sender(ctx));
    }

    fun helper_extracts_no_transfer(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        // No transfer - put back
        coin::put(&mut pool.balance, coins);
    }
}
