/// Deep call chain test - 5 hops to test IPA depth limits
/// Tests if analyzer correctly tracks extraction through deep call chains
module test::missing_transfer_deep {
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
    // VULNERABLE: 5-hop chain - entry -> h1 -> h2 -> h3 -> h4 -> extract
    // Tests LLM callee limit (only 10 callees shown to LLM)
    // =========================================================================

    /// Entry point - VULNERABLE via deep chain
    // @expect: missing-transfer
    public entry fun deep_withdraw(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        hop_1(pool, amount, ctx);
    }

    fun hop_1(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        hop_2(pool, amount, ctx);
    }

    fun hop_2(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        hop_3(pool, amount, ctx);
    }

    fun hop_3(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        hop_4(pool, amount, ctx);
    }

    fun hop_4(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        final_extract(pool, amount, ctx);
    }

    fun final_extract(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        // Missing transfer - put back
        coin::put(&mut pool.balance, coins);
    }

    // =========================================================================
    // SAFE: 5-hop chain with transfer at the end
    // =========================================================================

    public entry fun deep_withdraw_safe(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        hop_1_safe(pool, amount, ctx);
    }

    fun hop_1_safe(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        hop_2_safe(pool, amount, ctx);
    }

    fun hop_2_safe(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        hop_3_safe(pool, amount, ctx);
    }

    fun hop_3_safe(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        hop_4_safe(pool, amount, ctx);
    }

    fun hop_4_safe(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        final_extract_safe(pool, amount, ctx);
    }

    fun final_extract_safe(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        sui::transfer::public_transfer(coins, sui::tx_context::sender(ctx));
    }
}
