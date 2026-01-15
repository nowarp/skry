/// Loop extraction tests
/// Tests extraction patterns inside loops
module test::missing_transfer_loop {
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
    // VULNERABLE: Extract in loop, no transfer
    // =========================================================================

    /// VULNERABLE: Loop extracts multiple times, never transfers
    // @expect: missing-transfer
    public entry fun loop_extract_no_transfer(
        pool: &mut Pool,
        amount: u64,
        count: u64,
        ctx: &mut TxContext
    ) {
        let mut i = 0;
        while (i < count) {
            let coins = coin::take(&mut pool.balance, amount, ctx);
            // No transfer - put back (user gets nothing)
            coin::put(&mut pool.balance, coins);
            i = i + 1;
        };
    }

    // =========================================================================
    // SAFE: Extract in loop, transfer in same iteration
    // =========================================================================

    public entry fun loop_extract_with_transfer(
        pool: &mut Pool,
        amount: u64,
        count: u64,
        ctx: &mut TxContext
    ) {
        let mut i = 0;
        let sender = sui::tx_context::sender(ctx);
        while (i < count) {
            let coins = coin::take(&mut pool.balance, amount, ctx);
            sui::transfer::public_transfer(coins, sender);
            i = i + 1;
        };
    }

    // =========================================================================
    // FALSE NEGATIVE: Loop extracts, single transfer after loop
    // Only one coin transferred, rest leaked - like partial_transfer
    // =========================================================================

    /// FALSE NEGATIVE: Multiple extractions in loop, one transfer after
    /// Rule sees "has transfer" and doesn't flag
    // @false-negative: missing-transfer (loop extracts multiple, transfers once)
    public entry fun loop_extract_single_transfer_after(
        pool: &mut Pool,
        amount: u64,
        count: u64,
        ctx: &mut TxContext
    ) {
        let mut i = 0;
        let mut last_coins = coin::zero<SUI>(ctx);
        while (i < count) {
            let coins = coin::take(&mut pool.balance, amount, ctx);
            // Overwrite previous - all but last are leaked
            coin::destroy_zero(last_coins);
            last_coins = coins;
            i = i + 1;
        };
        // Only transfers the last one
        sui::transfer::public_transfer(last_coins, sui::tx_context::sender(ctx));
    }

    // =========================================================================
    // SAFE: Accumulate in loop, transfer accumulated
    // =========================================================================

    public entry fun loop_accumulate_then_transfer(
        pool: &mut Pool,
        amount: u64,
        count: u64,
        ctx: &mut TxContext
    ) {
        let mut accumulated = coin::zero<SUI>(ctx);
        let mut i = 0;
        while (i < count) {
            let coins = coin::take(&mut pool.balance, amount, ctx);
            coin::join(&mut accumulated, coins);
            i = i + 1;
        };
        sui::transfer::public_transfer(accumulated, sui::tx_context::sender(ctx));
    }
}
