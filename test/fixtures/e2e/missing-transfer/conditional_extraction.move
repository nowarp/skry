/// Conditional extraction tests
/// Tests extraction happening inside conditional branches
module test::missing_transfer_conditional {
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
    // VULNERABLE: Extraction in if-branch, no transfer anywhere
    // =========================================================================

    /// VULNERABLE: Conditionally extracts, never transfers
    // @expect: missing-transfer
    public entry fun conditional_extract_no_transfer(
        pool: &mut Pool,
        amount: u64,
        should_extract: bool,
        ctx: &mut TxContext
    ) {
        if (should_extract) {
            let coins = coin::take(&mut pool.balance, amount, ctx);
            // No transfer - put back (user gets nothing)
            coin::put(&mut pool.balance, coins);
        };
    }

    // =========================================================================
    // VULNERABLE: Extraction in else-branch, no transfer
    // =========================================================================

    /// VULNERABLE: Extracts in else branch, never transfers
    // @expect: missing-transfer
    public entry fun extract_in_else_no_transfer(
        pool: &mut Pool,
        amount: u64,
        skip: bool,
        ctx: &mut TxContext
    ) {
        if (skip) {
            // Do nothing
        } else {
            let coins = coin::take(&mut pool.balance, amount, ctx);
            // No transfer - put back
            coin::put(&mut pool.balance, coins);
        };
    }

    // =========================================================================
    // VULNERABLE: Both branches extract, neither transfers
    // =========================================================================

    /// VULNERABLE: Both branches extract, neither transfers
    // @expect: missing-transfer
    public entry fun both_branches_extract_no_transfer(
        pool: &mut Pool,
        amount: u64,
        which: bool,
        ctx: &mut TxContext
    ) {
        if (which) {
            let coins = coin::take(&mut pool.balance, amount, ctx);
            // No transfer - put back
            coin::put(&mut pool.balance, coins);
        } else {
            let coins = coin::take(&mut pool.balance, amount, ctx);
            // No transfer either - put back
            coin::put(&mut pool.balance, coins);
        };
    }

    // =========================================================================
    // SAFE: Conditional extraction with transfer in same branch
    // =========================================================================

    public entry fun conditional_extract_with_transfer(
        pool: &mut Pool,
        amount: u64,
        should_extract: bool,
        ctx: &mut TxContext
    ) {
        if (should_extract) {
            let coins = coin::take(&mut pool.balance, amount, ctx);
            sui::transfer::public_transfer(coins, sui::tx_context::sender(ctx));
        };
    }

    // =========================================================================
    // SAFE: Both branches extract, both transfer
    // =========================================================================

    public entry fun both_branches_extract_and_transfer(
        pool: &mut Pool,
        amount: u64,
        which: bool,
        ctx: &mut TxContext
    ) {
        if (which) {
            let coins = coin::take(&mut pool.balance, amount, ctx);
            sui::transfer::public_transfer(coins, sui::tx_context::sender(ctx));
        } else {
            let coins = coin::take(&mut pool.balance, amount, ctx);
            sui::transfer::public_transfer(coins, sui::tx_context::sender(ctx));
        };
    }

    // =========================================================================
    // FALSE NEGATIVE: One branch extracts+transfers, other extracts only
    // This is branch-sensitive - rule can't track per-path
    // =========================================================================

    /// FALSE NEGATIVE: if-branch safe, else-branch leaks
    // @false-negative: missing-transfer (requires branch-sensitive analysis)
    public entry fun if_transfers_else_leaks(
        pool: &mut Pool,
        amount: u64,
        safe_path: bool,
        ctx: &mut TxContext
    ) {
        if (safe_path) {
            let coins = coin::take(&mut pool.balance, amount, ctx);
            sui::transfer::public_transfer(coins, sui::tx_context::sender(ctx));
        } else {
            let coins = coin::take(&mut pool.balance, amount, ctx);
            // No transfer - put back on this path
            coin::put(&mut pool.balance, coins);
        };
    }
}
