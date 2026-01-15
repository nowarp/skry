/// Edge cases for missing-transfer rule
/// Tests extraction sinks beyond coin::take
module test::missing_transfer_edge {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};

    public struct Pool has key, store {
        id: UID,
        balance: Balance<SUI>,
    }

    public struct NestedPool has key {
        id: UID,
        inner: Pool,
    }

    // =========================================================================
    // VULNERABLE: Different extraction sinks (not just coin::take)
    // =========================================================================

    /// VULNERABLE: balance::split extraction without transfer
    // @expect: missing-transfer
    public entry fun withdraw_balance_split(
        pool: &mut Pool,
        amount: u64,
        _ctx: &mut TxContext
    ) {
        let extracted = balance::split(&mut pool.balance, amount);
        // Missing: need to convert to coin and transfer, or put back
        balance::destroy_zero(extracted); // This will abort if amount > 0!
    }

    /// VULNERABLE: balance::withdraw_all extracts entire balance
    // @expect: missing-transfer
    public entry fun withdraw_all_no_transfer(
        pool: &mut Pool,
        ctx: &mut TxContext
    ) {
        let full_balance = balance::withdraw_all(&mut pool.balance);
        let coins = coin::from_balance(full_balance, ctx);
        // Missing transfer - put back
        coin::put(&mut pool.balance, coins);
    }

    /// VULNERABLE: coin::from_balance without transfer
    // @expect: missing-transfer
    public entry fun from_balance_no_transfer(
        pool: &mut Pool,
        ctx: &mut TxContext
    ) {
        let coins = coin::from_balance(
            balance::withdraw_all(&mut pool.balance),
            ctx
        );
        // Missing transfer - put back
        coin::put(&mut pool.balance, coins);
    }

    // =========================================================================
    // FALSE NEGATIVE: Multiple extractions, partial transfer
    // Rule limitation: requires per-variable data-flow tracking
    // =========================================================================

    /// FALSE NEGATIVE: Two extractions, only one transferred
    /// coins2 is leaked but rule sees "has transfer" and doesn't flag
    // @false-negative: missing-transfer (requires per-variable tracking)
    public entry fun partial_transfer(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins1 = coin::take(&mut pool.balance, amount, ctx);
        let coins2 = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins1, tx_context::sender(ctx));
        // coins2 put back
        coin::put(&mut pool.balance, coins2);
    }

    // =========================================================================
    // FALSE NEGATIVE: Conditional transfer (one branch missing)
    // Rule limitation: requires branch-sensitive analysis
    // =========================================================================

    /// FALSE NEGATIVE: Transfer only in true branch
    /// false branch leaks but rule sees "has transfer" and doesn't flag
    // @false-negative: missing-transfer (requires branch-sensitive analysis)
    public entry fun conditional_transfer_one_branch(
        pool: &mut Pool,
        amount: u64,
        do_transfer: bool,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        if (do_transfer) {
            transfer::public_transfer(coins, tx_context::sender(ctx));
        } else {
            // put back on this path
            coin::put(&mut pool.balance, coins);
        };
    }

    // =========================================================================
    // VULNERABLE: Nested struct field extraction
    // =========================================================================

    /// VULNERABLE: Extract from nested struct field
    // @expect: missing-transfer
    public entry fun nested_extraction(
        nested: &mut NestedPool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut nested.inner.balance, amount, ctx);
        // Missing transfer - put back
        coin::put(&mut nested.inner.balance, coins);
    }

    // =========================================================================
    // SAFE: Proper handling patterns
    // =========================================================================

    /// SAFE: balance::split with proper conversion and transfer
    public entry fun balance_split_safe(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let extracted = balance::split(&mut pool.balance, amount);
        let coins = coin::from_balance(extracted, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// SAFE: Multiple extractions, all transferred
    public entry fun all_transferred(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let mut coins1 = coin::take(&mut pool.balance, amount, ctx);
        let coins2 = coin::take(&mut pool.balance, amount, ctx);
        coin::join(&mut coins1, coins2);
        transfer::public_transfer(coins1, tx_context::sender(ctx));
    }

    /// SAFE: Conditional but both branches transfer
    public entry fun conditional_both_transfer(
        pool: &mut Pool,
        amount: u64,
        to_sender: bool,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        if (to_sender) {
            transfer::public_transfer(coins, tx_context::sender(ctx));
        } else {
            transfer::public_transfer(coins, recipient);
        }
    }
}
