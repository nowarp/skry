/// Return type edge case tests
/// Tests returns-coin-type filter bypass edge cases
module test::missing_transfer_return {
    use sui::coin::{Self, Coin};
    use sui::balance::Balance;
    use sui::sui::SUI;
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};
    use std::option::{Self, Option};

    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    // =========================================================================
    // SAFE (bypass): Returns Coin<T> - caller's responsibility
    // These should NOT be flagged - they correctly bypass the filter
    // =========================================================================

    /// SAFE: Returns owned Coin - caller handles transfer
    public fun returns_coin(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ): Coin<SUI> {
        coin::take(&mut pool.balance, amount, ctx)
    }

    /// SAFE: Returns Balance - caller handles it
    public fun returns_balance(
        pool: &mut Pool,
        amount: u64,
    ): Balance<SUI> {
        sui::balance::split(&mut pool.balance, amount)
    }

    // =========================================================================
    // SAFE (bypass): Returns tuple with Coin
    // =========================================================================

    /// SAFE: Returns tuple (Coin, u64) - coin is returned
    public fun returns_coin_tuple(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ): (Coin<SUI>, u64) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        (coins, amount)
    }

    // =========================================================================
    // Edge case: Returns Option<Coin<T>>
    // Should this bypass the filter? Coin is wrapped in Option
    // =========================================================================

    /// Edge case: Returns Option<Coin> - coin wrapped in option
    /// If filter doesn't recognize this, it may incorrectly flag
    public fun returns_option_coin(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ): Option<Coin<SUI>> {
        if (sui::balance::value(&pool.balance) >= amount) {
            let coins = coin::take(&mut pool.balance, amount, ctx);
            option::some(coins)
        } else {
            option::none()
        }
    }

    // =========================================================================
    // VULNERABLE: Returns immutable reference to coin
    // &Coin<T> is NOT the same as returning Coin<T>
    // Cannot transfer a reference - this is actually a leak pattern
    // =========================================================================

    // Note: This pattern is actually not common in Move because you can't
    // return a reference to a local variable. But if someone stores the
    // extracted coin and returns a reference to it, that's vulnerable.

    // =========================================================================
    // VULNERABLE: Extracts coin, returns unrelated value
    // =========================================================================

    /// VULNERABLE: Extracts but returns u64, not the coin
    // @expect: missing-transfer
    public fun extracts_returns_amount(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ): u64 {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        let value = coin::value(&coins);
        // Put back - user gets nothing
        coin::put(&mut pool.balance, coins);
        value
    }

    /// VULNERABLE: Extracts but returns bool
    // @expect: missing-transfer
    public fun extracts_returns_bool(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ): bool {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        // Put back - user gets nothing
        coin::put(&mut pool.balance, coins);
        true
    }

    // =========================================================================
    // VULNERABLE: Entry function that extracts (can't return)
    // =========================================================================

    /// VULNERABLE: Entry can't return, must transfer
    // @expect: missing-transfer
    public entry fun entry_extracts_no_transfer(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        // Entry can't return - put back
        coin::put(&mut pool.balance, coins);
    }

    // =========================================================================
    // SAFE: Entry with transfer
    // =========================================================================

    public entry fun entry_extracts_with_transfer(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        sui::transfer::public_transfer(coins, sui::tx_context::sender(ctx));
    }
}
