/// Generic type extraction tests
/// Tests extraction with generic type parameters
module test::missing_transfer_generic {
    use sui::coin::{Self, Coin};
    use sui::balance::Balance;
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    /// Generic pool that can hold any coin type
    public struct GenericPool<phantom T> has key {
        id: UID,
        balance: Balance<T>,
    }

    // =========================================================================
    // VULNERABLE: Generic extraction without transfer
    // =========================================================================

    /// VULNERABLE: Extracts generic coin type, no transfer
    // @expect: missing-transfer
    public entry fun withdraw_generic<T>(
        pool: &mut GenericPool<T>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        // No transfer - put back
        coin::put(&mut pool.balance, coins);
    }

    // =========================================================================
    // VULNERABLE: Generic pool, concrete extraction
    // =========================================================================

    /// VULNERABLE: Generic pool but concrete SUI extraction
    // @expect: missing-transfer
    public entry fun withdraw_sui_from_generic(
        pool: &mut GenericPool<sui::sui::SUI>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        // No transfer - put back
        coin::put(&mut pool.balance, coins);
    }

    // =========================================================================
    // SAFE: Generic extraction with transfer
    // =========================================================================

    public entry fun withdraw_generic_safe<T>(
        pool: &mut GenericPool<T>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        sui::transfer::public_transfer(coins, sui::tx_context::sender(ctx));
    }

    // =========================================================================
    // SAFE: Returns generic coin (caller's responsibility)
    // =========================================================================

    public fun withdraw_generic_returns<T>(
        pool: &mut GenericPool<T>,
        amount: u64,
        ctx: &mut TxContext
    ): Coin<T> {
        coin::take(&mut pool.balance, amount, ctx)
    }

    // =========================================================================
    // VULNERABLE: Multiple generic params, extraction from one
    // =========================================================================

    public struct DualPool<phantom A, phantom B> has key {
        id: UID,
        balance_a: Balance<A>,
        balance_b: Balance<B>,
    }

    /// VULNERABLE: Extracts from first type param
    // @expect: missing-transfer
    public entry fun withdraw_first<A, B>(
        pool: &mut DualPool<A, B>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance_a, amount, ctx);
        // No transfer - put back
        coin::put(&mut pool.balance_a, coins);
    }

    /// VULNERABLE: Extracts from second type param
    // @expect: missing-transfer
    public entry fun withdraw_second<A, B>(
        pool: &mut DualPool<A, B>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance_b, amount, ctx);
        // No transfer - put back
        coin::put(&mut pool.balance_b, coins);
    }

    // =========================================================================
    // SAFE: Extracts both, transfers both
    // =========================================================================

    public entry fun withdraw_both_safe<A, B>(
        pool: &mut DualPool<A, B>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins_a = coin::take(&mut pool.balance_a, amount, ctx);
        let coins_b = coin::take(&mut pool.balance_b, amount, ctx);
        let sender = sui::tx_context::sender(ctx);
        sui::transfer::public_transfer(coins_a, sender);
        sui::transfer::public_transfer(coins_b, sender);
    }
}
