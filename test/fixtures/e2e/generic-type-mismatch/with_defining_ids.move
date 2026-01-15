/// Test: type_name::with_defining_ids<T>() should count as validation.
module test::with_defining_ids {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use std::type_name;

    public struct MultiPool has key {
        id: UID,
        expected_type: type_name::TypeName,
    }

    /// SAFE: validates with type_name::with_defining_ids before extraction
    public fun withdraw_with_defining_ids<T>(
        pool: &mut MultiPool,
        balance: &mut Balance<T>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        assert!(type_name::with_defining_ids<T>() == pool.expected_type, 1);
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// VULNERABLE: no validation before extraction
    // @expect: generic-type-mismatch
    public fun withdraw_no_validation<T>(
        pool: &mut MultiPool,
        balance: &mut Balance<T>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }
}
