/// Test: Validation via helper function should propagate through IPA.
/// Pattern: Helper calls type_name::get<T>(), caller inherits validation.
module test::validation_helper_ipa {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use std::type_name;

    /// Multi-token pool - T is NOT constrained by phantom (can hold any type)
    public struct MultiPool has key {
        id: UID,
    }

    /// Pure validator helper: calls type_name::get<T>() and returns String.
    /// This is NOT an extraction sink, but it validates T.
    public fun type_to_string<T>(): std::string::String {
        type_name::into_string(type_name::get<T>())
    }

    /// SAFE: Calls validator helper before extraction.
    /// Should NOT be flagged - inherits validation from type_to_string<T>().
    public fun withdraw_with_helper<T>(
        pool: &mut MultiPool,
        balance: &mut Balance<T>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let _type_str = type_to_string<T>();  // Validates T via helper
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// VULNERABLE: No validation before extraction.
    /// Should be flagged.
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
