/// Cross-module test: helper module with generic extraction functions
module test::cross_module_b {
    use sui::coin::{Self, Coin};
    use sui::balance::Balance;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use std::type_name;

    /// Multi-token pool - no phantom type, so T is unconstrained
    public struct Pool has key {
        id: UID,
    }

    /// VULNERABLE: No type_name::get validation, T is unconstrained
    // @expect: generic-type-mismatch
    public fun extract_coin<T>(pool: &mut Pool, balance: &mut Balance<T>, amount: u64, ctx: &mut TxContext) {
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// SAFE: Has type_name::get validation with assertion
    public fun extract_coin_validated<T>(pool: &mut Pool, balance: &mut Balance<T>, expected_type: std::string::String, amount: u64, ctx: &mut TxContext) {
        assert!(type_name::into_string(type_name::get<T>()) == expected_type, 1);
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }
}
