/// FQN conflict test: module_a with validated Pool
module test::fqn_col_a {
    use sui::coin::{Self, Coin};
    use sui::balance::Balance;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use std::type_name;

    /// Pool struct - no phantom type
    public struct Pool has key {
        id: UID,
    }

    /// SAFE: Validates type with type_name::get in assertion
    public fun withdraw<T>(pool: &mut Pool, balance: &mut Balance<T>, expected_type: std::string::String, amount: u64, ctx: &mut TxContext) {
        assert!(type_name::into_string(type_name::get<T>()) == expected_type, 0);
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }
}
