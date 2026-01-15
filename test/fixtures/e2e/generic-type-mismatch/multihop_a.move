/// Multi-hop test: module_a is entry - calls module_b which calls module_c
module test::multihop_a {
    use sui::coin::{Self, Coin};
    use sui::balance::Balance;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::UID;
    use test::multihop_b;

    public struct Pool has key {
        id: UID,
    }

    /// SAFE: Calls multihop_b::validate_via_c which calls module_c::validate
    /// Validation propagates: C -> B -> A (3-hop chain)
    public fun withdraw_multihop_safe<T>(pool: &mut Pool, balance: &mut Balance<T>, expected_type: std::string::String, amount: u64, ctx: &mut TxContext) {
        multihop_b::validate_via_c<T>(expected_type);
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// VULNERABLE: Calls multihop_b::no_validate which does NOT validate
    // @expect: generic-type-mismatch
    public fun withdraw_multihop_unsafe<T>(pool: &mut Pool, balance: &mut Balance<T>, amount: u64, ctx: &mut TxContext) {
        multihop_b::no_validate<T>();
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// VULNERABLE: No validation at all
    // @expect: generic-type-mismatch
    public fun withdraw_no_call<T>(pool: &mut Pool, balance: &mut Balance<T>, amount: u64, ctx: &mut TxContext) {
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }
}
