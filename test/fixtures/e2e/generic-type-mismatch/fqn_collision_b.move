/// FQN conflict test: module_b with unvalidated Pool
module test::fqn_col_b {
    use sui::coin::{Self, Coin};
    use sui::balance::Balance;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};

    /// Pool struct - no phantom type
    public struct Pool has key {
        id: UID,
    }

    /// VULNERABLE: No validation
    // @expect: generic-type-mismatch
    public fun withdraw<T>(pool: &mut Pool, balance: &mut Balance<T>, amount: u64, ctx: &mut TxContext) {
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }
}
