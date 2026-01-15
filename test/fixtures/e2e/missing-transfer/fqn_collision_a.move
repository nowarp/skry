/// FQN collision test - module A
module test::fqn_collision_a {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    /// VULNERABLE: Same struct name as module B, extracts without transfer
    // @expect: missing-transfer
    public entry fun withdraw(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        // Missing transfer - put back
        coin::put(&mut pool.balance, coins);
    }
}
