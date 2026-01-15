/// FQN collision test - module B
module test::fqn_collision_b {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};

    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    /// SAFE: Same struct name as module A, different FQN, proper transfer
    public entry fun withdraw(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }
}
