/// Test cases for duplicated-branch-body rule.
/// Identical code in multiple branches - consider refactoring
module test::duplicated_branch_body {
    use sui::coin::{Self, Coin};
    use sui::balance::Balance;
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};

    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    /// CODE SMELL: Identical bodies
    // @expect: duplicated-branch-body
    public entry fun process(is_vip: bool, pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        if (is_vip) {
            let coins = coin::take(&mut pool.balance, amount, ctx);
            transfer::public_transfer(coins, tx_context::sender(ctx));
        } else {
            let coins = coin::take(&mut pool.balance, amount, ctx);  // Same!
            transfer::public_transfer(coins, tx_context::sender(ctx));
        }
    }

    /// CODE SMELL: All branches do the same thing
    // @expect: duplicated-branch-body
    public entry fun handle_tier(tier: u64, pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        if (tier == 1) {
            let coins = coin::take(&mut pool.balance, amount, ctx);
            transfer::public_transfer(coins, tx_context::sender(ctx));
        } else if (tier == 2) {
            let coins = coin::take(&mut pool.balance, amount, ctx);  // Duplicate
            transfer::public_transfer(coins, tx_context::sender(ctx));
        } else {
            let coins = coin::take(&mut pool.balance, amount, ctx);  // Duplicate
            transfer::public_transfer(coins, tx_context::sender(ctx));
        }
    }

    /// SAFE: Different branch bodies
    public entry fun process_safe(is_vip: bool, pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        if (is_vip) {
            let coins = coin::take(&mut pool.balance, amount * 2, ctx);  // Different
            transfer::public_transfer(coins, tx_context::sender(ctx));
        } else {
            let coins = coin::take(&mut pool.balance, amount, ctx);
            transfer::public_transfer(coins, tx_context::sender(ctx));
        }
    }
}
