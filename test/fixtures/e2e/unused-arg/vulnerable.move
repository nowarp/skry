/// Test cases for unused-arg rule.
/// Function argument is never used
module test::unused_arg {
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

    /// UNUSED: amount is never used
    // @expect: unused-arg
    public entry fun process(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        // amount is declared but never referenced!
        let coins = coin::take(&mut pool.balance, 100, ctx);  // Uses 100, not amount
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// UNUSED: recipient is never used
    // @expect: unused-arg
    public entry fun withdraw(pool: &mut Pool, recipient: address, ctx: &mut TxContext) {
        let coins = coin::take(&mut pool.balance, 50, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));  // Uses sender, not recipient
    }

    /// UNUSED: Multiple unused args
// @expect: unused-arg
    public entry fun complex(pool: &mut Pool, amount: u64, recipient: address, fee: u64, ctx: &mut TxContext) {
        // Only uses pool and ctx, ignores amount, recipient, fee
        let coins = coin::take(&mut pool.balance, 100, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// SAFE: Underscore prefix signals intentionally unused
    public entry fun process_safe(pool: &mut Pool, _unused: u64, ctx: &mut TxContext) {
        let coins = coin::take(&mut pool.balance, 100, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// SAFE: All arguments used
    public entry fun withdraw_safe(pool: &mut Pool, amount: u64, recipient: address, ctx: &mut TxContext) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }

    /// SAFE: TxContext should NEVER be flagged (even in non-entry, even if unused)
    public fun helper_unused_ctx(pool: &mut Pool, ctx: &mut TxContext) {
        pool.balance = pool.balance;
    }

    /// SAFE: init functions should NEVER be checked for unused args
    public fun init(ctx: &mut TxContext, fee_wallet: address, decimals: u8) {
        // fee_wallet and decimals unused - but init functions are exempt
    }
}
