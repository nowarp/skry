/// Test cases for missing-transfer rule.
/// Value extraction without transfer to recipient
module test::missing_transfer {
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

    /// VULNERABLE: Extracts coin but doesn't transfer
    // @expect: missing-transfer
    public entry fun withdraw_missing(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        // Missing transfer - put back (user gets nothing)
        coin::put(&mut pool.balance, coins);
    }

    /// VULNERABLE: Extracts via split but doesn't transfer
    // @expect: missing-transfer
    public entry fun withdraw_split_missing(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let mut total = coin::take(&mut pool.balance, amount, ctx);
        let coins = coin::split(&mut total, amount / 2, ctx);
        coin::put(&mut pool.balance, total);
        // Missing transfer - put back
        coin::put(&mut pool.balance, coins);
    }

    /// VULNERABLE: IPA - entry calls helper that extracts without transfer
    // @expect: missing-transfer
    public entry fun withdraw_via_helper(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        do_extraction(pool, amount, ctx);
    }

    fun do_extraction(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        // No transfer - put back
        coin::put(&mut pool.balance, coins);
    }

    /// SAFE: Extracts and transfers
    public entry fun withdraw_proper(
        pool: &mut Pool,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }

    /// SAFE: Returns Coin type (caller handles transfer)
    public fun withdraw_returns(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ): Coin<SUI> {
        coin::take(&mut pool.balance, amount, ctx)
    }

    /// SAFE: Puts coin back into balance
    public entry fun withdraw_and_redeposit(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        coin::put(&mut pool.balance, coins);
    }
}
