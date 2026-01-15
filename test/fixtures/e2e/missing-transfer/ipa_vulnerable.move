/// IPA test - vulnerable entry -> helper chain
module test::missing_transfer_ipa_vuln {
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

    /// VULNERABLE: Entry calls helper that extracts without transfer
    // @expect: missing-transfer
    public entry fun withdraw(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        extract_funds(pool, amount, ctx);
    }

    /// Helper extracts but doesn't transfer
    fun extract_funds(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        // Missing transfer - put back
        coin::put(&mut pool.balance, coins);
    }

    /// VULNERABLE: Two-hop chain - entry -> helper1 -> helper2
    // @expect: missing-transfer
    public entry fun withdraw_two_hop(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        call_helper1(pool, amount, ctx);
    }

    fun call_helper1(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        call_helper2(pool, amount, ctx);
    }

    fun call_helper2(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        // Still no transfer - put back
        coin::put(&mut pool.balance, coins);
    }
}
