/// Cross-module test - helper module
module test::missing_transfer_helper {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    /// VULNERABLE: Extracts but doesn't transfer
    // @expect: missing-transfer
    public fun extract_no_transfer(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        // Missing transfer - put back
        coin::put(&mut pool.balance, coins);
    }

    /// SAFE: Returns coin for caller to handle
    public fun extract_and_return(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ): Coin<SUI> {
        coin::take(&mut pool.balance, amount, ctx)
    }
}
