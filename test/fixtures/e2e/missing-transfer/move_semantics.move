module test::missing_transfer_move_semantics {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    // =========================================================================
    // SAFE: Extraction result flows through assignment
    // =========================================================================

    public entry fun alias_then_transfer(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        let my_coins = coins;
        sui::transfer::public_transfer(my_coins, sui::tx_context::sender(ctx));
    }

    // =========================================================================
    // SAFE: Extraction result flows through from_balance
    // =========================================================================

    public entry fun split_convert_transfer(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let extracted = balance::split(&mut pool.balance, amount);
        let coins = coin::from_balance(extracted, ctx);
        sui::transfer::public_transfer(coins, sui::tx_context::sender(ctx));
    }

    // =========================================================================
    // VULNERABLE: Alias but no transfer
    // =========================================================================

    /// VULNERABLE: Alias extraction, put back
    // @expect: missing-transfer
    public entry fun alias_no_transfer(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        let my_coins = coins;
        coin::put(&mut pool.balance, my_coins);
    }
}
