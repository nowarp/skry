/// Tests different value extraction patterns beyond coin::take
/// All extraction sinks should be detected
module test::extraction_sinks {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    /// VULNERABLE: balance::split extraction
    // @expect: generic-type-mismatch
    public fun extract_via_split<T>(balance: &mut Balance<T>, amount: u64, ctx: &mut TxContext) {
        let extracted = balance::split(balance, amount);
        let coins = coin::from_balance(extracted, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// VULNERABLE: balance::withdraw_all extraction
    // @expect: generic-type-mismatch
    public fun extract_via_withdraw_all<T>(balance: Balance<T>, ctx: &mut TxContext) {
        let coins = coin::from_balance(balance, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// VULNERABLE: coin::from_balance direct
    // @expect: generic-type-mismatch
    public fun extract_via_from_balance<T>(balance: Balance<T>, ctx: &mut TxContext) {
        let coins = coin::from_balance(balance, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// VULNERABLE: Coin parameter directly transferred without validation
    /// Caller provides coin but T is unconstrained
    // @false-negative: generic-type-mismatch
    public fun transfer_coin_param<T>(coin: Coin<T>, ctx: &mut TxContext) {
        transfer::public_transfer(coin, tx_context::sender(ctx));
    }
}
