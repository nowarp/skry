/// THE ACTUAL SINK - extracts coins without validation
/// This is 3 hops deep from entry point
module test::sink_callee_c {
    use sui::coin;
    use sui::balance::Balance;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    /// Extracts without validation - the vulnerable sink
    // @expect: generic-type-mismatch
    public fun do_extract<T>(balance: &mut Balance<T>, amount: u64, ctx: &mut TxContext) {
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }
}
