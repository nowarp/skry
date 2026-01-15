/// Tests both public entry and public fun are flagged
/// Both are externally callable and should be checked
module test::entry_vs_public {
    use sui::coin;
    use sui::balance::Balance;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    /// VULNERABLE: public function (entry removed - Balance<T> not valid entry param)
    // @expect: generic-type-mismatch
    public fun entry_withdraw<T>(balance: &mut Balance<T>, amount: u64, ctx: &mut TxContext) {
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// VULNERABLE: public fun (non-entry) - still callable from entry points
    // @expect: generic-type-mismatch
    public fun public_withdraw<T>(balance: &mut Balance<T>, amount: u64, ctx: &mut TxContext) {
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// SAFE: private fun - not directly callable
    fun private_withdraw<T>(balance: &mut Balance<T>, amount: u64, ctx: &mut TxContext) {
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }
}
