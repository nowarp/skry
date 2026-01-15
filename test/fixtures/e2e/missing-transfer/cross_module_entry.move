/// Cross-module test - entry module
module test::missing_transfer_entry {
    use sui::coin::Coin;
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use test::missing_transfer_helper;

    /// VULNERABLE: Calls helper from another module that extracts without transfer
    // @expect: missing-transfer
    public entry fun withdraw_cross_module(
        pool: &mut missing_transfer_helper::Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        missing_transfer_helper::extract_no_transfer(pool, amount, ctx);
    }

    /// SAFE: Gets coin from helper and transfers
    public entry fun withdraw_cross_module_safe(
        pool: &mut missing_transfer_helper::Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = missing_transfer_helper::extract_and_return(pool, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }
}
