/// Cross-module tests for admin-bypasses-pause rule.
/// Tests IPA across module boundaries.
module test::pause_helper {
    use sui::coin::{Self, Coin};
    use sui::balance::Balance;
    use sui::sui::SUI;
    use sui::tx_context::TxContext;
    use sui::transfer;

    /// Helper with sink (no pause check) - called from other module
    public fun withdraw_no_check(
        balance: &mut Balance<SUI>,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }

    /// Helper that checks pause before sink - called from other module
    public fun withdraw_with_check(
        balance: &mut Balance<SUI>,
        paused: bool,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        assert!(!paused, 0);
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }
}
