/// Multihop test - C does extraction without transfer
module test::missing_transfer_hop_c {
    use sui::coin::{Self, Coin};
    use sui::balance::Balance;
    use sui::sui::SUI;
    use sui::tx_context::TxContext;

    /// Final hop - VULNERABLE: extracts but doesn't transfer
    // @expect: missing-transfer
    public fun execute_extraction(
        balance: &mut Balance<SUI>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(balance, amount, ctx);
        // Missing transfer - put back
        coin::put(balance, coins);
    }
}
