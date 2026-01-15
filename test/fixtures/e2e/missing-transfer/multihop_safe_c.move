/// Multihop SAFE test - C does extraction AND transfer
module test::missing_transfer_safe_hop_c {
    use sui::coin;
    use sui::balance::Balance;
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::TxContext;

    /// Final hop - SAFE: extracts AND transfers
    public fun execute_safe_extraction(
        balance: &mut Balance<SUI>,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }
}
