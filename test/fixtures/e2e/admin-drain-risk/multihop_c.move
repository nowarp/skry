/// Multihop test - C does the drain
module test::admin_drain_hop_c {
    use sui::coin::{Self, Coin};
    use sui::balance::Balance;
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::TxContext;

    /// Final hop - VULNERABLE: drains to arbitrary recipient
    /// Only the entrypoint will be reported
    public fun execute_transfer(
        balance: &mut Balance<SUI>,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let amount = sui::balance::value(balance);
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, recipient);  // Admin can drain to anyone
    }
}
