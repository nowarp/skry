/// Multihop SAFE test - A calls B, B calls C, C transfers
/// Tests that transitive has-transfer*? works correctly
module test::missing_transfer_safe_hop_a {
    use sui::tx_context::TxContext;
    use test::missing_transfer_safe_hop_b;

    /// SAFE: Entry calls B which calls C which properly transfers
    /// Should NOT be flagged - transfer happens in callee chain
    public entry fun initiate_safe_withdrawal(
        pool: &mut missing_transfer_safe_hop_b::Pool,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        missing_transfer_safe_hop_b::process_safe_withdrawal(pool, amount, recipient, ctx);
    }
}
