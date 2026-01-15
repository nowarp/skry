/// Multihop test - A calls B
module test::missing_transfer_hop_a {
    use sui::tx_context::TxContext;
    use test::missing_transfer_hop_b;

    /// Entry point - calls module B
    // @expect: missing-transfer
    public entry fun initiate_withdrawal(
        pool: &mut missing_transfer_hop_b::Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        missing_transfer_hop_b::process_withdrawal(pool, amount, ctx);
    }
}
