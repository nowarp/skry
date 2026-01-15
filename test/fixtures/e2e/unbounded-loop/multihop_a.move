/// Multihop test - A calls B
module test::unbounded_loop_hop_a {
    use sui::tx_context::TxContext;
    use test::unbounded_loop_hop_b;

    /// Entry point - passes tainted count through chain
    // @expect: unbounded-loop
    public entry fun start_processing(count: u64, ctx: &mut TxContext) {
        unbounded_loop_hop_b::middle_process(count);
    }
}
