/// Intermediate module - just passes through to C
module test::sink_callee_b {
    use sui::balance::Balance;
    use sui::tx_context::TxContext;
    use test::sink_callee_c;

    /// Intermediate - passes through to C (flagged because public + leads to sink)
    // @expect: generic-type-mismatch
    public fun intermediate_withdraw<T>(balance: &mut Balance<T>, amount: u64, ctx: &mut TxContext) {
        sink_callee_c::do_extract<T>(balance, amount, ctx);
    }
}
