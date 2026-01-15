/// A→B→C where C has the VULNERABLE SINK (not validator)
/// Entry point A calls B, B calls C, C extracts without validation
/// Tests if vulnerability propagates UP the call chain through IPA
module test::sink_callee_a {
    use sui::balance::Balance;
    use sui::tx_context::TxContext;
    use test::sink_callee_b;

    /// VULNERABLE: Calls chain A→B→C where C has unvalidated extraction
    /// IPA should propagate UnvalidatedTypeAtSink from C through B to A
    // @expect: generic-type-mismatch
    public fun entry_sink_chain<T>(balance: &mut Balance<T>, amount: u64, ctx: &mut TxContext) {
        sink_callee_b::intermediate_withdraw<T>(balance, amount, ctx);
    }
}
