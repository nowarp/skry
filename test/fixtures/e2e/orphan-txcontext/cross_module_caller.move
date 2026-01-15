/// Cross-module caller
module test::orphan_txcontext_caller {
    use sui::tx_context::TxContext;
    use test::orphan_txcontext_callee;

    /// Calls helper that USES TxContext - this is safe
    public entry fun call_helper(ctx: &mut TxContext) {
        orphan_txcontext_callee::used_cross_module(ctx);
    }

    /// Passes TxContext to helper that DOESN'T use it
    /// The callee (unused_txcontext_param) should be flagged, not this function
    public entry fun call_unused_helper(ctx: &mut TxContext) {
        orphan_txcontext_callee::unused_txcontext_param(ctx, 100);
    }
}
