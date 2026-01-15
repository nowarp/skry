/// Cross-module helper
module test::orphan_txcontext_callee {
    use sui::tx_context::TxContext;

    /// USED: Called from another module AND uses TxContext
    public(package) fun used_cross_module(ctx: &mut TxContext): address {
        sui::tx_context::sender(ctx)
    }

    /// ORPHAN: Not called from anywhere
    // @expect: orphan-txcontext
    public(package) fun orphan_cross_module(ctx: &mut TxContext): u64 {
        sui::tx_context::epoch(ctx)
    }

    /// ORPHAN: Called but TxContext NOT used (passed but ignored)
    // @expect: orphan-txcontext
    public(package) fun unused_txcontext_param(ctx: &mut TxContext, amount: u64): u64 {
        amount * 2
    }
}
