/// Re-export test - Module B (re-exports ReexportCap from C)
module test::reexport_b {
    use sui::tx_context::TxContext;
    use test::reexport_c::{Self, ReexportCap};

    // @expect: test-only-missing
    public fun wrap(ctx: &mut TxContext): ReexportCap {
        reexport_c::create(ctx)
    }
}
