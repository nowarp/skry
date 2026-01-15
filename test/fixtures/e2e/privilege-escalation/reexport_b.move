/// BUG TEST: Type resolution - Module B (re-exports PrivCap from C)
module test::priv_reexport_b {
    use sui::tx_context::TxContext;
    use test::priv_reexport_c::{Self, PrivCap};

    // @expect: privilege-escalation
    public fun wrap(ctx: &mut TxContext): PrivCap {
        priv_reexport_c::create(ctx)
    }
}
