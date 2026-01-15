/// Type resolution test (module A)
/// Calls B which calls C - tests IPA chain for test-only-missing
module test::reexport_a {
    use sui::tx_context::TxContext;
    use test::reexport_b;
    use test::reexport_c::ReexportCap;

    // @expect: test-only-missing
    public fun get_cap(ctx: &mut TxContext): ReexportCap {
        reexport_b::wrap(ctx)
    }
}
