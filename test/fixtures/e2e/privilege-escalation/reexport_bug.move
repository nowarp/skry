/// BUG TEST: Type resolution doesn't follow re-exports (module A)
/// Imports PrivCap from C, calls B::wrap which also returns C::PrivCap.
module test::priv_reexport_a {
    use sui::tx_context::TxContext;
    use test::priv_reexport_b;
    use test::priv_reexport_c::PrivCap;

    /// BUG: FunReturnType resolves to test::priv_reexport_b::PrivCap
    /// but IsPrivileged fact exists for test::priv_reexport_c::PrivCap
    /// So creates-privileged-cap? fails to match (IPA propagates wrong FQN).
    // @expect: privilege-escalation
    public fun get_priv_cap(ctx: &mut TxContext): PrivCap {
        priv_reexport_b::wrap(ctx)
    }
}
