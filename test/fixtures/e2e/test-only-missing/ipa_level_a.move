/// IPA Level A: Entry point (top of chain)
module test::ipa_level_a {
    use sui::tx_context::TxContext;
    use test::ipa_level_b;
    use test::ipa_level_c::IpaCap;

    /// Public entry through 3-module chain
    // @expect: test-only-missing
    public fun get_cap(ctx: &mut TxContext): IpaCap {
        ipa_level_b::wrap(ctx)
    }
}
