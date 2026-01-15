/// IPA Level B: Middle wrapper
module test::ipa_level_b {
    use sui::tx_context::TxContext;
    use test::ipa_level_c::{Self, IpaCap};

    /// Wraps level C (PUBLIC)
    // @expect: test-only-missing
    public fun wrap(ctx: &mut TxContext): IpaCap {
        ipa_level_c::create(ctx)
    }
}
