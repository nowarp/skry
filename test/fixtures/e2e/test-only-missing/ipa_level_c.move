/// IPA Level C: The actual creator (bottom of chain)
module test::ipa_level_c {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    public struct IpaCap has key, store {
        id: UID,
    }

    /// Creates the capability (PUBLIC)
    // @expect: test-only-missing
    public fun create(ctx: &mut TxContext): IpaCap {
        IpaCap { id: object::new(ctx) }
    }
}
