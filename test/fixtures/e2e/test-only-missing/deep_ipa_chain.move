/// Deep IPA chain test: 3-level intra-module chain
/// Tests that CreatesCapability propagates through multiple levels
module test::deep_ipa {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    public struct DeepCap has key, store {
        id: UID,
    }

    /// Level 3: Actually creates the cap (PRIVATE)
    fun create_internal(ctx: &mut TxContext): DeepCap {
        DeepCap { id: object::new(ctx) }
    }

    /// Level 2: Middle wrapper (PRIVATE)
    fun wrap_create(ctx: &mut TxContext): DeepCap {
        create_internal(ctx)
    }

    /// Level 1: Public entry point - 3-level chain
    // @expect: test-only-missing
    public fun get_deep_cap(ctx: &mut TxContext): DeepCap {
        wrap_create(ctx)
    }

    /// SAFE: Has #[test_only]
    #[test_only]
    public fun get_deep_cap_test(ctx: &mut TxContext): DeepCap {
        wrap_create(ctx)
    }
}
