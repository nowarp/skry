/// Test: #[test_only] on wrapper should exclude wrapper, but creator is still flagged
module test::test_only_wrapper {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    public struct WrapperCap has key, store {
        id: UID,
    }

    /// Creator: Public, no test_only, no auth
    // @expect: test-only-missing
    public fun create_raw(ctx: &mut TxContext): WrapperCap {
        WrapperCap { id: object::new(ctx) }
    }

    /// Wrapper with test_only: calls create_raw
    /// SAFE: Has #[test_only] attribute
    #[test_only]
    public fun create_for_testing(ctx: &mut TxContext): WrapperCap {
        create_raw(ctx)
    }
}
