/// FQN conflict test: module_a with public creator without test_only (vulnerable)
module test::module_a {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    /// AdminCap (same simple name as module_b::AdminCap)
    public struct AdminCap has key, store {
        id: UID,
    }

    /// VULNERABLE: No #[test_only]
    // @expect: test-only-missing
    public fun create_admin_cap(ctx: &mut TxContext): AdminCap {
        AdminCap { id: object::new(ctx) }
    }
}
