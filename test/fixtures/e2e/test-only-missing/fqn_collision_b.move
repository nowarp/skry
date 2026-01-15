/// FQN conflict test: module_b with public creator WITH test_only (safe)
module test::module_b {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    /// AdminCap (same simple name as module_a::AdminCap)
    public struct AdminCap has key, store {
        id: UID,
    }

    /// SAFE: Has #[test_only]
    #[test_only]
    public fun create_admin_cap(ctx: &mut TxContext): AdminCap {
        AdminCap { id: object::new(ctx) }
    }
}
