/// Cross-module test: capability defined here, shared in init_module
module test::cap_module {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    /// VULNERABLE: Admin capability (will be shared in init_module)
    // @expect: shared-capability-exposure
    public struct AdminCap has key, store {
        id: UID,
    }

    /// Factory function to create AdminCap
    public fun create_admin_cap(ctx: &mut TxContext): AdminCap {
        AdminCap { id: object::new(ctx) }
    }
}
