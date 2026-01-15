/// Cross-module test: capability module
module test::cap_module {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    /// Admin capability
    public struct AdminCap has key, store {
        id: UID,
    }

    /// Helper to create AdminCap
    public fun create(ctx: &mut TxContext): AdminCap {
        AdminCap { id: object::new(ctx) }
    }
}
