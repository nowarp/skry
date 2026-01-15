/// FQN conflict test: module_a with shared AdminCap (vulnerable)
module test::module_a {
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};

    /// VULNERABLE: AdminCap is shared (same simple name as module_b::AdminCap)
    // @expect: shared-capability-exposure
    public struct AdminCap has key {
        id: UID,
    }

    /// Shares AdminCap
    fun init(ctx: &mut TxContext) {
        let cap = AdminCap { id: object::new(ctx) };
        transfer::share_object(cap);  // WRONG: should use transfer::transfer
    }
}
