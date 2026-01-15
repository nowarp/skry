module test::cross_cap {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    public struct AdminCap has key, store { id: UID }

    fun init(ctx: &mut TxContext) {
        transfer::transfer(AdminCap { id: object::new(ctx) }, tx_context::sender(ctx));
    }

    /// Exported for cross-module use
    // @expect: single-step-ownership
    public fun do_transfer(cap: AdminCap, recipient: address) {
        transfer::transfer(cap, recipient);
    }
}
