module test::fqn_a {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    /// AdminCap in this module IS privileged
    public struct AdminCap has key, store { id: UID }

    fun init(ctx: &mut TxContext) {
        transfer::transfer(AdminCap { id: object::new(ctx) }, tx_context::sender(ctx));
    }

    // @expect: single-step-ownership
    public fun transfer_admin(cap: AdminCap, addr: address) {
        transfer::transfer(cap, addr);
    }
}
