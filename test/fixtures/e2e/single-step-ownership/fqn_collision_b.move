module test::fqn_b {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    /// AdminCap in this module is NOT privileged (user token)
    public struct AdminCap has key, store { id: UID }

    fun init(ctx: &mut TxContext) {
        transfer::transfer(AdminCap { id: object::new(ctx) }, tx_context::sender(ctx));
    }

    /// This AdminCap is NOT privileged, just a user token - should NOT trigger
    public fun transfer_cap(cap: AdminCap, recipient: address) {
        transfer::transfer(cap, recipient);
    }
}
