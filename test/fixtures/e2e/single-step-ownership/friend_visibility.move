module test::friend_vis {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    public struct AdminCap has key, store { id: UID }

    fun init(ctx: &mut TxContext) {
        transfer::transfer(AdminCap { id: object::new(ctx) }, tx_context::sender(ctx));
    }

    /// public(package) is internal - should not trigger
    public(package) fun internal_transfer(cap: AdminCap, addr: address) {
        transfer::transfer(cap, addr);
    }
}
