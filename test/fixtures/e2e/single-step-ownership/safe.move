module test::safe_patterns {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    public struct AdminCap has key, store { id: UID }
    public struct AuthCap has key { id: UID }

    fun init(ctx: &mut TxContext) {
        transfer::transfer(AdminCap { id: object::new(ctx) }, tx_context::sender(ctx));
    }

    /// Takes by reference, not by value
    public fun use_admin(_cap: &AdminCap, recipient: address) {
        // Cannot transfer - only has reference
    }

    /// Init is allowed (one-time setup)
    fun init_transfer(ctx: &mut TxContext) {
        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    /// Transfers to sender (not tainted third-party)
    public fun transfer_to_self(cap: AdminCap, ctx: &TxContext) {
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    /// Destroys cap instead of transferring - safe
    public fun destroy_admin(cap: AdminCap) {
        let AdminCap { id } = cap;
        object::delete(id);
    }

    /// Transfers to hardcoded address - not user-controlled, safe
    public fun transfer_to_treasury(cap: AdminCap) {
        transfer::transfer(cap, @0x123);
    }
}
