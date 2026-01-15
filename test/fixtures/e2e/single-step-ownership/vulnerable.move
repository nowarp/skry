module test::single_step_ownership {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    public struct AdminCap has key, store { id: UID }
    public struct AuthCap has key, store { id: UID }

    fun init(ctx: &mut TxContext) {
        transfer::transfer(AdminCap { id: object::new(ctx) }, tx_context::sender(ctx));
    }

    // @expect: single-step-ownership
    public fun transfer_admin(cap: AdminCap, new_admin: address) {
        transfer::transfer(cap, new_admin);
    }

    // @expect: single-step-ownership
    public entry fun change_owner(cap: AdminCap, recipient: address) {
        transfer::public_transfer(cap, recipient);
    }

    /// Has auth check but still vulnerable to typos - cap lost forever
    // @expect: single-step-ownership
    public fun transfer_with_auth(_auth: &AuthCap, cap: AdminCap, new_admin: address) {
        transfer::transfer(cap, new_admin);
    }
}
