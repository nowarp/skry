module test::safe_two_step {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use std::option::{Self, Option};

    public struct AdminCap has key, store { id: UID }

    public struct AdminState has key {
        id: UID,
        pending_admin: Option<address>,
    }

    fun init(ctx: &mut TxContext) {
        transfer::transfer(AdminCap { id: object::new(ctx) }, tx_context::sender(ctx));
        transfer::share_object(AdminState {
            id: object::new(ctx),
            pending_admin: option::none(),
        });
    }

    public fun offer_admin(_cap: &AdminCap, state: &mut AdminState, new_admin: address) {
        state.pending_admin = option::some(new_admin);
    }

    public fun claim_admin(state: &mut AdminState, ctx: &mut TxContext): AdminCap {
        let pending = option::extract(&mut state.pending_admin);
        assert!(pending == tx_context::sender(ctx), 1);
        AdminCap { id: object::new(ctx) }
    }

    public fun cancel_pending(_cap: &AdminCap, state: &mut AdminState) {
        state.pending_admin = option::none();
    }
}
