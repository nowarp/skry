module test::sender_param {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    public struct Cap has key {
        id: UID,
    }

    public struct HelperCap has key {
        id: UID,
    }

    fun init(ctx: &mut TxContext) {
        let authority = tx_context::sender(ctx);
        create_and_transfer(authority, ctx);
    }

    fun create_and_transfer(recipient: address, ctx: &mut TxContext) {
        let cap = Cap { id: object::new(ctx) };
        transfer::public_transfer(cap, recipient);
    }

    public entry fun create_helper_cap(ctx: &mut TxContext) {
        let sender_addr = tx_context::sender(ctx);
        helper_create(sender_addr, ctx);
    }

    fun helper_create(recipient: address, ctx: &mut TxContext) {
        let helper_cap = HelperCap { id: object::new(ctx) };
        transfer::public_transfer(helper_cap, recipient);
    }
}
