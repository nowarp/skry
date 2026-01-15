/// Multiple helpers test: init calls multiple helper functions
/// Tests that all helpers are marked as InitImpl
module test::multi_helper {
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::object::{Self, UID};

    public struct AdminCap has key {
        id: UID,
    }

    public struct Registry has key {
        id: UID,
        initialized: bool,
    }

    fun init(ctx: &mut TxContext) {
        create_admin(ctx);
        create_registry(ctx);
    }

    fun create_admin(ctx: &mut TxContext) {
        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    fun create_registry(ctx: &mut TxContext) {
        let reg = Registry {
            id: object::new(ctx),
            initialized: true
        };
        transfer::share_object(reg);
    }

    /// VULNERABLE: Recreates admin cap
    // @expect: double-init
    public entry fun reset_admin(ctx: &mut TxContext) {
        create_admin(ctx);
    }

    /// VULNERABLE: Recreates registry
    // @expect: double-init
    public entry fun reset_registry(ctx: &mut TxContext) {
        create_registry(ctx);
    }

    /// VULNERABLE: Full system reset
    // @expect: double-init
    public entry fun full_reset(ctx: &mut TxContext) {
        create_admin(ctx);
        create_registry(ctx);
    }

    /// SAFE: Normal operation
    public entry fun normal_op(_ctx: &mut TxContext) {
        // Normal stuff
    }
}
