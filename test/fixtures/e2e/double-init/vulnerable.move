/// Test cases for double-init rule.
/// Public function calls module initializer (re-initialization risk)
module test::double_init {
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
        do_init(ctx);
    }

    /// Internal initializer - should only be called once
    fun do_init(ctx: &mut TxContext) {
        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    /// VULNERABLE: Calls initializer directly
    // @expect: double-init
    public entry fun reinitialize(ctx: &mut TxContext) {
        do_init(ctx);  // Re-initialization risk!
    }

    /// VULNERABLE: Another function calling initializer
    // @expect: double-init
    public entry fun reset_system(ctx: &mut TxContext) {
        do_init(ctx);  // Dangerous
    }

    /// SAFE: Does not call initializer
    public entry fun normal_action(_ctx: &mut TxContext) {
        // Normal operations
    }

    /// SAFE: Helper that doesn't call initializer
    fun setup_helper(_ctx: &mut TxContext) {
        // Setup logic without calling init
    }
}
