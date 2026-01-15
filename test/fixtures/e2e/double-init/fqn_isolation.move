/// FQN isolation test: same simple name (do_init) in different modules
/// Tests that FQN matching doesn't cross-contaminate between modules
module test::fqn_iso_a {
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::object::{Self, UID};

    public struct CapA has key {
        id: UID,
    }

    fun init(ctx: &mut TxContext) {
        do_init(ctx);
    }

    fun do_init(ctx: &mut TxContext) {
        let cap = CapA { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    /// VULNERABLE: Calls A::do_init
    // @expect: double-init
    public entry fun reset_a(ctx: &mut TxContext) {
        do_init(ctx);
    }
}

module test::fqn_iso_b {
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::object::{Self, UID};

    public struct CapB has key {
        id: UID,
    }

    fun init(ctx: &mut TxContext) {
        do_init(ctx);
    }

    fun do_init(ctx: &mut TxContext) {
        let cap = CapB { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    /// VULNERABLE: Calls B::do_init (its own module's init helper)
    // @expect: double-init
    public entry fun reset_b(ctx: &mut TxContext) {
        do_init(ctx);
    }

    /// SAFE: This is a normal action, not calling do_init
    public entry fun normal_b(_ctx: &mut TxContext) {
        // Normal operation
    }
}
