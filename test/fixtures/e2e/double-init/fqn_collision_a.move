/// FQN collision test - module A
module test::fqn_collision_a {
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    public struct Cap has key {
        id: UID,
    }

    fun init(ctx: &mut TxContext) {
        do_init(ctx);
    }

    fun do_init(ctx: &mut TxContext) {
        let cap = Cap { id: object::new(ctx) };
        sui::transfer::transfer(cap, sui::tx_context::sender(ctx));
    }

    /// VULNERABLE: Calls initializer
    // @expect: double-init
    public entry fun reset(ctx: &mut TxContext) {
        do_init(ctx);
    }
}
