/// FQN collision test - module B
module test::fqn_collision_b {
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    public struct Cap has key {
        id: UID,
    }

    fun init(ctx: &mut TxContext) {
        let cap = Cap { id: object::new(ctx) };
        sui::transfer::transfer(cap, sui::tx_context::sender(ctx));
    }

    /// SAFE: Doesn't call init
    public entry fun action(ctx: &mut TxContext) {
        // Normal operation
    }
}
