/// FQN collision test - module A
module test::fqn_collision_a {
    use sui::tx_context::{Self, TxContext};
    use sui::object::UID;

    public struct Game has key {
        id: UID,
        seed: u64
    }

    /// VULNERABLE: Uses epoch as randomness
    // @expect: weak-randomness
    public entry fun play(game: &Game, ctx: &mut TxContext) {
        let random = tx_context::epoch(ctx);  // Weak
        let _ = random % 10;
    }
}
