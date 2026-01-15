/// FQN collision test - module B
module test::fqn_collision_b {
    use sui::random::{Self, Random};
    use sui::tx_context::TxContext;
    use sui::object::UID;

    public struct Game has key {
        id: UID,
        seed: u64
    }

    /// SAFE: Uses sui::random
    public entry fun play(game: &Game, r: &Random, ctx: &mut TxContext) {
        let mut gen = random::new_generator(r, ctx);
        let random = random::generate_u64(&mut gen);
        let _ = random % 10;
    }
}
