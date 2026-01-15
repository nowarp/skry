/// IPA test - safe entry -> helper with proper random
module test::weak_randomness_ipa_safe {
    use sui::random::{Self, Random};
    use sui::tx_context::TxContext;

    /// SAFE: Entry gets proper random, passes to helper
    public entry fun pick_winner(r: &Random, ctx: &mut TxContext) {
        let mut gen = random::new_generator(r, ctx);
        let strong_random = random::generate_u64(&mut gen);
        select_winner(strong_random);
    }

    fun select_winner(seed: u64) {
        let winner_index = seed % 100;
        // Safe: using cryptographically secure randomness
    }
}
