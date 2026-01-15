/// Cross-module test - helper module
module test::weak_randomness_helper {
    /// Uses provided seed for selection
    public fun select_winner(seed: u64) {
        let winner_index = seed % 100;
        // If seed is weak (from timestamp), this is vulnerable
    }

    /// Uses proper randomness
    public fun select_winner_safe(r: &sui::random::Random, ctx: &mut sui::tx_context::TxContext) {
        let mut gen = sui::random::new_generator(r, ctx);
        let random = sui::random::generate_u64(&mut gen);
        let _ = random % 100;
    }
}
