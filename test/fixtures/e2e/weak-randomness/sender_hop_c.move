/// Cross-module sender test - C uses weak random
module test::weak_randomness_sender_hop_c {
    /// Final hop - uses sender-derived seed for lottery
    /// The entrypoint in A MUST be detected
    public fun finalize_lottery(seed: u64) {
        let winner = seed % 100;
        // Predictable - derived from sender address
    }
}
