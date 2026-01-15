/// Multihop test - C uses weak random
module test::weak_randomness_hop_c {
    /// Final hop - VULNERABLE: uses weak randomness from A
    /// The entrypoint MUST be detected (this one is not)
    public fun finalize_selection(random: u64) {
        let winner = random % 100;
        // Predictable outcome due to weak source
    }
}
