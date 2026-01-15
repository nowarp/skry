/// Cross-module sender test - B calls C
module test::weak_randomness_sender_hop_b {
    use test::weak_randomness_sender_hop_c;

    /// Middle hop - propagates sender-derived seed
    public fun process_seed(seed: u64) {
        weak_randomness_sender_hop_c::finalize_lottery(seed);
    }
}
