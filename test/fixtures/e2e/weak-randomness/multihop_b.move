/// Multihop test - B calls C
module test::weak_randomness_hop_b {
    use test::weak_randomness_hop_c;

    /// Middle hop - propagates weak random
    public fun process_random(seed: u64) {
        weak_randomness_hop_c::finalize_selection(seed);
    }
}
