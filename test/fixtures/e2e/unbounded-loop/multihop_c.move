/// Multihop test - C uses tainted bound
module test::unbounded_loop_hop_c {
    /// Final hop - loop here, but flagged at entry point start_processing
    public fun final_loop(iterations: u64) {
        let mut i = 0;
        while (i < iterations) {  // Tainted from A through B
            i = i + 1;
        };
    }
}
