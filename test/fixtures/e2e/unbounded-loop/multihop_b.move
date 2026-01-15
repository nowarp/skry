/// Multihop test - B calls C
module test::unbounded_loop_hop_b {
    use test::unbounded_loop_hop_c;

    /// Middle hop - propagates tainted count
    public fun middle_process(count: u64) {
        unbounded_loop_hop_c::final_loop(count);
    }
}
