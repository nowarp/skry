/// Test: A->B(sanitize)->C chain - Module C (sink)
module test::sanitize_chain_c {

    /// Loop sink - vulnerability depends on caller chain
    public fun do_loop(iterations: u64) {
        let mut i = 0;
        while (i < iterations) {
            i = i + 1;
        };
    }
}
