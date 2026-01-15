/// Cross-module test - helper module
module test::unbounded_loop_helper {
    /// VULNERABLE if called with tainted value (flagged at entry point, not here)
    public fun do_loop(iterations: u64) {
        let mut i = 0;
        while (i < iterations) {
            i = i + 1;
        };
    }

    /// SAFE: Has internal validation
    public fun do_loop_validated(iterations: u64) {
        assert!(iterations <= 1000, 0);
        let mut i = 0;
        while (i < iterations) {
            i = i + 1;
        };
    }
}
