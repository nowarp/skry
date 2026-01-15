/// Test: A->B(sanitize)->C chain - Module B (middle hop)
module test::sanitize_chain_b {
    use test::sanitize_chain_c;

    /// Sanitizes before forwarding to C
    public fun validate_and_forward(count: u64) {
        assert!(count <= 100, 0);
        sanitize_chain_c::do_loop(count);
    }

    /// Forwards raw without sanitization
    public fun forward_raw(count: u64) {
        sanitize_chain_c::do_loop(count);
    }
}
