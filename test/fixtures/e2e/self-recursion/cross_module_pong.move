/// Cross-module recursion test - module B (pong)
module test::cross_pong {
    /// Cross-module chain endpoint (ping -> pong)
    /// Move doesn't allow circular deps, so this terminates the chain
    // @false-negative: self-recursion (cross-module chain not detected)
    public fun pong(n: u64): u64 {
        n
    }
}
