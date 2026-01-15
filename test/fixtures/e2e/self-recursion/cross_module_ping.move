/// Cross-module recursion test - module A (ping)
module test::cross_ping {
    use test::cross_pong;

    /// VULNERABLE: Cross-module call chain (ping -> pong)
    // @false-negative: self-recursion
    public fun ping(n: u64): u64 {
        if (n == 0) {
            0
        } else {
            cross_pong::pong(n - 1)
        }
    }

    /// VULNERABLE: Entry that triggers cross-module recursion
    // @false-negative: self-recursion
    public entry fun start_ping_pong(n: u64, _ctx: &mut sui::tx_context::TxContext) {
        let _result = ping(n);
    }
}
