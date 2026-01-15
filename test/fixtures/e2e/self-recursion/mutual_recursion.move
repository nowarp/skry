/// Mutual recursion tests: functions that call each other in a cycle
module test::mutual_recursion {
    use sui::tx_context::TxContext;

    /// VULNERABLE: Part of mutual recursion cycle (is_even <-> is_odd)
    // @false-negative: self-recursion
    public fun is_even(n: u64): bool {
        if (n == 0) {
            true
        } else {
            is_odd(n - 1)
        }
    }

    /// VULNERABLE: Part of mutual recursion cycle
    // @false-negative: self-recursion
    public fun is_odd(n: u64): bool {
        if (n == 0) {
            false
        } else {
            is_even(n - 1)
        }
    }

    /// VULNERABLE: Entry that uses mutual recursion
    // @false-negative: self-recursion
    public entry fun check_parity(n: u64, _ctx: &mut TxContext) {
        let _even = is_even(n);
        let _odd = is_odd(n);
    }

    /// VULNERABLE: Three-way cycle (a -> b -> c -> a)
    // @false-negative: self-recursion
    public fun cycle_a(n: u64): u64 {
        if (n == 0) { 0 } else { cycle_b(n - 1) }
    }

    // @false-negative: self-recursion
    public fun cycle_b(n: u64): u64 {
        if (n == 0) { 0 } else { cycle_c(n - 1) }
    }

    // @false-negative: self-recursion
    public fun cycle_c(n: u64): u64 {
        if (n == 0) { 0 } else { cycle_a(n - 1) }
    }

    /// SAFE: No cycle - just chain of calls
    public fun chain_a(n: u64): u64 {
        chain_b(n)
    }

    public fun chain_b(n: u64): u64 {
        chain_c(n)
    }

    public fun chain_c(n: u64): u64 {
        n * 2
    }
}
