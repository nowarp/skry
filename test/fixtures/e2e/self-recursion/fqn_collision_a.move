/// FQN collision test - module A
module test::fqn_collision_a {
    use sui::tx_context::TxContext;

    public struct Counter has drop {
        value: u64
    }

    /// VULNERABLE: Recursive public function
    // @expect: self-recursion
    public fun count_down(counter: Counter, n: u64): u64 {
        if (n == 0) {
            0
        } else {
            count_down(counter, n - 1)
        }
    }
}
