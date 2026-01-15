/// FQN collision test - module B
module test::fqn_collision_b {
    use sui::tx_context::TxContext;

    public struct Counter has drop {
        value: u64
    }

    /// SAFE: Iterative approach
    public fun count_down(counter: Counter, n: u64): u64 {
        let mut result = n;
        while (result > 0) {
            result = result - 1;
        };
        result
    }
}
