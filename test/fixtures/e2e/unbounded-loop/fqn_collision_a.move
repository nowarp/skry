/// FQN collision test - module A
module test::fqn_collision_a {
    use sui::tx_context::TxContext;
    use sui::object::UID;

    public struct Processor has key {
        id: UID,
        max_iterations: u64
    }

    /// VULNERABLE: Uses tainted loop bound
    // @expect: unbounded-loop
    public entry fun process(p: &Processor, count: u64) {
        let mut i = 0;
        while (i < count) {  // Tainted
            i = i + 1;
        };
    }
}
