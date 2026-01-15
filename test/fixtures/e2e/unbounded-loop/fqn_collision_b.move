/// FQN collision test - module B
module test::fqn_collision_b {
    use sui::tx_context::TxContext;
    use sui::object::UID;

    public struct Processor has key {
        id: UID,
        max_iterations: u64
    }

    /// SAFE: Uses validated bound
    public entry fun process(p: &Processor, count: u64) {
        assert!(count <= 1000, 0);
        let mut i = 0;
        while (i < count) {  // Sanitized
            i = i + 1;
        };
    }
}
