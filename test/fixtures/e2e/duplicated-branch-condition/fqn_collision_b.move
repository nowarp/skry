/// FQN collision test - module B
module test::fqn_collision_b {
    use sui::tx_context::TxContext;

    public struct Data has drop {
        value: u64
    }

    /// Same struct name as module A, different FQN, no duplicates
    public fun process(data: Data) {
        if (data.value > 200) {
            // Different threshold
        } else if (data.value > 100) {  // Different from first - NOT a duplicate
            // Medium
        } else {
            // Default
        }
    }
}
