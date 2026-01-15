/// FQN collision test - module A
module test::fqn_collision_a {
    use sui::tx_context::TxContext;

    public struct Data has drop {
        value: u64
    }

    /// Same struct name as module B, but different FQN
    // @expect: duplicated-branch-condition
    public fun process(data: Data) {
        if (data.value > 100) {
            // First branch
        } else if (data.value > 100) {  // DUPLICATE in module A
            // Dead code
        } else {
            // Default
        }
    }
}
