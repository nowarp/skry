/// FQN collision test - module A
module test::fqn_collision_a {
    use sui::tx_context::TxContext;

    public struct Data has drop {
        value: u64
    }

    /// UNUSED: data parameter never used
    // @expect: unused-arg
    public fun process(data: Data, amount: u64) {
        let _ = amount + 100;  // Only uses amount
    }
}
