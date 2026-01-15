/// FQN collision test - module B
module test::fqn_collision_b {
    use sui::tx_context::TxContext;

    public struct Data has drop {
        value: u64
    }

    /// SAFE: All parameters used
    public fun process(data: Data, amount: u64) {
        let _ = data.value + amount;
    }
}
