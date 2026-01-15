/// FQN collision test - module B
module test::fqn_collision_b {
    use sui::tx_context::TxContext;

    public struct Config has drop {
        mode: u64
    }

    /// SAFE: Different bodies
    public fun run(config: Config) {
        if (config.mode == 1) {
            let x = 42;
        } else {
            let x = 100;  // Different
        }
    }
}
