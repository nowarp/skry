/// FQN collision test - module A
module test::fqn_collision_a {
    use sui::tx_context::TxContext;

    public struct Config has drop {
        mode: u64
    }

    /// CODE SMELL: Duplicated bodies
    // @expect: duplicated-branch-body
    public fun run(config: Config) {
        if (config.mode == 1) {
            let x = 42;
        } else {
            let x = 42;  // Duplicate
        }
    }
}
