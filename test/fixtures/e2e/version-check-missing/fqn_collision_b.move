/// FQN collision test - module B
module test::fqn_collision_b {
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    const VERSION: u64 = 2;

    public struct Config has key {
        id: UID,
        version: u64,
    }

    /// All functions check version
    public entry fun update_a(config: &mut Config, ctx: &mut TxContext) {
        assert!(config.version == VERSION, 0);
    }

    public entry fun update_b(config: &mut Config, ctx: &mut TxContext) {
        assert!(config.version == VERSION, 0);
    }
}
