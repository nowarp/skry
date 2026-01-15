/// FQN collision test - module A
module test::fqn_collision_a {
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    const VERSION: u64 = 1;

    public struct Config has key {
        id: UID,
        version: u64,
    }

    /// Has version check
    public entry fun update_checked(config: &mut Config, ctx: &mut TxContext) {
        assert!(config.version == VERSION, 0);
    }

    /// VULNERABLE: Missing version check
    // @expect: version-check-missing
    public entry fun update_unchecked(config: &mut Config, ctx: &mut TxContext) {
        // Missing check
    }
}
