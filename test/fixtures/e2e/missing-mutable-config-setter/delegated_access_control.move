// Test case: Delegated access control pattern (like MultiversX bridge)
// The setter calls another function to check access, rather than taking a capability parameter
// Should NOT trigger missing-mutable-config-setter rule (but currently does - FP)
module test::delegated_setter {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};

    // Has delegated setter via checkOwnerRole - should NOT trigger rule
    // but rule doesn't detect transitive auth checks
    public struct Config has key {
        id: UID,
        fee_rate: u64,
        owner: address,
    }

    fun init(ctx: &mut TxContext) {
        let config = Config {
            id: object::new(ctx),
            fee_rate: 100,
            owner: tx_context::sender(ctx),
        };
        sui::transfer::share_object(config);
    }

    // Access control helper - checks sender against stored owner
    public fun checkOwnerRole(config: &Config, ctx: &TxContext) {
        assert!(config.owner == tx_context::sender(ctx), 0);
    }

    // Delegated setter - calls checkOwnerRole instead of taking capability parameter
    // This is a valid privileged setter but rule doesn't detect it
    public fun set_fee_rate(config: &mut Config, new_rate: u64, ctx: &TxContext) {
        checkOwnerRole(config, ctx);  // Delegated access control
        config.fee_rate = new_rate;
    }
}
