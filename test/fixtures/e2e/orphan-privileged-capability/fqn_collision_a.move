/// FQN collision test - module A
module test::fqn_collision_a {
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};

    /// ORPHAN: MasterCap never used
    // @expect: orphan-privileged-capability
    public struct MasterCap has key {
        id: UID,
    }

    fun init(ctx: &mut TxContext) {
        sui::transfer::transfer(
            MasterCap { id: object::new(ctx) },
            tx_context::sender(ctx)
        );
    }

    public entry fun dangerous_action() {
        // Missing MasterCap check
    }
}
