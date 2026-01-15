/// FQN collision test - module B
module test::fqn_collision_b {
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};

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

    /// SAFE: MasterCap is used
    public entry fun protected_action(_cap: &MasterCap) {
        // Protected
    }
}
