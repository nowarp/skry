/// FQN collision test - module A
module test::fqn_collision_a {
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    /// ORPHAN: OwnerCap never used
    // @expect: orphan-capability
    public struct OwnerCap has key {
        id: UID,
    }

    public entry fun action(ctx: &mut TxContext) {
        // Missing OwnerCap check
    }
}
