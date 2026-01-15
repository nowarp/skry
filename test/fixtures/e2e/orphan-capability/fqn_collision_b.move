/// FQN collision test - module B
module test::fqn_collision_b {
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    public struct OwnerCap has key {
        id: UID,
    }

    /// SAFE: OwnerCap is used
    public entry fun action(_cap: &OwnerCap, ctx: &mut TxContext) {
        // Protected
    }
}
