/// Test FQN collision handling for OwnerCap (module B)
module test::fqn_collision_b {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    /// OwnerCap in module B - same simple name as module A
    public struct OwnerCap has key { id: UID }

    fun init(ctx: &mut TxContext) {
        let cap = OwnerCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    /// SAFE: Guarded by OwnerCap reference
    // @safe: missing-destroy-guard
    public entry fun burn_cap_guarded(_guard: &OwnerCap, cap: OwnerCap) {
        let OwnerCap { id } = cap;
        object::delete(id);
    }
}
