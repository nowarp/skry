/// Test FQN collision handling for OwnerCap (module A)
module test::fqn_collision_a {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    /// OwnerCap in module A - will collide with module B's OwnerCap
    public struct OwnerCap has key { id: UID }

    fun init(ctx: &mut TxContext) {
        let cap = OwnerCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    /// VULNERABLE: Anyone can burn OwnerCap from module A
    // @expect: missing-destroy-guard
    public entry fun burn_cap(cap: OwnerCap) {
        let OwnerCap { id } = cap;
        object::delete(id);
    }
}
