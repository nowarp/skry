/// Test FQN collision handling with aliased imports
module test::fqn_collision_alias {
    use sui::object::{Self, UID};
    use test::fqn_collision_a::OwnerCap as AOwnerCap;

    /// VULNERABLE: Anyone can burn aliased OwnerCap from module A
    // @expect: missing-destroy-guard
    public entry fun burn_aliased(cap: AOwnerCap) {
        let AOwnerCap { id } = cap;
        object::delete(id);
    }
}
