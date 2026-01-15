/// Test cases for missing-destroy-guard rule.
/// Tests detection of capability destruction without authorization.
module test::destroy_guard {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    /// Admin capability - single-UID privileged struct
    public struct AdminCap has key {
        id: UID,
    }

    /// Owner capability
    public struct OwnerCap has key {
        id: UID,
    }

    /// Treasury capability
    public struct TreasuryCap has key {
        id: UID,
    }

    // =========================================================================
    // VULNERABLE: Capability destruction without authorization
    // =========================================================================

    /// VULNERABLE: Anyone can burn admin cap
    // @expect: missing-destroy-guard
    public entry fun burn_admin_cap(cap: AdminCap) {
        let AdminCap { id } = cap;
        object::delete(id);
    }

    /// Not detected: OwnerCap not created in init (not recognized as IsCapability)
    /// Would be vulnerable if OwnerCap was created in init
    public entry fun burn_owner_cap(cap: OwnerCap) {
        let OwnerCap { id } = cap;
        object::delete(id);
    }

    /// Not detected: TreasuryCap not created in init (not recognized as IsCapability)
    /// Would be vulnerable if TreasuryCap was created in init
    public entry fun burn_treasury_cap(cap: TreasuryCap) {
        let TreasuryCap { id } = cap;
        object::delete(id);
    }

    // =========================================================================
    // SAFE: Capability destruction with proper authorization
    // =========================================================================

    /// SAFE: Burning requires admin cap proof
    // @safe: missing-destroy-guard
    public entry fun burn_owner_with_admin(
        _admin: &AdminCap,
        cap: OwnerCap
    ) {
        let OwnerCap { id } = cap;
        object::delete(id);
    }

    /// SAFE: Self-destruction (owner burns their own cap)
    // @safe: missing-destroy-guard
    public entry fun self_burn_admin(
        admin: AdminCap,
        _proof: &AdminCap  // Must prove you have another admin cap
    ) {
        let AdminCap { id } = admin;
        object::delete(id);
    }

    // =========================================================================
    // Edge cases
    // =========================================================================

    /// NOT VULNERABLE: Init can destroy (setup logic)
    // @safe: missing-destroy-guard
    fun init(ctx: &mut TxContext) {
        // Create and immediately destroy a temporary cap (valid pattern)
        let temp = AdminCap { id: object::new(ctx) };
        let AdminCap { id } = temp;
        object::delete(id);

        // Create the real cap
        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }
}
