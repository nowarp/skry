/// Capability Leakage - IPA Test
/// Tests that capability leakage is detected through helper call chains

module test::capability_leakage_ipa {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    /// Privileged admin capability
    public struct AdminCap has key {
        id: UID,
    }

    /// Init creates AdminCap (transferred to sender)
    fun init(ctx: &mut TxContext) {
        let admin = AdminCap { id: object::new(ctx) };
        transfer::transfer(admin, tx_context::sender(ctx));
    }

    /// VULNERABLE: Returns AdminCap via helper chain without auth check
    /// Capability leakage through IPA
    // @expect: capability-leakage
    public entry fun leak_cap_via_helper(recipient: address, ctx: &mut TxContext) {
        let cap = create_admin_helper(ctx);
        transfer_helper(cap, recipient);
    }

    /// Helper that creates AdminCap (transitive creation)
    fun create_admin_helper(ctx: &mut TxContext): AdminCap {
        AdminCap { id: object::new(ctx) }
    }

    /// Helper that transfers to tainted recipient
    fun transfer_helper(cap: AdminCap, recipient: address) {
        transfer::transfer(cap, recipient);
    }

    /// VULNERABLE: Returns AdminCap directly without auth
    // @expect: capability-leakage
    public fun get_admin_cap(ctx: &mut TxContext): AdminCap {
        AdminCap { id: object::new(ctx) }
    }

    /// SAFE: Requires AdminCap to create another AdminCap
    public fun create_admin_safe(
        _existing_admin: &AdminCap,
        ctx: &mut TxContext
    ): AdminCap {
        AdminCap { id: object::new(ctx) }
    }
}
