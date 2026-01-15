/// Capability Leakage - Cross-Module Test (Cap Module)
/// Defines capabilities and helper functions

module test::cap_module {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    /// Privileged admin capability
    public struct AdminCap has key {
        id: UID,
    }

    /// Init creates AdminCap
    fun init(ctx: &mut TxContext) {
        let admin = AdminCap { id: object::new(ctx) };
        transfer::transfer(admin, tx_context::sender(ctx));
    }

    /// Helper that creates AdminCap (exported for cross-module use)
    // @expect: capability-leakage
    public fun create_admin(ctx: &mut TxContext): AdminCap {
        AdminCap { id: object::new(ctx) }
    }

    /// Helper that transfers to a recipient
    public fun transfer_cap(cap: AdminCap, recipient: address) {
        transfer::transfer(cap, recipient);
    }

    /// SAFE: Creates AdminCap with auth check
    public fun create_admin_with_auth(
        _existing_admin: &AdminCap,
        ctx: &mut TxContext
    ): AdminCap {
        create_admin(ctx)
    }
}
