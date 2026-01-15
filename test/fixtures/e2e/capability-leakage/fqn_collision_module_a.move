/// Capability Leakage - FQN Collision Test (Module A)
/// Tests FQN resolution for capability leakage detection

module test::module_a {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    /// Privileged AdminCap in module A
    public struct AdminCap has key, store {
        id: UID,
    }

    /// Init creates AdminCap
    fun init(ctx: &mut TxContext) {
        let admin = AdminCap { id: object::new(ctx) };
        transfer::transfer(admin, tx_context::sender(ctx));
    }

    /// VULNERABLE: Returns module_a::AdminCap without auth
    /// Should be flagged (module_a::AdminCap is privileged)
    // @expect: capability-leakage
    public fun get_admin_cap(ctx: &mut TxContext): AdminCap {
        AdminCap { id: object::new(ctx) }
    }

    /// VULNERABLE: Transfers module_a::AdminCap to tainted recipient
    // @expect: capability-leakage
    public entry fun leak_admin_cap(recipient: address, ctx: &mut TxContext) {
        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, recipient);
    }

    /// SAFE: Requires AdminCap to return AdminCap
    public fun create_admin_with_auth(
        _admin: &AdminCap,
        ctx: &mut TxContext
    ): AdminCap {
        AdminCap { id: object::new(ctx) }
    }
}
