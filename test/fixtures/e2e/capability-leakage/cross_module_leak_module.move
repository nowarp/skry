/// Capability Leakage - Cross-Module Test (Leak Module)
/// Module that leaks capabilities from another module

module test::leak_module {
    use test::cap_module::{Self, AdminCap};
    use sui::tx_context::TxContext;

    /// VULNERABLE: Leaks AdminCap from cap_module to tainted recipient
    /// Cross-module capability leakage
    // @expect: capability-leakage
    public entry fun leak_admin_cross_module(recipient: address, ctx: &mut TxContext) {
        let cap = cap_module::create_admin(ctx);
        cap_module::transfer_cap(cap, recipient);
    }

    /// VULNERABLE: Returns AdminCap from another module without auth
    // @expect: capability-leakage
    public fun get_admin_from_other_module(ctx: &mut TxContext): AdminCap {
        cap_module::create_admin(ctx)
    }

    /// SAFE: Uses auth-checked wrapper from cap_module
    public entry fun create_admin_safe(
        admin: &AdminCap,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let cap = cap_module::create_admin_with_auth(admin, ctx);
        cap_module::transfer_cap(cap, recipient);
    }
}
