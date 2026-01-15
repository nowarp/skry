/// Privilege Escalation - Cross-Module Test (Vulnerable Module)
/// Module that improperly creates privileged capabilities from another module

module test::vulnerable_module {
    use test::cap_module::{Self, OperatorCap};
    use sui::transfer;
    use sui::tx_context::TxContext;

    /// VULNERABLE: Creates OperatorCap (from cap_module) without AdminCap check
    /// Privilege escalation across module boundary
    // @expect: privilege-escalation
    public entry fun create_operator_unsafe(recipient: address, ctx: &mut TxContext) {
        let cap = cap_module::create_operator_cap(ctx);
        transfer::public_transfer(cap, recipient);
    }

    /// SAFE: Uses the safe wrapper that checks AdminCap
    public entry fun create_operator_safe(
        admin: &test::cap_module::AdminCap,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let cap = cap_module::create_operator_with_admin(admin, ctx);
        transfer::public_transfer(cap, recipient);
    }
}
