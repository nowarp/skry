/// Cross-module test - entry module
module test::admin_drain_entry {
    use sui::tx_context::TxContext;
    use test::admin_drain_helper;

    public struct AdminCap has key, store {
        id: sui::object::UID,
    }

    /// VULNERABLE: Admin entry calls helper with tainted recipient
    // @expect: admin-drain-risk
    public entry fun emergency_withdraw(
        _admin: &AdminCap,
        vault: &mut admin_drain_helper::UserVault,
        recipient: address,
        ctx: &mut TxContext
    ) {
        admin_drain_helper::drain_vault(vault, recipient, ctx);
    }
}
