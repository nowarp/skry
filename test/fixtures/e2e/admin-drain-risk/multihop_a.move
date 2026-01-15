/// Multihop test - A calls B
module test::admin_drain_hop_a {
    use sui::tx_context::TxContext;
    use sui::object::UID;
    use test::admin_drain_hop_b;

    public struct AdminCap has key, store {
        id: UID,
    }

    /// Entry point with admin cap - starts drain chain
    // @expect: admin-drain-risk
    public entry fun admin_rescue_funds(
        _admin: &AdminCap,
        vault: &mut admin_drain_hop_b::UserVault,
        recipient: address,
        ctx: &mut TxContext
    ) {
        admin_drain_hop_b::process_withdrawal(vault, recipient, ctx);
    }
}
