/// Multihop test - B calls C
module test::admin_drain_hop_b {
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};
    use test::admin_drain_hop_c;

    public struct UserVault has key {
        id: UID,
        owner: address,
        balance: Balance<SUI>,
    }

    /// Middle hop - propagates tainted recipient
    public fun process_withdrawal(
        vault: &mut UserVault,
        recipient: address,
        ctx: &mut TxContext
    ) {
        admin_drain_hop_c::execute_transfer(&mut vault.balance, recipient, ctx);
    }
}
