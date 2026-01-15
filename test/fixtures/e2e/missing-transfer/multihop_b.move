/// Multihop test - B calls C
module test::missing_transfer_hop_b {
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};
    use test::missing_transfer_hop_c;

    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    /// Middle hop - VULNERABLE: calls module C that extracts without transfer
    // @expect: missing-transfer
    public fun process_withdrawal(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        missing_transfer_hop_c::execute_extraction(&mut pool.balance, amount, ctx);
    }
}
