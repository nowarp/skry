/// Multihop SAFE test - B calls C which transfers
module test::missing_transfer_safe_hop_b {
    use sui::balance::Balance;
    use sui::sui::SUI;
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};
    use test::missing_transfer_safe_hop_c;

    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    /// Middle hop - delegates to C which properly transfers
    public fun process_safe_withdrawal(
        pool: &mut Pool,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        missing_transfer_safe_hop_c::execute_safe_extraction(
            &mut pool.balance,
            amount,
            recipient,
            ctx
        );
    }
}
