// Test FQN collision: a::dex::Pool with sender-checked setter (should NOT be flagged)
module test::dex_a {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};

    public struct Pool has key {
        id: UID,
        admin: address,
        fee_rate: u64
    }

    // Setter with sender check (privileged)
    public fun set_fee(pool: &mut Pool, rate: u64, ctx: &TxContext) {
        assert!(pool.admin == tx_context::sender(ctx), 0);
        pool.fee_rate = rate;
    }
}
