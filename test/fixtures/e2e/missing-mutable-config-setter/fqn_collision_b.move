// Test FQN collision: b::lending::Pool with NO setter (should be flagged)
module test::lending_b {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    // @expect: missing-mutable-config-setter
    public struct Pool has key {
        id: UID,
        fee_rate: u64
    }

    fun init(ctx: &mut TxContext) {
        let pool = Pool {
            id: object::new(ctx),
            fee_rate: 100,
        };
        sui::transfer::share_object(pool);
    }

    // NO setter function for fee_rate
}
