// Test case: Pool.fee_rate is mutable config field but has NO setter
// Should trigger missing-mutable-config-setter rule
module test::pool_no_setter {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    // @expect: missing-mutable-config-setter
    public struct Pool has key {
        id: UID,
        fee_rate: u64,
    }

    public struct AdminCap has key, store { id: UID }

    fun init(ctx: &mut TxContext) {
        let pool = Pool {
            id: object::new(ctx),
            fee_rate: 100,
        };
        sui::transfer::share_object(pool);

        let admin = AdminCap { id: object::new(ctx) };
        sui::transfer::transfer(admin, sui::tx_context::sender(ctx));
    }

    // No setter function for fee_rate - this is the problem!
}
