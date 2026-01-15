// Test case: Pool.fee_rate has privileged setter gated by AdminCap
// Should NOT trigger missing-mutable-config-setter rule
module test::pool {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

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

    // Privileged setter - requires AdminCap
    public fun set_fee_rate(_: &AdminCap, pool: &mut Pool, new_rate: u64) {
        pool.fee_rate = new_rate;
    }
}
