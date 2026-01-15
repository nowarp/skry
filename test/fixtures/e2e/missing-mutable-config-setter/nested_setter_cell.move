// Test case: nested field setter via method call pattern
// Should NOT trigger missing-mutable-config-setter rule
module test::nested_pool {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    public struct Cell<T: store> has store { value: T }

    public struct Pool has key {
        id: UID,
        fee_config: Cell<u64>,
    }

    public struct AdminCap has key, store { id: UID }

    fun init(ctx: &mut TxContext) {
        let pool = Pool {
            id: object::new(ctx),
            fee_config: Cell { value: 100 },
        };
        sui::transfer::share_object(pool);

        let admin = AdminCap { id: object::new(ctx) };
        sui::transfer::transfer(admin, sui::tx_context::sender(ctx));
    }

    // Privileged setter using nested method call - should be recognized
    public fun update_fee(_: &AdminCap, pool: &mut Pool, v: u64) {
        pool.fee_config.set(v);  // SHOULD recognize this as setter
    }

    public fun set<T: store + drop>(c: &mut Cell<T>, v: T) {
        c.value = v;
    }
}
