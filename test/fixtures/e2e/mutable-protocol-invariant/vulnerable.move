// Test case: Protocol invariant field modified outside init
// Should trigger mutable-protocol-invariant rule
module test::pool_invariant {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    public struct Pool has key {
        id: UID,
        decimals: u8,  // Protocol invariant - users expect this never changes
        balance: u64,
    }

    public struct AdminCap has key, store { id: UID }

    fun init(ctx: &mut TxContext) {
        let pool = Pool {
            id: object::new(ctx),
            decimals: 9,  // Set once in init
            balance: 0,
        };
        sui::transfer::share_object(pool);

        let admin = AdminCap { id: object::new(ctx) };
        sui::transfer::transfer(admin, sui::tx_context::sender(ctx));
    }

    // @expect: mutable-protocol-invariant
    public fun set_decimals(_: &AdminCap, pool: &mut Pool, new_decimals: u8) {
        pool.decimals = new_decimals;  // Modifying protocol invariant!
    }

    // Safe: modifying balance is fine
    public fun deposit(_: &AdminCap, pool: &mut Pool, amount: u64) {
        pool.balance = pool.balance + amount;
    }
}
