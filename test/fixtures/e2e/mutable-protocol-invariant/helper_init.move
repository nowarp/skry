// Test case: Init calls helper that writes invariant (transitive)
// Current behavior: helper IS flagged because it directly writes invariant
// (even though it's only called from init - we don't track call context)
module test::helper_init {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    public struct Pool has key {
        id: UID,
        decimals: u8,  // Protocol invariant
        total_supply: u64,
    }

    fun init(ctx: &mut TxContext) {
        let pool = Pool {
            id: object::new(ctx),
            decimals: 0,  // placeholder
            total_supply: 0,
        };
        // Helper sets the actual value - this is fine
        set_initial_decimals(&mut pool, 18);
        sui::transfer::share_object(pool);
    }

    // @expect: mutable-protocol-invariant
    // Helper called from init - currently flagged (FP, but expected behavior)
    fun set_initial_decimals(pool: &mut Pool, d: u8) {
        pool.decimals = d;
    }

    // Safe: only reads
    public fun get_decimals(pool: &Pool): u8 {
        pool.decimals
    }
}
