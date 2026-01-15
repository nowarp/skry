/// Vulnerable fee pool - anyone can modify protocol fee rate.
/// This should trigger the unauth-sensitive-setter rule.
module vulnerable_fee_pool::pool {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::TxContext;

    /// Shared pool that holds protocol configuration.
    struct Pool has key {
        id: UID,
        /// Fee rate in basis points (100 = 1%)
        fee_rate: u64,
        /// Total liquidity in the pool
        total_liquidity: u64,
    }

    /// Create and share the pool.
    fun init(ctx: &mut TxContext) {
        let pool = Pool {
            id: object::new(ctx),
            fee_rate: 30, // 0.3% default fee
            total_liquidity: 0,
        };
        transfer::share_object(pool);
    }

    /// VULNERABLE: Anyone can set the fee rate!
    /// No admin check, no capability required.
    public entry fun set_fee_rate(pool: &mut Pool, new_rate: u64) {
        pool.fee_rate = new_rate;
    }

    /// VULNERABLE: Anyone can drain liquidity!
    public entry fun set_liquidity(pool: &mut Pool, amount: u64) {
        pool.total_liquidity = amount;
    }

    /// Safe getter - read-only access.
    public fun get_fee_rate(pool: &Pool): u64 {
        pool.fee_rate
    }
}
