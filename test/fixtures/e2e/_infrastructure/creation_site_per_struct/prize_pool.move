/// Test case for per-struct creation site tracking.
/// Bug: When init() creates multiple structs with different transfer patterns,
/// each struct should have its own correct transfer pattern, not mixed.
///
/// Pattern from real-world project:
/// - PrizePoolCap: transferred to sender (admin cap, should be privileged)
/// - PrizePool: shared (protocol pool, NOT privileged)
///
/// Bug behavior: PrizePoolCap gets marked as "shared" because
/// detect_transfer_patterns() works at function level, not per-struct.
module test::prize_pool {
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use sui::bag::{Self, Bag};

    /// Capability for authorized PrizePool operations.
    /// SHOULD BE: privileged (transferred to sender in init)
    /// BUG: Gets marked as "shared" because init() also calls share_object
    public struct PrizePoolCap has key, store {
        id: UID,
    }

    /// Shared object storing lottery configuration and state.
    /// Correctly shared - this is intentional.
    public struct PrizePool has key {
        id: UID,
        price_per_ticket: u64,
        lp_fee_bps: u64,
        protocol_fee_bps: u64,
        referrer_fee_bps: u64,
        reserves: Bag,
    }

    fun init(ctx: &mut TxContext) {
        let authority = tx_context::sender(ctx);

        // Create and TRANSFER the cap to sender
        let authority_cap = PrizePoolCap {
            id: object::new(ctx),
        };

        // Create and SHARE the pool
        let prize_pool = PrizePool {
            id: object::new(ctx),
            price_per_ticket: 0,
            lp_fee_bps: 2500,
            protocol_fee_bps: 500,
            referrer_fee_bps: 1000,
            reserves: bag::new(ctx),
        };

        // The cap is TRANSFERRED to sender - it's an admin capability
        transfer::transfer(authority_cap, authority);

        // The pool is SHARED - it's protocol state
        transfer::share_object(prize_pool);
    }

    /// Admin function protected by PrizePoolCap.
    /// If PrizePoolCap is correctly detected as privileged (transferred to sender),
    /// this function should NOT be flagged for missing authorization.
    public entry fun set_price(
        _cap: &PrizePoolCap,
        pool: &mut PrizePool,
        new_price: u64,
    ) {
        pool.price_per_ticket = new_price;
    }

    /// VULNERABLE: Same operation without cap - should be flagged
    public entry fun set_price_unsafe(
        pool: &mut PrizePool,
        new_price: u64,
    ) {
        pool.price_per_ticket = new_price;
    }
}
