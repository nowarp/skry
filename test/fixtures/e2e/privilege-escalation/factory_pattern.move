/// Factory Pattern - privilege cap created when caller provides TreasuryCap
/// This is a legitimate pattern where:
/// 1. Caller must own TreasuryCap<P> (stdlib privileged capability)
/// 2. Function creates AdminCap<P> for the caller's OWN new pool
/// 3. Caps are RETURNED, not transferred to tainted recipient
///
/// Real-world example: AlphaFi liquid-staking create_lst()
// @inject: IsCapability(test::factory_pattern::TreasuryAdminCap)
// @inject: IsPrivileged(test::factory_pattern::TreasuryAdminCap)
module test::factory_pattern {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::coin::TreasuryCap;

    /// OTW for this module
    public struct FACTORY_PATTERN has drop {}

    /// Admin capability for a specific pool type P
    public struct AdminCap<phantom P> has key, store {
        id: UID,
    }

    /// Fee collection capability
    public struct CollectionFeeCap<phantom P> has key, store {
        id: UID,
    }

    /// Pool info struct
    public struct PoolInfo<phantom P> has key, store {
        id: UID,
    }

    /// Treasury struct (non-capability)
    public struct Treasury has key, store {
        id: UID,
        balance: u64,
    }

    /// TreasuryAdminCap capability for a Treasury
    public struct TreasuryAdminCap has key, store {
        id: UID,
    }

    /// Init creates AdminCap for FACTORY_PATTERN type -> makes AdminCap privileged
    /// Also creates TreasuryAdminCap -> makes it privileged
    fun init(_otw: FACTORY_PATTERN, ctx: &mut TxContext) {
        let admin = AdminCap<FACTORY_PATTERN> { id: object::new(ctx) };
        transfer::transfer(admin, tx_context::sender(ctx));
        // Create TreasuryAdminCap in init to make it privileged
        let treasury_admin = TreasuryAdminCap { id: object::new(ctx) };
        transfer::transfer(treasury_admin, tx_context::sender(ctx));
    }

    /// SAFE: Factory function - requires TreasuryCap<P> to create pool
    /// Caller must own the treasury cap for coin type P
    /// Returns AdminCap for the caller's OWN new pool
    /// (Already correctly filtered by requires_parent_cap due to TreasuryCap param)
    public fun create_pool<P: drop>(
        _treasury_cap: &TreasuryCap<P>,
        ctx: &mut TxContext
    ): (AdminCap<P>, CollectionFeeCap<P>, PoolInfo<P>) {
        (
            AdminCap<P> { id: object::new(ctx) },
            CollectionFeeCap<P> { id: object::new(ctx) },
            PoolInfo<P> { id: object::new(ctx) }
        )
    }

    /// SAFE: Factory with TreasuryCap consumed by value
    /// (Already correctly filtered by requires_parent_cap due to TreasuryCap param)
    public fun create_pool_consume<P: drop>(
        _treasury_cap: TreasuryCap<P>,
        ctx: &mut TxContext
    ): AdminCap<P> {
        AdminCap<P> { id: object::new(ctx) }
    }

    /// SAFE: Simple factory - creates Treasury + TreasuryAdminCap together
    /// This is the pattern used by create_treasury() in multisig-treasury
    /// Anyone can create a new treasury and gets admin cap for it
    public fun create_treasury(ctx: &mut TxContext): (Treasury, TreasuryAdminCap) {
        let treasury = Treasury {
            id: object::new(ctx),
            balance: 0,
        };
        let admin_cap = TreasuryAdminCap {
            id: object::new(ctx),
        };
        (treasury, admin_cap)
    }

    /// SAFE: Entry wrapper that shares treasury and transfers cap to sender
    /// This is the pattern used by create_and_share_treasury()
    // @false-positive: privilege-escalation (factory pattern - creates Treasury + cap together)
    public entry fun create_and_share_treasury(ctx: &mut TxContext) {
        let (treasury, admin_cap) = create_treasury(ctx);
        transfer::share_object(treasury);
        transfer::transfer(admin_cap, tx_context::sender(ctx));
    }
}
