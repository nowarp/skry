/// FP: Deferred initialization pattern
/// create_lst creates AdminCap outside of init() - legitimate one-time setup
/// Pattern from suilend liquid-staking
module test::deferred_init {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    public struct AdminCap<phantom P> has key { id: UID }
    public struct LiquidStakingInfo<phantom P> has key { id: UID }
    public struct DEFERRED_INIT has drop {}

    fun init(_otw: DEFERRED_INIT, _ctx: &mut TxContext) {
        // Package setup only, no AdminCap creation
    }

    /// SAFE: Factory pattern - creates LiquidStakingInfo + AdminCap together
    public fun create_lst<P: drop>(ctx: &mut TxContext): (AdminCap<P>, LiquidStakingInfo<P>) {
        let admin = AdminCap<P> { id: object::new(ctx) };
        let info = LiquidStakingInfo<P> { id: object::new(ctx) };
        (admin, info)
    }
}
