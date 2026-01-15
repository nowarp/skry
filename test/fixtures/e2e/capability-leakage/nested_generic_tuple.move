/// Test: Nested generic tuple return types
/// Ensures returns-privileged-type? parser handles complex generics
module test::nested_generic_tuple {
    use sui::object::{Self, UID};
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;
    use sui::tx_context::TxContext;

    /// Privileged admin capability
    public struct AdminCap has key, store {
        id: UID,
    }

    /// VULNERABLE: Returns tuple with nested generic and privileged cap
    /// Parser must correctly identify AdminCap in "(Coin<Balance<SUI>>, AdminCap)"
    // @expect: capability-leakage
    public fun create_with_nested_generic(
        ctx: &mut TxContext
    ): (Coin<SUI>, AdminCap) {
        let cap = AdminCap { id: object::new(ctx) };
        let coin = coin::zero<SUI>(ctx);
        (coin, cap)
    }

    /// VULNERABLE: Triple-nested generic with cap
    // @expect: capability-leakage
    public fun deeply_nested_generic(
        ctx: &mut TxContext
    ): (Balance<SUI>, AdminCap) {
        let cap = AdminCap { id: object::new(ctx) };
        let bal = balance::zero<SUI>();
        (bal, cap)
    }

    /// SAFE: Returns nested generic but NO privileged type
    public fun nested_no_cap(ctx: &mut TxContext): (Coin<SUI>, u64) {
        let coin = coin::zero<SUI>(ctx);
        (coin, 0)
    }
}
