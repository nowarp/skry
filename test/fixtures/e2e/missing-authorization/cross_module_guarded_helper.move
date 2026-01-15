/// Helper module with authorization checks.
/// Guards should propagate to callers.
module test::guarded_helper {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};

    use test::unguarded_helper::{Self as unguarded_helper, Pool};

    /// Admin capability for role-based auth
    public struct AdminCap has key, store {
        id: UID,
    }

    /// Helper with sender check - guard should propagate to callers
    /// Has actual sink BUT protected by sender check
    public fun do_withdraw_checked(
        pool: &mut Pool,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        // This sender check should propagate to callers
        assert!(tx_context::sender(ctx) == @0x1, 0);
        // Has sink, but protected by sender check above
        let coins = coin::take(unguarded_helper::balance_mut(pool), amount, ctx);
        transfer::public_transfer(coins, recipient);
    }

    /// Helper with role check - guard should propagate
    public fun do_withdraw_with_cap(
        pool: &mut Pool,
        amount: u64,
        recipient: address,
        _cap: &AdminCap,
        ctx: &mut TxContext
    ) {
        // Role check via AdminCap param - guard propagates
        let coins = coin::take(unguarded_helper::balance_mut(pool), amount, ctx);
        transfer::public_transfer(coins, recipient);
    }

    /// Create admin cap (init only)
    fun init(ctx: &mut TxContext) {
        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }
}
