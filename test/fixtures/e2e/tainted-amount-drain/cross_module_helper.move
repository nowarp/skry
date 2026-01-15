/// Helper module for cross-module tainted amount tests.
module test::amount_helper {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};

    /// Shared pool
    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    /// Admin capability
    public struct AdminCap has key, store {
        id: UID,
    }

    /// Unguarded take - callers without auth should be flagged
    // @false-negative: tainted-amount-drain
    public fun do_take(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// Guarded take - has role check, guard propagates to callers
    public fun do_take_with_cap(
        pool: &mut Pool,
        amount: u64,
        _cap: &AdminCap,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    fun init(ctx: &mut TxContext) {
        let pool = Pool {
            id: object::new(ctx),
            balance: balance::zero(),
        };
        transfer::share_object(pool);

        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }
}
