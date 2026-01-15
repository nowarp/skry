/// Helper module WITHOUT authorization checks.
/// Callers should be flagged if they call these without their own auth.
module test::unguarded_helper {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    /// Shared pool holding protocol funds
    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    /// Unguarded withdraw - NO auth check
    /// Has actual sink: transfer::public_transfer to tainted recipient
    public fun do_withdraw(
        pool: &mut Pool,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        // No sender check, no role check
        // Extract from shared pool and send to user-controlled recipient
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }

    /// Another unguarded helper for state writes
    public fun set_value(
        pool: &mut Pool,
        value: u64,
    ) {
        // No auth - would be tainted state write if value came from param
    }

    /// Public accessor for pool balance - needed for cross-module access
    public fun balance_mut(pool: &mut Pool): &mut Balance<SUI> {
        &mut pool.balance
    }

    /// Init creates shared pool - makes Pool a shared object type
    fun init(ctx: &mut TxContext) {
        let pool = Pool {
            id: object::new(ctx),
            balance: balance::zero(),
        };
        transfer::share_object(pool);
    }
}
