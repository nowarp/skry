/// Incentive module that delegates to wrapper - simulates Navi's incentive_v3 pattern
/// Entry functions call base functions which call the pause wrapper.
/// The pause check should propagate transitively via call graph.

module test::wrapper_incentive {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::object::{Self, UID};
    use test::wrapper_storage::{Self, Config};

    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    /// Base function calls wrapper - should inherit pause protection
    fun base_deposit(config: &Config, pool: &mut Pool, coin: Coin<SUI>) {
        wrapper_storage::when_not_paused(config);
        let bal = coin::into_balance(coin);
        balance::join(&mut pool.balance, bal);
    }

    /// Entry function calls base which calls wrapper - pause check propagates transitively
    public entry fun entry_deposit(
        config: &Config,
        pool: &mut Pool,
        coin: Coin<SUI>,
        _ctx: &mut TxContext
    ) {
        base_deposit(config, pool, coin);
    }

    /// Base function calls wrapper - should inherit pause protection
    fun base_withdraw(config: &Config, pool: &mut Pool, amount: u64, ctx: &mut TxContext): Coin<SUI> {
        wrapper_storage::when_not_paused(config);
        let bal = balance::split(&mut pool.balance, amount);
        coin::from_balance(bal, ctx)
    }

    /// Entry calls base which calls wrapper - pause check propagates transitively
    public entry fun entry_withdraw(
        config: &Config,
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coin = base_withdraw(config, pool, amount, ctx);
        transfer::public_transfer(coin, tx_context::sender(ctx));
    }

    fun init(ctx: &mut TxContext) {
        let pool = Pool {
            id: object::new(ctx),
            balance: balance::zero(),
        };
        transfer::share_object(pool);
    }
}
