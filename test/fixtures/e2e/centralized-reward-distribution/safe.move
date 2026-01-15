/// Safe cases for centralized-reward-distribution rule.
/// These should NOT trigger the rule.
// @inject: ProjectCategory("gaming", 0.9)
module test::centralized_reward_safe {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use sui::transfer;

    public struct GamePool has key {
        id: UID,
        reward_pool: Balance<SUI>,
        admin: address,
    }

    /// Init shares the pool - marks GamePool as shared object
    fun init_module(ctx: &mut TxContext) {
        let pool = GamePool {
            id: object::new(ctx),
            reward_pool: balance::zero(),
            admin: tx_context::sender(ctx),
        };
        transfer::share_object(pool);
    }

    fun assert_admin(pool: &GamePool, ctx: &TxContext) {
        assert!(tx_context::sender(ctx) == pool.admin, 0);
    }

    /// SAFE: User withdraws their own stake (no address param)
    /// Not admin picking winner - user self-serve
    public fun user_withdraw_stake(
        pool: &mut GamePool,
        amount: u64,
        ctx: &mut TxContext
    ): Coin<SUI> {
        // User withdraws to themselves
        let stake = balance::split(&mut pool.reward_pool, amount);
        coin::from_balance(stake, ctx)
    }

    /// SAFE: Admin emergency drain (no address param = drains to admin)
    /// Different pattern - admin drain, not reward distribution
    public fun admin_emergency_withdraw(
        pool: &mut GamePool,
        ctx: &mut TxContext
    ): Coin<SUI> {
        assert_admin(pool, ctx);
        let amount = balance::value(&pool.reward_pool);
        let funds = balance::split(&mut pool.reward_pool, amount);
        coin::from_balance(funds, ctx)
    }

    /// SAFE: Transfer to sender (admin gets their own funds)
    public entry fun admin_collect_fees(
        pool: &mut GamePool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        assert_admin(pool, ctx);
        let fees = coin::take(&mut pool.reward_pool, amount, ctx);
        transfer::public_transfer(fees, tx_context::sender(ctx));
    }

    /// SAFE: No auth check - public function (different security issue)
    /// This is a different vulnerability (missing auth), not centralized reward
    public fun public_withdraw(
        pool: &mut GamePool,
        recipient: address,
        amount: u64,
        ctx: &mut TxContext
    ): Coin<SUI> {
        // No auth - this is a different bug (missing auth)
        let funds = balance::split(&mut pool.reward_pool, amount);
        coin::from_balance(funds, ctx)
    }

}
