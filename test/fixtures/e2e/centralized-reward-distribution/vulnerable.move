/// Test cases for centralized-reward-distribution rule.
/// Detects gaming projects where admin picks lottery/reward recipients
/// without verifiable on-chain randomness.
// @inject: ProjectCategory("gaming", 0.9)
module test::centralized_reward {
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
    fun init(ctx: &mut TxContext) {
        let pool = GamePool {
            id: object::new(ctx),
            reward_pool: balance::zero(),
            admin: tx_context::sender(ctx),
        };
        transfer::share_object(pool);
    }

    /// Helper to check admin
    fun assert_admin(pool: &GamePool, ctx: &TxContext) {
        assert!(tx_context::sender(ctx) == pool.admin, 0);
    }

    /// VULNERABLE: Admin picks winner and extracts from pool
    /// Admin can choose who gets rewards - no on-chain randomness
    // @expect: centralized-reward-distribution
    public fun distribute_reward(
        pool: &mut GamePool,
        winner: address,
        amount: u64,
        ctx: &mut TxContext
    ): Coin<SUI> {
        assert_admin(pool, ctx);
        let reward = balance::split(&mut pool.reward_pool, amount);
        coin::from_balance(reward, ctx)
    }

    /// VULNERABLE: Admin selects lottery winner
    /// Same pattern - admin-controlled winner selection
    // @expect: centralized-reward-distribution
    public fun pick_lottery_winner(
        pool: &mut GamePool,
        winner: address,
        ctx: &mut TxContext
    ): Coin<SUI> {
        assert_admin(pool, ctx);
        let amount = balance::value(&pool.reward_pool) / 10;
        let prize = balance::split(&mut pool.reward_pool, amount);
        coin::from_balance(prize, ctx)
    }

    /// VULNERABLE: Admin distributes game prizes
    /// No verifiable selection mechanism
    // @expect: centralized-reward-distribution
    public fun award_game_prize(
        pool: &mut GamePool,
        player: address,
        prize_amount: u64,
        ctx: &mut TxContext
    ): Coin<SUI> {
        assert_admin(pool, ctx);
        let prize = balance::split(&mut pool.reward_pool, prize_amount);
        coin::from_balance(prize, ctx)
    }

    /// VULNERABLE: Tournament winner selection by admin
    // @expect: centralized-reward-distribution
    public entry fun award_tournament_winner(
        pool: &mut GamePool,
        winner: address,
        ctx: &mut TxContext
    ) {
        assert_admin(pool, ctx);
        let amount = balance::value(&pool.reward_pool);
        let prize = coin::take(&mut pool.reward_pool, amount, ctx);
        transfer::public_transfer(prize, winner);
    }
}
