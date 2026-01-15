/// PTB helper pattern test - function returns caller's own Balance
/// Uses tx_context::sender to identify user (implicit ownership), should NOT be flagged

module test::ptb_helper {
    use sui::tx_context::{Self, TxContext};
    use sui::balance::{Self, Balance};
    use sui::object::{Self, UID};
    use sui::table::{Self, Table};
    use sui::transfer;
    use sui::sui::SUI;

    /// Shared pool object (shared in init)
    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
        user_balances: Table<address, u64>,
    }

    /// TRUE POSITIVE: Returns balance from shared pool without any sender involvement
    // @expect: returns-coin-without-auth
    public fun withdraw_no_auth(pool: &mut Pool, amount: u64): Balance<SUI> {
        balance::split(&mut pool.balance, amount)
    }

    /// SAFE: PTB helper - uses sender to call helper (Navi pattern)
    /// This is the Navi pattern: sender is passed to callee for validation
    /// No assertion on sender in this function - callee validates position
    /// Fixed: calls-sender? filter now excludes PTB helpers
    public fun withdraw_for_sender(
        pool: &mut Pool,
        amount: u64,
        ctx: &TxContext
    ): Balance<SUI> {
        let user = tx_context::sender(ctx);
        // Sender is used to update user state (like Navi's update_reward_all)
        update_user_state(pool, user);
        // Callee does the actual withdrawal with validation
        do_withdraw(pool, amount)
    }

    /// Helper that updates user state (simulates Navi's update_reward_all)
    fun update_user_state(pool: &mut Pool, user: address) {
        // Just uses sender for lookup, no assertion
        if (table::contains(&pool.user_balances, user)) {
            let _balance = table::borrow(&pool.user_balances, user);
        };
    }

    /// Helper that performs withdrawal (simulates lending::withdraw_coin)
    fun do_withdraw(pool: &mut Pool, amount: u64): Balance<SUI> {
        balance::split(&mut pool.balance, amount)
    }

    fun init(ctx: &mut TxContext) {
        let pool = Pool {
            id: object::new(ctx),
            balance: balance::zero(),
            user_balances: table::new(ctx),
        };
        transfer::share_object(pool);
    }
}
