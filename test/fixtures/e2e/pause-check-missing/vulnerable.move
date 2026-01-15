/// Test cases for pause-related rules.
/// Tests pause-check-missing, admin-bypasses-pause, unprotected-pause.
module test::pause_protocol {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::object::{Self, UID};

    /// Protocol config with pause field
    public struct Config has key {
        id: UID,
        paused: bool,
        fee_rate: u64,
    }

    /// Shared pool
    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    /// Admin capability
    public struct AdminCap has key, store {
        id: UID,
    }

    // =========================================================================
    // pause-check-missing: Functions with sinks that don't check pause
    // =========================================================================

    /// VULNERABLE: Has sink but doesn't check pause
    // @expect: pause-check-missing
    public entry fun withdraw_no_pause(
        pool: &mut Pool,
        _config: &Config,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        // No pause check here!
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }

    /// SAFE: Checks pause before sink
    public entry fun withdraw_with_pause(
        pool: &mut Pool,
        config: &Config,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        assert!(!config.paused, 0);
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }

    // =========================================================================
    // admin-bypasses-pause: Admin functions that don't check pause
    // =========================================================================

    /// Not for this rule: Admin function (has role check) - see admin-bypasses-pause
    public entry fun admin_withdraw_no_pause(
        pool: &mut Pool,
        _config: &Config,
        amount: u64,
        recipient: address,
        _cap: &AdminCap,
        ctx: &mut TxContext
    ) {
        // Admin can bypass pause (centralization risk)
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }

    /// SAFE: Admin function that checks pause
    public entry fun admin_withdraw_with_pause(
        pool: &mut Pool,
        config: &Config,
        amount: u64,
        recipient: address,
        _cap: &AdminCap,
        ctx: &mut TxContext
    ) {
        assert!(!config.paused, 0);
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }

    // =========================================================================
    // unprotected-pause: Pause control without authorization
    // =========================================================================

    /// Not for this rule: pause control function (unprotected-pause)
    public fun pause_protocol(config: &mut Config) {
        config.paused = true;
    }

    /// Not for this rule: pause control function (unprotected-pause)
    public fun unpause_protocol(config: &mut Config) {
        config.paused = false;
    }

    /// SAFE: Pause control with admin capability
    public fun pause_admin(config: &mut Config, _cap: &AdminCap) {
        config.paused = true;
    }

    /// SAFE: Unpause with admin capability
    public fun unpause_admin(config: &mut Config, _cap: &AdminCap) {
        config.paused = false;
    }

    // =========================================================================
    // IPA tests: Entry → helper patterns for pause checking
    // =========================================================================

    /// VULNERABLE: Entry calls helper that has sink but neither checks pause
    // @expect: pause-check-missing
    public entry fun ipa_withdraw_no_pause(
        pool: &mut Pool,
        _config: &Config,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        do_withdraw(pool, amount, recipient, ctx);
    }

    /// Helper with sink (no pause check)
    fun do_withdraw(pool: &mut Pool, amount: u64, recipient: address, ctx: &mut TxContext) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }

    /// SAFE: Entry calls helper that checks pause (guard propagates)
    public entry fun ipa_withdraw_with_pause(
        pool: &mut Pool,
        config: &Config,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        do_withdraw_checked(pool, config, amount, recipient, ctx);
    }

    /// Helper that checks pause before sink
    fun do_withdraw_checked(
        pool: &mut Pool,
        config: &Config,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        assert!(!config.paused, 0);
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }

    fun init(ctx: &mut TxContext) {
        let config = Config {
            id: object::new(ctx),
            paused: false,
            fee_rate: 100,
        };
        transfer::share_object(config);

        let pool = Pool {
            id: object::new(ctx),
            balance: balance::zero(),
        };
        transfer::share_object(pool);

        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }
}
