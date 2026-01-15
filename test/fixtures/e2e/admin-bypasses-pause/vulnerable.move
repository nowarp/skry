/// Test cases for admin-bypasses-pause rule.
/// Admin-gated functions that don't check pause (centralization risk).
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
    // VULNERABLE: Admin functions that bypass pause check
    // =========================================================================

    /// VULNERABLE: Admin function with sink doesn't check pause
    // @expect: admin-bypasses-pause
    public entry fun admin_withdraw_no_pause(
        pool: &mut Pool,
        _config: &Config,
        amount: u64,
        recipient: address,
        _cap: &AdminCap,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }

    // =========================================================================
    // IPA: Entry → helper patterns (single module)
    // =========================================================================

    /// VULNERABLE (IPA): Admin entry calls helper with sink, neither checks pause
    // @expect: admin-bypasses-pause
    public entry fun ipa_admin_no_pause(
        pool: &mut Pool,
        _config: &Config,
        amount: u64,
        recipient: address,
        _cap: &AdminCap,
        ctx: &mut TxContext
    ) {
        do_withdraw(pool, amount, recipient, ctx);
    }

    /// Helper with sink (no pause check)
    fun do_withdraw(pool: &mut Pool, amount: u64, recipient: address, ctx: &mut TxContext) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }

    /// Safe (IPA): Admin entry calls helper that checks pause - should be safe
    public entry fun ipa_admin_with_pause(
        pool: &mut Pool,
        config: &Config,
        amount: u64,
        recipient: address,
        _cap: &AdminCap,
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

    // =========================================================================
    // SAFE: Admin functions that check pause
    // =========================================================================

    /// SAFE: Admin function checks pause before sink
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
    // NOT APPLICABLE: Non-admin functions (no centralization risk here)
    // =========================================================================

    /// Not applicable: No admin cap, so not a centralization risk
    public entry fun user_withdraw_no_pause(
        pool: &mut Pool,
        _config: &Config,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
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
