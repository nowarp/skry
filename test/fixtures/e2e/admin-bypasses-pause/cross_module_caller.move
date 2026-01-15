module test::pause_caller {
    use sui::balance::Balance;
    use sui::sui::SUI;
    use sui::tx_context::TxContext;
    use sui::object::UID;
    use test::pause_helper;

    public struct Config has key {
        id: UID,
        paused: bool,
    }

    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    public struct AdminCap has key, store {
        id: UID,
    }

    // =========================================================================
    // Cross-module IPA tests
    // =========================================================================

    /// VULNERABLE (cross-module): Admin calls helper in another module, no pause check
    // @expect: admin-bypasses-pause
    public entry fun xmod_admin_no_pause(
        pool: &mut Pool,
        _config: &Config,
        amount: u64,
        recipient: address,
        _cap: &AdminCap,
        ctx: &mut TxContext
    ) {
        pause_helper::withdraw_no_check(&mut pool.balance, amount, recipient, ctx);
    }

    /// Safe (cross-module): Admin calls helper that checks pause - should be safe
    public entry fun xmod_admin_with_pause(
        pool: &mut Pool,
        config: &Config,
        amount: u64,
        recipient: address,
        _cap: &AdminCap,
        ctx: &mut TxContext
    ) {
        pause_helper::withdraw_with_check(&mut pool.balance, config.paused, amount, recipient, ctx);
    }
}
