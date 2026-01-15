/// Test cases for mutable-ref-escape rule.
/// Detects public entry functions returning &mut to internal state.
module test::mutable_ref_escape {
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::object::{Self, UID};

    /// Shared protocol pool
    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
        fee_rate: u64,
    }

    /// Admin capability
    public struct AdminCap has key, store {
        id: UID,
    }

    /// VULNERABLE: Returns &mut to shared object internal state
    // @expect: mutable-ref-escape
    public fun get_balance_mut(
        pool: &mut Pool,
    ): &mut Balance<SUI> {
        &mut pool.balance
    }

    /// VULNERABLE: Returns &mut to internal field
    // @expect: mutable-ref-escape
    public fun get_fee_rate_mut(
        pool: &mut Pool,
    ): &mut u64 {
        &mut pool.fee_rate
    }

    /// SAFE: Has role check
    public fun get_balance_admin(
        pool: &mut Pool,
        _cap: &AdminCap,
    ): &mut Balance<SUI> {
        &mut pool.balance
    }

    /// SAFE: public(package) is internal
    public(package) fun get_balance_internal(
        pool: &mut Pool,
    ): &mut Balance<SUI> {
        &mut pool.balance
    }

    // ========== IPA Tests ==========

    /// Helper that returns &mut (used by IPA tests)
    fun do_get_balance(pool: &mut Pool): &mut Balance<SUI> {
        &mut pool.balance
    }

    /// VULNERABLE: Public fun returning &mut via helper (IPA should detect)
    // @expect: mutable-ref-escape
    public fun get_balance_via_helper(pool: &mut Pool): &mut Balance<SUI> {
        do_get_balance(pool)
    }

    /// SAFE: Public fun with role calling helper (guard should propagate)
    public fun get_balance_via_guarded_helper(
        _cap: &AdminCap,
        pool: &mut Pool
    ): &mut Balance<SUI> {
        do_get_balance(pool)
    }

    /// Init
    fun init(ctx: &mut TxContext) {
        let pool = Pool {
            id: object::new(ctx),
            balance: balance::zero(),
            fee_rate: 100,
        };
        transfer::share_object(pool);

        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }
}
