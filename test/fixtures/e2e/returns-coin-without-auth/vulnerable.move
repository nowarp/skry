/// Test cases for returns-coin-without-auth rule.
/// Detects public functions returning Coin/Balance without authorization.
module test::returns_coin {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::object::{Self, UID};

    /// Protocol treasury
    public struct Treasury has key {
        id: UID,
        balance: Balance<SUI>,
    }

    /// Admin capability
    public struct AdminCap has key, store {
        id: UID,
    }

    /// VULNERABLE: Returns Coin without auth check
    // @expect: returns-coin-without-auth
    public fun get_funds(
        treasury: &mut Treasury,
        amount: u64,
        ctx: &mut TxContext
    ): Coin<SUI> {
        coin::take(&mut treasury.balance, amount, ctx)
    }

    /// Returns reference to Balance
    public fun get_balance(
        treasury: &mut Treasury,
    ): &Balance<SUI> {
        &treasury.balance
    }

    /// SAFE: Has role check
    public fun get_funds_admin(
        treasury: &mut Treasury,
        amount: u64,
        _cap: &AdminCap,
        ctx: &mut TxContext
    ): Coin<SUI> {
        coin::take(&mut treasury.balance, amount, ctx)
    }

    /// SAFE: Has sender check
    public fun get_funds_with_sender(
        treasury: &mut Treasury,
        amount: u64,
        ctx: &mut TxContext
    ): Coin<SUI> {
        assert!(tx_context::sender(ctx) == @0x1, 0);
        coin::take(&mut treasury.balance, amount, ctx)
    }

    /// SAFE: public(package) is internal
    public(package) fun get_funds_internal(
        treasury: &mut Treasury,
        amount: u64,
        ctx: &mut TxContext
    ): Coin<SUI> {
        coin::take(&mut treasury.balance, amount, ctx)
    }

    // ========== IPA Tests ==========

    /// Helper that returns Coin (used by IPA tests)
    fun do_withdraw(treasury: &mut Treasury, amount: u64, ctx: &mut TxContext): Coin<SUI> {
        coin::take(&mut treasury.balance, amount, ctx)
    }

    /// VULNERABLE: Entry returning Coin via helper (IPA should detect)
    // @expect: returns-coin-without-auth
    public fun get_funds_via_helper(
        treasury: &mut Treasury,
        amount: u64,
        ctx: &mut TxContext
    ): Coin<SUI> {
        do_withdraw(treasury, amount, ctx)
    }

    /// SAFE: Entry with role calling helper (guard should propagate)
    public fun get_funds_via_guarded_helper(
        _cap: &AdminCap,
        treasury: &mut Treasury,
        amount: u64,
        ctx: &mut TxContext
    ): Coin<SUI> {
        do_withdraw(treasury, amount, ctx)
    }

    // ========== IPA Sender Check Tests ==========

    /// Helper that checks sender (for IPA propagation test)
    fun assert_admin(ctx: &TxContext) {
        assert!(tx_context::sender(ctx) == @0x1, 0);
    }

    /// SAFE: Calls helper with sender check (IPA should propagate HasSenderEqualityCheck)
    public fun get_funds_via_sender_helper(
        treasury: &mut Treasury,
        amount: u64,
        ctx: &mut TxContext
    ): Coin<SUI> {
        assert_admin(ctx);
        coin::take(&mut treasury.balance, amount, ctx)
    }

    // ========== Balance<T> Tests ==========

    /// Helper that returns Balance (used by IPA tests)
    fun do_get_balance(treasury: &Treasury): &Balance<SUI> {
        &treasury.balance
    }

    /// VULNERABLE: Returns Balance<T> without auth
    // @expect: returns-coin-without-auth
    public fun get_balance_value(treasury: &mut Treasury, amount: u64): Balance<SUI> {
        balance::split(&mut treasury.balance, amount)
    }

    fun init(ctx: &mut TxContext) {
        let treasury = Treasury {
            id: object::new(ctx),
            balance: balance::zero(),
        };
        transfer::share_object(treasury);

        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }
}
