/// Test cases for tainted-amount-drain rule.
/// User-controlled amount in coin::take enables drain.
module test::tainted_amount {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};

    /// Shared pool
    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    /// Admin capability
    public struct AdminCap has key, store {
        id: UID,
    }

    /// VULNERABLE: Direct tainted amount drain
    /// User controls amount parameter in coin::take
    // @expect: tainted-amount-drain
    public entry fun drain_direct(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// VULNERABLE: IPA - entry calls helper with tainted amount
    // @expect: tainted-amount-drain
    public entry fun drain_via_helper(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        do_take(pool, amount, ctx);
    }

    /// Helper that performs the take
    fun do_take(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// SAFE: Has role check
    public entry fun drain_with_role(
        pool: &mut Pool,
        amount: u64,
        _cap: &AdminCap,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// SAFE: IPA - callee has role check (guard propagates)
    public entry fun drain_via_guarded_helper(
        pool: &mut Pool,
        amount: u64,
        cap: &AdminCap,
        ctx: &mut TxContext
    ) {
        do_take_guarded(pool, amount, cap, ctx);
    }

    /// Helper with role check
    fun do_take_guarded(
        pool: &mut Pool,
        amount: u64,
        _cap: &AdminCap,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    fun init(ctx: &mut TxContext) {
        let pool = Pool {
            id: object::new(ctx),
            balance: balance::zero(),
        };
        transfer::share_object(pool);

        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }
}
