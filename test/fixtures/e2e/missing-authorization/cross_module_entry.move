/// Entry points that call helpers in other modules.
/// Tests cross-module guard propagation.
module test::entry {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    use test::guarded_helper;
    use test::unguarded_helper::{Self, Pool};

    /// VULNERABLE: Entry calls unguarded helper - should be flagged
    /// Passes tainted recipient to callee with sink
    // @expect:missing-authorization
    public entry fun withdraw_via_unguarded(
        pool: &mut Pool,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        unguarded_helper::do_withdraw(pool, amount, recipient, ctx);
    }

    /// SAFE: Entry calls guarded helper (has sender equality check) - guard propagates
    public entry fun withdraw_via_guarded(
        pool: &mut Pool,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        guarded_helper::do_withdraw_checked(pool, amount, recipient, ctx);
    }

    /// SAFE: Entry itself has role check
    public entry fun withdraw_with_role(
        pool: &mut Pool,
        amount: u64,
        recipient: address,
        _cap: &guarded_helper::AdminCap,
        ctx: &mut TxContext
    ) {
        unguarded_helper::do_withdraw(pool, amount, recipient, ctx);
    }
}
