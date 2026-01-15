/// Test cases for orphan-txcontext rule.
/// public(package) function with TxContext is not called
module test::orphan_txcontext {
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    public struct Pool has key {
        id: UID,
        balance: u64,
    }

    /// ORPHAN: public(package) with TxContext, never called
    // @expect: orphan-txcontext
    public(package) fun unused_helper(pool: &mut Pool, ctx: &mut TxContext) {
        pool.balance = pool.balance + 1;
    }

    /// ORPHAN: Another unused public(package) function
    // @expect: orphan-txcontext
    public(package) fun another_unused(amount: u64, ctx: &mut TxContext): u64 {
        amount * 2
    }

    /// Called but TxContext NOT used
    // @expect: orphan-txcontext
    public(package) fun used_helper(pool: &mut Pool, ctx: &mut TxContext) {
        pool.balance = pool.balance + 10;
    }

    public entry fun withdraw(pool: &mut Pool, ctx: &mut TxContext) {
        used_helper(pool, ctx);
    }

    /// Called but TxContext NOT used
    // @expect: orphan-txcontext
    public(package) fun another_used(pool: &mut Pool, ctx: &mut TxContext) {
        pool.balance = pool.balance - 5;
    }

    public entry fun deposit(pool: &mut Pool, ctx: &mut TxContext) {
        another_used(pool, ctx);
    }
}
