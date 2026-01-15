/// Entry points for cross-module tainted amount tests.
module test::amount_entry {
    use sui::tx_context::TxContext;

    use test::amount_helper::{Self, Pool, AdminCap};

    /// VULNERABLE: Cross-module tainted amount
    /// Entry passes user-controlled amount to helper in another module
    // @expect: tainted-amount-drain
    public entry fun drain_cross_module(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        amount_helper::do_take(pool, amount, ctx);
    }

    /// SAFE: Cross-module with role check in callee
    public entry fun drain_cross_module_guarded(
        pool: &mut Pool,
        amount: u64,
        cap: &AdminCap,
        ctx: &mut TxContext
    ) {
        amount_helper::do_take_with_cap(pool, amount, cap, ctx);
    }
}
