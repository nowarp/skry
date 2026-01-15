/// Recursive module test A
/// Tests cycle handling in call graph: A -> B -> A
module test::missing_transfer_recursive_a {
    use sui::coin::{Self, Coin};
    use sui::balance::Balance;
    use sui::sui::SUI;
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};
    use test::missing_transfer_recursive_b;

    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    // =========================================================================
    // VULNERABLE: Entry calls B, B calls back to A's helper which extracts
    // Cycle: entry_a -> process_b -> helper_a (extracts)
    // =========================================================================

    /// Entry in A - calls B which calls back to A's helper
    // @expect: missing-transfer
    public entry fun withdraw_via_cycle(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        missing_transfer_recursive_b::process(pool, amount, ctx);
    }

    /// Helper in A that actually extracts - called from B
    /// Also vulnerable independently since it's public
    // @expect: missing-transfer
    public fun extract_helper(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        // No transfer - leaked
    }

    // =========================================================================
    // SAFE: Same cycle pattern but with transfer
    // =========================================================================

    public entry fun withdraw_via_cycle_safe(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        missing_transfer_recursive_b::process_safe(pool, amount, ctx);
    }

    public fun extract_helper_safe(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        sui::transfer::public_transfer(coins, sui::tx_context::sender(ctx));
    }
}
