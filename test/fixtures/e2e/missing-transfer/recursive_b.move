/// Recursive module test B
/// Tests cycle handling in call graph: A -> B -> A
module test::missing_transfer_recursive_b {
    use sui::tx_context::TxContext;
    use test::missing_transfer_recursive_a::{Self, Pool};

    // =========================================================================
    // Middle hop that calls back to A
    // =========================================================================

    /// Process in B - calls back to A's helper
    /// Also vulnerable since it's public and transitively extracts
    // @expect: missing-transfer
    public fun process(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        // Calls back to module A - creates cycle
        missing_transfer_recursive_a::extract_helper(pool, amount, ctx);
    }

    /// Safe variant - calls A's safe helper
    public fun process_safe(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        missing_transfer_recursive_a::extract_helper_safe(pool, amount, ctx);
    }
}
