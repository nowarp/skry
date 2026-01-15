/// Cross-module test: entry point calling unvalidated helper in module_b
module test::cross_module_a {
    use sui::tx_context::TxContext;
    use sui::balance::Balance;
    use test::cross_module_b;

    /// VULNERABLE: Calls unvalidated generic function in module_b
    // @expect: generic-type-mismatch
    public fun withdraw_cross_module<T>(pool: &mut cross_module_b::Pool, balance: &mut Balance<T>, amount: u64, ctx: &mut TxContext) {
        cross_module_b::extract_coin<T>(pool, balance, amount, ctx);
    }

    /// SAFE: Calls validated generic function in module_b
    public fun withdraw_cross_module_safe<T>(pool: &mut cross_module_b::Pool, balance: &mut Balance<T>, expected_type: std::string::String, amount: u64, ctx: &mut TxContext) {
        cross_module_b::extract_coin_validated<T>(pool, balance, expected_type, amount, ctx);
    }
}
