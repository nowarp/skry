/// Test: A->B(sanitize)->C chain - Module A (entry)
module test::sanitize_chain_a {
    use sui::tx_context::TxContext;
    use test::sanitize_chain_b;

    /// Entry that calls B which sanitizes before calling C
    /// Should NOT flag since B sanitizes the value
    // @false-positive: unbounded-loop (cross-module sanitization not tracked)
    public entry fun start_sanitized(count: u64, ctx: &mut TxContext) {
        sanitize_chain_b::validate_and_forward(count);
    }

    /// Entry that calls B which does NOT sanitize
    // @expect: unbounded-loop
    public entry fun start_unsanitized(count: u64, ctx: &mut TxContext) {
        sanitize_chain_b::forward_raw(count);
    }
}
