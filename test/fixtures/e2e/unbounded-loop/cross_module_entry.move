/// Cross-module test - entry module
module test::unbounded_loop_entry {
    use sui::tx_context::TxContext;
    use test::unbounded_loop_helper;

    /// VULNERABLE: Passes tainted count to helper in another module
    // @expect: unbounded-loop
    public entry fun process_cross_module(count: u64, ctx: &mut TxContext) {
        unbounded_loop_helper::do_loop(count);
    }

    /// SAFE: Validates before cross-module call
    public entry fun process_cross_module_safe(count: u64, ctx: &mut TxContext) {
        assert!(count <= 100, 0);
        unbounded_loop_helper::do_loop(count);
    }
}
