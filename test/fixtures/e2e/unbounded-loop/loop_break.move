/// Test: loop/break construct (not just while)
module test::unbounded_loop_break {
    use sui::tx_context::TxContext;

    /// VULNERABLE: Tainted bound in break condition
    // @expect: unbounded-loop
    public entry fun process_loop_break(count: u64, ctx: &mut TxContext) {
        let mut i = 0;
        loop {
            if (i >= count) break;
            i = i + 1;
        };
    }

    /// VULNERABLE: Loop with tainted continue condition
    // @false-negative: unbounded-loop (loop/continue pattern not handled)
    public entry fun process_loop_continue(count: u64, ctx: &mut TxContext) {
        let mut i = 0;
        loop {
            i = i + 1;
            if (i < count) continue;
            break;
        };
    }

    /// SAFE: Loop with constant early break
    // @false-positive: unbounded-loop (early break limits iterations)
    public entry fun process_early_break(count: u64, ctx: &mut TxContext) {
        let mut i = 0;
        loop {
            if (i >= 10) break;  // Always exits by 10
            if (i >= count) break;
            i = i + 1;
        };
    }
}
