/// Test: taint through return values
module test::unbounded_loop_return {
    use sui::tx_context::TxContext;

    /// Helper that returns tainted value
    fun get_count(x: u64): u64 { x }

    /// Helper with computation
    fun double_count(x: u64): u64 { x * 2 }

    /// VULNERABLE: Taint flows through return value
    // @expect: unbounded-loop
    public entry fun process_via_return(count: u64, ctx: &mut TxContext) {
        let bound = get_count(count);
        let mut i = 0;
        while (i < bound) {
            i = i + 1;
        };
    }

    /// VULNERABLE: Taint through computation return
    // @expect: unbounded-loop
    public entry fun process_via_computed_return(count: u64, ctx: &mut TxContext) {
        let bound = double_count(count);
        let mut i = 0;
        while (i < bound) {
            i = i + 1;
        };
    }

    /// SAFE: Return from sanitizing function
    fun sanitize_count(x: u64): u64 {
        if (x > 100) { 100 } else { x }
    }

    // @false-positive: unbounded-loop (return sanitization not detected)
    public entry fun process_sanitized_return(count: u64, ctx: &mut TxContext) {
        let bound = sanitize_count(count);
        let mut i = 0;
        while (i < bound) {
            i = i + 1;
        };
    }
}
