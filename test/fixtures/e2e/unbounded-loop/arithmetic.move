/// Test: arithmetic on tainted values
module test::unbounded_loop_arith {
    use sui::tx_context::TxContext;

    /// VULNERABLE: Multiplication still tainted
    // @expect: unbounded-loop
    public entry fun process_multiply(count: u64, ctx: &mut TxContext) {
        let mut i = 0;
        while (i < count * 2) {
            i = i + 1;
        };
    }

    /// VULNERABLE: Addition still tainted
    // @expect: unbounded-loop
    public entry fun process_add(count: u64, offset: u64, ctx: &mut TxContext) {
        let mut i = 0;
        while (i < count + offset) {
            i = i + 1;
        };
    }

    /// VULNERABLE: Division still tainted (attacker controls numerator)
    // @expect: unbounded-loop
    public entry fun process_divide(count: u64, ctx: &mut TxContext) {
        let mut i = 0;
        while (i < count / 2) {
            i = i + 1;
        };
    }

    /// VULNERABLE: Complex expression
    // @expect: unbounded-loop
    public entry fun process_complex(a: u64, b: u64, ctx: &mut TxContext) {
        let bound = (a + b) * 2;
        let mut i = 0;
        while (i < bound) {
            i = i + 1;
        };
    }

    /// SAFE: Tainted value bounded by constant min
    // @false-positive: unbounded-loop (if-else sanitization not detected)
    public entry fun process_bounded_min(count: u64, ctx: &mut TxContext) {
        let bound = if (count < 100) { count } else { 100 };
        let mut i = 0;
        while (i < bound) {
            i = i + 1;
        };
    }
}
