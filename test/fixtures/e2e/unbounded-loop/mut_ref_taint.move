/// Test: taint through mutable references
module test::unbounded_loop_mutref {
    use sui::tx_context::TxContext;

    /// Helper that writes to mutable ref
    fun set_bound(result: &mut u64, val: u64) {
        *result = val;
    }

    /// Helper that doubles via mut ref
    fun double_in_place(val: &mut u64) {
        *val = *val * 2;
    }

    /// VULNERABLE: Taint propagated via mutable reference
    // @expect: unbounded-loop
    public entry fun process_mut_ref(count: u64, ctx: &mut TxContext) {
        let mut bound = 0;
        set_bound(&mut bound, count);
        let mut i = 0;
        while (i < bound) {
            i = i + 1;
        };
    }

    /// VULNERABLE: Taint through in-place mutation
    // @expect: unbounded-loop
    public entry fun process_mut_inplace(count: u64, ctx: &mut TxContext) {
        let mut bound = count;
        double_in_place(&mut bound);
        let mut i = 0;
        while (i < bound) {
            i = i + 1;
        };
    }

    /// SAFE: Sanitization via mut ref
    fun clamp_bound(val: &mut u64) {
        if (*val > 100) { *val = 100; };
    }

    // @false-positive: unbounded-loop (clamp sanitizes but not detected)
    public entry fun process_sanitized_mutref(count: u64, ctx: &mut TxContext) {
        let mut bound = count;
        clamp_bound(&mut bound);
        let mut i = 0;
        while (i < bound) {
            i = i + 1;
        };
    }
}
