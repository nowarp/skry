/// Safe test cases - no self-recursive entry functions
module test::self_recursive_safe {
    use sui::tx_context::TxContext;

    /// Iterative approach
    entry fun process_items(count: u64, ctx: &mut TxContext) {
        let mut i = 0;
        while (i < count) {
            i = i + 1;
        };
    }

    /// Entry calls helper (not recursive)
    entry fun process_with_helper(count: u64, ctx: &mut TxContext) {
        do_processing(count);
    }

    fun do_processing(n: u64) {
        let mut i = 0;
        while (i < n) {
            i = i + 1;
        };
    }

    /// Helper can be recursive (not entry)
    fun recursive_helper(n: u64): u64 {
        if (n == 0) {
            0
        } else {
            n + recursive_helper(n - 1)  // OK - not an entry function
        }
    }

    entry fun use_recursive_helper(n: u64, ctx: &mut TxContext) {
        let _result = recursive_helper(n);
    }
}
