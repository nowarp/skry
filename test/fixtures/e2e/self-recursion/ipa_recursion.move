/// IPA recursion tests: entry calls private recursive function
module test::ipa_recursion {
    use sui::tx_context::TxContext;

    /// VULNERABLE: Entry transitively calls recursive function
    /// Current rule misses this - needs transitive-recursion rule
    // @false-negative: self-recursion
    public entry fun compute_fibonacci(n: u64, _ctx: &mut TxContext) {
        let _result = fib(n);
    }

    /// Private recursive helper - not directly flagged
    fun fib(n: u64): u64 {
        if (n <= 1) {
            n
        } else {
            fib(n - 1) + fib(n - 2)
        }
    }

    /// VULNERABLE: Public calls private recursive through helper chain
    // @false-negative: self-recursion
    public fun deep_compute(n: u64): u64 {
        helper_a(n)
    }

    fun helper_a(n: u64): u64 {
        helper_b(n)
    }

    fun helper_b(n: u64): u64 {
        recursive_core(n)
    }

    fun recursive_core(n: u64): u64 {
        if (n == 0) {
            0
        } else {
            recursive_core(n - 1) + 1
        }
    }

    /// SAFE: Entry calls non-recursive helper
    public entry fun safe_compute(n: u64, _ctx: &mut TxContext) {
        let _result = iterative_sum(n);
    }

    fun iterative_sum(n: u64): u64 {
        let mut sum = 0;
        let mut i = 0;
        while (i <= n) {
            sum = sum + i;
            i = i + 1;
        };
        sum
    }
}
