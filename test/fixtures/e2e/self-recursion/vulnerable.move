/// Test cases for self-recursion rule.
/// Self-recursive function in public entry - potential stack overflow
module test::self_recursion {
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    public struct Pool has key {
        id: UID,
        value: u64,
    }

    /// VULNERABLE: Recursive public function
    // @expect: self-recursion
    public fun recursive_withdraw(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        if (amount > 0) {
            recursive_withdraw(pool, amount - 1, ctx);  // Stack overflow!
        };
    }

    /// VULNERABLE: Recursive entry
    // @expect: self-recursion
    public entry fun recursive_process(n: u64, ctx: &mut TxContext) {
        if (n > 0) {
            recursive_process(n - 1, ctx);
        };
    }

    /// Not for this rule: Private recursive function (would need IPA to catch via compute_fib)
    fun fibonacci(n: u64): u64 {
        if (n <= 1) {
            n
        } else {
            fibonacci(n - 1) + fibonacci(n - 2)  // Can overflow with large n
        }
    }

    public entry fun compute_fib(n: u64, ctx: &mut TxContext) {
        let _result = fibonacci(n);
    }

    /// SAFE: Non-recursive with loop
    public entry fun safe_withdraw(pool: &mut Pool, count: u64, ctx: &mut TxContext) {
        let mut i = 0;
        while (i < count) {
            i = i + 1;
        };
    }
}
