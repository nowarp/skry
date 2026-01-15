/// Test cases for self-recursive-entry rule.
/// Entry function calls itself - infinite recursion
module test::self_recursive_entry {
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    public struct Counter has key {
        id: UID,
        value: u64,
    }

    /// VULNERABLE: Entry calls itself
    // @expect: self-recursive-entry
    entry fun recursive_action(counter: u64, ctx: &mut TxContext) {
        if (counter > 0) {
            recursive_action(counter - 1, ctx);  // Stack overflow!
        };
    }

    /// VULNERABLE: Entry with decrement recursion
    // @expect: self-recursive-entry
    entry fun countdown(n: u64, ctx: &mut TxContext) {
        if (n > 0) {
            countdown(n - 1, ctx);  // Dangerous!
        };
    }

    /// VULNERABLE: Conditional self-recursion
    // @expect: self-recursive-entry
    entry fun process_recursive(state: &mut Counter, recurse: bool, ctx: &mut TxContext) {
        state.value = state.value + 1;
        if (recurse) {
            process_recursive(state, false, ctx);  // Still vulnerable
        };
    }

    /// SAFE: Entry with loop
    entry fun iterative_action(counter: u64, ctx: &mut TxContext) {
        let mut i = counter;
        while (i > 0) {
            i = i - 1;
        };
    }

    /// SAFE: Entry calls non-recursive helper
    entry fun safe_entry(counter: u64, ctx: &mut TxContext) {
        process_count(counter);
    }

    fun process_count(n: u64) {
        let mut i = n;
        while (i > 0) {
            i = i - 1;
        };
    }
}
