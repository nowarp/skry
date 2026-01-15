/// FQN collision test - module A
module test::fqn_collision_a {
    use sui::tx_context::TxContext;

    /// VULNERABLE: Entry function is self-recursive
    // @expect: self-recursive-entry
    entry fun process(count: u64, n: u64, ctx: &mut TxContext) {
        if (n > 0) {
            process(count, n - 1, ctx);  // Recursive entry
        };
    }
}
