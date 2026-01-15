/// FQN collision test - module B
module test::fqn_collision_b {
    use sui::tx_context::TxContext;

    /// SAFE: Entry uses iteration
    entry fun process(count: u64, n: u64, ctx: &mut TxContext) {
        let mut i = 0;
        while (i < n) {
            i = i + 1;
        };
    }
}
