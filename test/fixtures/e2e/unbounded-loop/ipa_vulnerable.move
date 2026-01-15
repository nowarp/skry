/// IPA test - vulnerable entry -> helper chain
module test::unbounded_loop_ipa_vuln {
    use sui::tx_context::TxContext;

    /// VULNERABLE: Entry passes tainted count to helper
    // @expect: unbounded-loop
    public entry fun process_batch(count: u64, ctx: &mut TxContext) {
        execute_loop(count);
    }

    /// Helper uses tainted bound
    fun execute_loop(iterations: u64) {
        let mut i = 0;
        while (i < iterations) {  // Tainted from entry
            i = i + 1;
        };
    }

    /// VULNERABLE: Two-hop propagation
    // @expect: unbounded-loop
    public entry fun process_two_hop(count: u64, ctx: &mut TxContext) {
        call_middle(count);
    }

    fun call_middle(count: u64) {
        call_final(count);
    }

    fun call_final(iterations: u64) {
        let mut i = 0;
        while (i < iterations) {  // Still tainted
            i = i + 1;
        };
    }
}
