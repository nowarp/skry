/// IPA test - safe entry -> helper with validation
module test::unbounded_loop_ipa_safe {
    use sui::tx_context::TxContext;

    const MAX_COUNT: u64 = 1000;

    /// SAFE: Entry validates before calling helper
    public entry fun process_batch(count: u64, ctx: &mut TxContext) {
        assert!(count <= MAX_COUNT, 0);
        execute_loop(count);  // Sanitized by assert
    }

    fun execute_loop(iterations: u64) {
        let mut i = 0;
        while (i < iterations) {
            i = i + 1;
        };
    }

    /// SAFE: Helper validates
    public entry fun process_with_helper_validation(count: u64, ctx: &mut TxContext) {
        execute_validated_loop(count);
    }

    fun execute_validated_loop(iterations: u64) {
        assert!(iterations <= 500, 1);  // Helper validates
        let mut i = 0;
        while (i < iterations) {
            i = i + 1;
        };
    }
}
