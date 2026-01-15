/// Safe test cases - distinct branch bodies
module test::duplicated_branch_safe {
    use sui::tx_context::TxContext;

    /// Distinct logic in each branch
    public entry fun process(tier: u64) {
        if (tier == 1) {
            // Tier 1 logic
            let x = 100;
        } else if (tier == 2) {
            // Tier 2 logic - different
            let x = 200;
        } else {
            // Default - also different
            let x = 50;
        }
    }

    /// Refactored to remove duplication
    public entry fun process_refactored(is_premium: bool) {
        let multiplier = if (is_premium) { 2 } else { 1 };
        let amount = 100 * multiplier;
    }
}
