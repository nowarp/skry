/// Safe test cases - no duplicated branch conditions
module test::duplicated_branch_safe {
    use sui::tx_context::TxContext;

    /// All conditions are distinct
    public entry fun distinct_conditions(amount: u64) {
        if (amount > 1000) {
            // Very large
        } else if (amount > 500) {
            // Large
        } else if (amount > 100) {
            // Medium
        } else {
            // Small
        }
    }

    /// Different variables checked
    public entry fun different_variables(amount: u64, fee: u64) {
        if (amount > 100) {
            // Check amount
        } else if (fee > 10) {  // Different variable
            // Check fee
        } else {
            // Default
        }
    }

    /// Logical combinations
    public entry fun logical_combinations(amount: u64, active: bool) {
        if (amount > 100 && active) {
            // Both conditions
        } else if (amount > 100 && !active) {  // Different combination
            // Amount large but not active
        } else {
            // Default
        }
    }

    /// Simple if-else without else-if
    public entry fun simple_if_else(amount: u64) {
        if (amount > 100) {
            // Large
        } else {
            // Small
        }
    }
}
