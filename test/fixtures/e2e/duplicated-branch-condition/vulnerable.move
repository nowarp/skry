/// Test cases for duplicated-branch-condition rule.
/// Same condition appears multiple times - second branch unreachable
module test::duplicated_branch_condition {
    use sui::coin::{Self, Coin};
    use sui::balance::Balance;
    use sui::sui::SUI;
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    /// VULNERABLE: Same condition twice - second branch unreachable!
    // @expect: duplicated-branch-condition
    public entry fun process_amount(amount: u64) {
        if (amount > 100) {
            // Handle large amounts
        } else if (amount > 100) {  // DUPLICATE! Never reached
            // Dead code - this branch is unreachable
        } else {
            // Handle small amounts
        }
    }

    /// VULNERABLE: Multiple duplicates in nested conditions
    // @expect: duplicated-branch-condition
    public entry fun complex_duplicates(amount: u64, active: bool) {
        if (amount > 1000) {
            // Handle very large
        } else if (amount > 100) {
            // Handle large
        } else if (amount > 1000) {  // DUPLICATE of first condition
            // Dead code
        } else {
            // Handle small
        }
    }

    /// VULNERABLE: Duplicate boolean condition
    // @expect: duplicated-branch-condition
    public entry fun bool_duplicate(is_active: bool, value: u64) {
        if (is_active) {
            // First branch
        } else if (is_active) {  // DUPLICATE!
            // Dead code
        } else {
            // Default
        }
    }

    /// SAFE: Distinct conditions
    public entry fun process_safe(amount: u64) {
        if (amount > 100) {
            // Handle large
        } else if (amount > 50) {  // Different condition
            // Handle medium
        } else {
            // Handle small
        }
    }

    /// SAFE: Different operators
    public entry fun different_operators(amount: u64) {
        if (amount > 100) {
            // Greater than
        } else if (amount == 100) {  // Different operator
            // Exactly 100
        } else {
            // Less than
        }
    }
}
