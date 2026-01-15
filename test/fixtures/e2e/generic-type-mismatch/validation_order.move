/// Tests that ORDER of validation matters
/// Validation AFTER extraction should NOT make it safe
module test::validation_order {
    use sui::coin;
    use sui::balance::Balance;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use std::type_name;

    /// VULNERABLE: Validates AFTER extraction - too late!
    /// Attacker already extracted coins before validation runs
    // @expect: generic-type-mismatch
    public fun withdraw_validate_after<T>(balance: &mut Balance<T>, amount: u64, ctx: &mut TxContext) {
        // Extract first (vulnerable!)
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
        // Validate after (useless) - also discarded so not a real validation
        let _ = type_name::get<T>();
    }

    /// SAFE: Validates BEFORE extraction - correct order with assertion
    public fun withdraw_validate_before<T>(balance: &mut Balance<T>, expected_type: std::string::String, amount: u64, ctx: &mut TxContext) {
        // Validate first with assertion (blocks arbitrary T)
        assert!(type_name::into_string(type_name::get<T>()) == expected_type, 0);
        // Extract after validation
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }
}
