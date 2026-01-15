/// Tests that IPA validation propagation is precise
/// Callee validating T should NOT make caller's U safe
module test::partial_ipa_validation {
    use sui::coin;
    use sui::balance::Balance;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use std::type_name;

    /// Helper that validates its type param
    public fun validate_type<V>(expected: std::string::String) {
        assert!(type_name::into_string(type_name::get<V>()) == expected, 0);
    }

    /// VULNERABLE: Calls validate_type<T> but extracts U
    /// IPA should not mark U as validated just because T was validated
    // @expect: generic-type-mismatch
    public fun validate_t_but_extract_u<T, U>(
        balance_u: &mut Balance<U>,
        expected_t: std::string::String,
        amount: u64,
        ctx: &mut TxContext
    ) {
        // Validates T via IPA
        validate_type<T>(expected_t);
        // But extracts U - which was never validated!
        let coins = coin::take(balance_u, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// SAFE: Validates U (the type being extracted)
    public fun validate_u_extract_u<T, U>(
        balance_u: &mut Balance<U>,
        expected_u: std::string::String,
        amount: u64,
        ctx: &mut TxContext
    ) {
        // Validates U via IPA
        validate_type<U>(expected_u);
        // Extracts U - which WAS validated
        let coins = coin::take(balance_u, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }
}
