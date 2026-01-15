/// Tests that validation must be for the CORRECT type parameter
/// Validating T when extracting U should NOT make U safe
module test::wrong_type_validated {
    use sui::coin;
    use sui::balance::Balance;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use std::type_name;

    /// VULNERABLE: Validates T but extracts U - U is unvalidated!
    // @expect: generic-type-mismatch
    public fun validate_t_extract_u<T, U>(
        balance_t: &mut Balance<T>,
        balance_u: &mut Balance<U>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        // Validates T - but we're extracting U!
        let _ = type_name::get<T>();
        // Extracts U - which was never validated
        let coins = coin::take(balance_u, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// VULNERABLE: Has 3 type params, only validates first, extracts third
    // @expect: generic-type-mismatch
    public fun multi_type_wrong<A, B, C>(
        balance_a: &mut Balance<A>,
        balance_b: &mut Balance<B>,
        balance_c: &mut Balance<C>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let _ = type_name::get<A>();  // Validates A
        let _ = type_name::get<B>();  // Validates B
        // C is never validated!
        let coins = coin::take(balance_c, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// SAFE: Validates the exact type being extracted with assertion
    public fun validate_correct_type<T, U>(
        balance_u: &mut Balance<U>,
        expected_type: std::string::String,
        amount: u64,
        ctx: &mut TxContext
    ) {
        // Validates U - the type we're extracting
        assert!(type_name::into_string(type_name::get<U>()) == expected_type, 0);
        let coins = coin::take(balance_u, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }
}
