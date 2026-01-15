/// Tests that type validation via method chain is recognized.
/// Pattern: type_name::get<T>().into_string() should validate T.
module test::method_chain_validation {
    use sui::coin;
    use sui::balance::Balance;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use std::type_name;
    use std::ascii::String;

    /// Helper that validates type via method chain and assertion
    public fun validate_type<T>(expected: String) {
        assert!(type_name::get<T>().into_string() == expected, 0);
    }

    /// SAFE: Validates T via helper that uses method chain with assertion
    public fun withdraw_with_helper<T>(
        balance: &mut Balance<T>,
        expected_type: String,
        amount: u64,
        ctx: &mut TxContext
    ) {
        validate_type<T>(expected_type);
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// SAFE: Direct method chain validation with assertion
    public fun withdraw_with_direct_chain<T>(
        balance: &mut Balance<T>,
        expected_type: String,
        amount: u64,
        ctx: &mut TxContext
    ) {
        assert!(type_name::get<T>().into_string() == expected_type, 0);
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// VULNERABLE: No validation at all
    // @expect: generic-type-mismatch
    public fun withdraw_no_validation<T>(
        balance: &mut Balance<T>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }
}
