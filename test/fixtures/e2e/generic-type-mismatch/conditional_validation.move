/// Tests conditional validation - if validation only happens in some branches
module test::conditional_validation {
    use sui::coin;
    use sui::balance::Balance;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use std::type_name;

    /// VULNERABLE: Validates only in one branch (and discards result)
    /// Attacker can pass flag=false to bypass validation
    // @expect: generic-type-mismatch
    public fun conditional_withdraw<T>(
        balance: &mut Balance<T>,
        amount: u64,
        validate: bool,
        ctx: &mut TxContext
    ) {
        if (validate) {
            let _ = type_name::get<T>();  // Discarded - not real validation
        };
        // Extraction happens regardless of branch
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// VULNERABLE: Extraction in unvalidated branch (and validation discards result)
    // @expect: generic-type-mismatch
    public fun branch_without_validation<T>(
        balance: &mut Balance<T>,
        amount: u64,
        use_fast_path: bool,
        ctx: &mut TxContext
    ) {
        if (use_fast_path) {
            // Fast path - no validation!
            let coins = coin::take(balance, amount, ctx);
            transfer::public_transfer(coins, tx_context::sender(ctx));
        } else {
            // Slow path - has validation but discarded
            let _ = type_name::get<T>();
            let coins = coin::take(balance, amount, ctx);
            transfer::public_transfer(coins, tx_context::sender(ctx));
        }
    }

    /// SAFE: Validates before branching with assertion
    public fun validate_before_branch<T>(
        balance: &mut Balance<T>,
        expected_type: std::string::String,
        amount: u64,
        double_amount: bool,
        ctx: &mut TxContext
    ) {
        // Validation happens unconditionally first with assertion
        assert!(type_name::into_string(type_name::get<T>()) == expected_type, 0);
        if (double_amount) {
            let coins = coin::take(balance, amount * 2, ctx);
            transfer::public_transfer(coins, tx_context::sender(ctx));
        } else {
            let coins = coin::take(balance, amount, ctx);
            transfer::public_transfer(coins, tx_context::sender(ctx));
        }
    }
}
