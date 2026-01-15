/// Test case: Validation helper without type check.
/// Pattern: validate_xxx<T>() is called before extraction, but doesn't validate T.
/// Based on Navi Protocol lending_core/validation.move:validate_withdraw pattern.
module test::validation_helper {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use std::type_name;

    public struct Storage has key {
        id: UID,
    }

    /// Validation helper without type_name::get<CoinType>.
    /// VULNERABLE: Has validation responsibility but doesn't validate type
    /// Uses &mut Storage like real Navi code (lending_core/validation.move:35)
    // @expect: generic-type-mismatch
    public fun validate_withdraw<CoinType>(storage: &mut Storage, asset: u8, amount: u64) {
        // Missing: type_name::get<CoinType>() validation
        // The commented line below is what Navi has:
        // assert!(type_name::into_string(type_name::get<CoinType>()) == ..., ...);
        assert!(amount != 0, 0);
    }

    /// Private function that calls validate then extracts
    /// This demonstrates the pattern where validation and extraction are in same caller.
    fun execute_withdraw<CoinType>(
        storage: &mut Storage,
        pool: &mut Balance<CoinType>,
        asset: u8,
        amount: u64,
        ctx: &mut TxContext
    ): Coin<CoinType> {
        validate_withdraw<CoinType>(storage, asset, amount);
        coin::take(pool, amount, ctx)
    }

    /// Entry point that calls execute_withdraw
    /// VULNERABLE: No type validation in call chain (validate_withdraw doesn't validate)
    // @expect: generic-type-mismatch
    public entry fun withdraw<CoinType>(
        storage: &mut Storage,
        pool: &mut Balance<CoinType>,
        asset: u8,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = execute_withdraw<CoinType>(storage, pool, asset, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// SAFE: Validation helper WITH type check (result used in assertion)
    public fun validate_withdraw_safe<CoinType>(storage: &Storage, expected_type: std::string::String, amount: u64) {
        // Real validation: compare type against expected and abort if mismatch
        assert!(type_name::into_string(type_name::get<CoinType>()) == expected_type, 1);
        assert!(amount != 0, 0);
    }

    /// Private function that calls safe validate then extracts
    fun execute_withdraw_safe<CoinType>(
        storage: &Storage,
        pool: &mut Balance<CoinType>,
        expected_type: std::string::String,
        amount: u64,
        ctx: &mut TxContext
    ): Coin<CoinType> {
        validate_withdraw_safe<CoinType>(storage, expected_type, amount);
        coin::take(pool, amount, ctx)
    }

    /// Entry point that calls safe execute_withdraw
    public entry fun withdraw_safe<CoinType>(
        storage: &Storage,
        pool: &mut Balance<CoinType>,
        expected_type: std::string::String,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = execute_withdraw_safe<CoinType>(storage, pool, expected_type, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// SAFE: Entry point validates type BEFORE calling internal function with extraction.
    /// The internal function (execute_withdraw) has extraction but caller validated first.
    public entry fun withdraw_caller_validates<CoinType>(
        storage: &mut Storage,
        pool: &mut Balance<CoinType>,
        expected_type: std::string::String,
        asset: u8,
        amount: u64,
        ctx: &mut TxContext
    ) {
        // Caller validates type BEFORE calling internal extraction function
        assert!(type_name::into_string(type_name::get<CoinType>()) == expected_type, 1);
        // Now safe to call internal function that has extraction but no validation
        let coins = execute_withdraw<CoinType>(storage, pool, asset, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }
}
