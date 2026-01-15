/// Test: type_name::get used for logging vs actual validation
/// Only assert!/abort usage should count as validation
module test::logging_not_validation {
    use sui::coin::{Self, Coin};
    use sui::balance::Balance;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::UID;
    use sui::event::emit;
    use std::type_name;
    use std::string::String;

    public struct Pool has key {
        id: UID,
        expected_type: String,
    }

    public struct WithdrawEvent has copy, drop {
        coin_type: String,
        amount: u64,
    }

    /// VULNERABLE: type_name::get used only for logging/events - NOT validation
    /// The result goes to emit(), not to an assertion
    // @expect: generic-type-mismatch
    public fun withdraw_with_logging<T>(
        pool: &mut Pool,
        balance: &mut Balance<T>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        // This is NOT validation - just logging the type
        emit(WithdrawEvent {
            coin_type: type_name::into_string(type_name::get<T>()),
            amount: amount,
        });
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// VULNERABLE: type_name::get result is discarded - NOT validation
    // @expect: generic-type-mismatch
    public fun withdraw_discarded_result<T>(
        pool: &mut Pool,
        balance: &mut Balance<T>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        // Result is assigned but never used for validation
        let _type_check = type_name::get<T>();
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// SAFE: type_name::get result is used in assert! - ACTUAL validation
    public fun withdraw_with_assert<T>(
        pool: &mut Pool,
        balance: &mut Balance<T>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        // This IS validation - result is compared in assert
        assert!(
            type_name::into_string(type_name::get<T>()) == pool.expected_type,
            0
        );
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// SAFE: type_name::get stored then used in assert! - ACTUAL validation
    public fun withdraw_with_stored_assert<T>(
        pool: &mut Pool,
        balance: &mut Balance<T>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        // Result stored first, then used in assertion
        let actual_type = type_name::into_string(type_name::get<T>());
        assert!(actual_type == pool.expected_type, 0);
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }
}
