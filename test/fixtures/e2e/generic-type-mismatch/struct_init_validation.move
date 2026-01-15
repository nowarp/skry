/// Test: type_name::get<T>() inside struct field initializer should count as validation
module test::struct_init_validation {
    use sui::coin::{Self, Coin};
    use sui::balance::Balance;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use sui::event;
    use std::type_name::{Self, TypeName};

    public struct Pool has key {
        id: UID,
    }

    public struct WithdrawEvent has copy, drop {
        amount: u64,
        token_type: TypeName,
    }

    /// VULNERABLE: type_name::get<T>() in event is logging, NOT validation
    /// Using type info in events doesn't prevent type confusion attacks
    // @expect: generic-type-mismatch
    public fun withdraw_with_event<T>(
        pool: &mut Pool,
        balance: &mut Balance<T>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(balance, amount, ctx);
        // type_name::get<T>() for logging - NOT validation
        event::emit(WithdrawEvent {
            amount: amount,
            token_type: type_name::get<T>(),
        });
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// VULNERABLE: Same pattern - logging is not validation
    // @expect: generic-type-mismatch
    public fun withdraw_with_let_event<T>(
        pool: &mut Pool,
        balance: &mut Balance<T>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(balance, amount, ctx);
        let evt = WithdrawEvent {
            amount: amount,
            token_type: type_name::get<T>(),
        };
        event::emit(evt);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }
}
