/// Test cases for generic-type-mismatch rule.
/// Generic type parameter without type_name::get validation.
module test::generic_type_mismatch {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use std::type_name;

    /// Multi-token pool - stores balances for multiple token types in a single object.
    /// T is NOT phantom, so the pool can hold any Balance<T>.
    /// This is the vulnerable pattern: attacker provides arbitrary T to extract coins.
    public struct MultiPool has key {
        id: UID,
        // Dynamic field would store Balance<T> for various T
    }

    /// Safe pool with phantom T - constrains T to the pool's type
    public struct TypedPool<phantom T> has key {
        id: UID,
        balance: Balance<T>,
    }

    /// Admin capability
    public struct AdminCap has key, store {
        id: UID,
    }

    /// VULNERABLE: Generic type parameter without validation on multi-token pool.
    /// Attacker can call with arbitrary T to extract unexpected coin types.
    /// The pool doesn't constrain T, so any type can be passed.
    // @expect: generic-type-mismatch
    public fun withdraw<T>(
        pool: &mut MultiPool,
        balance: &mut Balance<T>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// VULNERABLE: Same issue via helper function
    // @expect: generic-type-mismatch
    public fun withdraw_via_helper<T>(
        pool: &mut MultiPool,
        balance: &mut Balance<T>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        do_withdraw(balance, amount, ctx);
    }

    fun do_withdraw<T>(
        balance: &mut Balance<T>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// SAFE: Has type_name::get validation with assertion
    public fun withdraw_with_validation<T>(
        pool: &mut MultiPool,
        balance: &mut Balance<T>,
        amount: u64,
        expected_type: std::string::String,
        ctx: &mut TxContext
    ) {
        // Real validation: compare type against expected and abort if mismatch
        assert!(type_name::into_string(type_name::get<T>()) == expected_type, 1);
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// SAFE: Has role check (admin-controlled)
    public fun withdraw_with_role<T>(
        pool: &mut MultiPool,
        balance: &mut Balance<T>,
        amount: u64,
        _cap: &AdminCap,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// SAFE: Phantom-typed pool constrains T to pool's type
    public entry fun withdraw_typed<T>(
        pool: &mut TypedPool<T>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// SAFE: No value extraction (just read)
    public entry fun get_balance<T>(
        pool: &TypedPool<T>
    ): u64 {
        balance::value(&pool.balance)
    }

    /// Init
    fun init(ctx: &mut TxContext) {
        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }
}
