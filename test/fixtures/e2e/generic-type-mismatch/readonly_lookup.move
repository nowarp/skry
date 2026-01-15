/// Test: Read-only lookup functions should NOT be flagged.
/// They have generic params but only read data - no extraction possible.
module test::readonly_lookup {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use sui::table::{Self, Table};
    use std::type_name::{Self, TypeName};

    public struct Registry has key {
        id: UID,
        allowed_types: Table<TypeName, bool>,
    }

    /// SAFE: Read-only lookup - no &mut params, returns bool.
    /// Called from withdraw_checked which does extraction.
    /// Should NOT be flagged - read-only functions can't extract value.
    public fun is_allowed<T>(registry: &Registry): bool {
        table::contains(&registry.allowed_types, type_name::with_defining_ids<T>())
    }

    /// VULNERABLE: Has &mut param, does extraction.
    /// Calls is_allowed<T> then extracts - is_allowed gets IPA responsibility.
    /// Should be flagged - no type validation.
    public fun withdraw_checked<T>(
        registry: &Registry,
        balance: &mut Balance<T>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        assert!(is_allowed<T>(registry), 1);
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// VULNERABLE: Has &mut param - can modify/extract.
    /// Should be flagged - no type validation before extraction.
    // @expect: generic-type-mismatch
    public fun withdraw<T>(
        registry: &mut Registry,
        balance: &mut Balance<T>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }
}
