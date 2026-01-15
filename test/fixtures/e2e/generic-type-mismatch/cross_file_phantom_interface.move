/// Test: Interface module using phantom type from different file.
/// Pattern: Pool<phantom L> defined in pool_module, used here.
/// L should be recognized as phantom-bound even when Pool is imported.
module interface_module::interface {
    use sui::coin::{Self, Coin};
    use sui::balance::Balance;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use pool_module::pool::Pool;
    use std::type_name;

    /// SAFE: L is phantom-bound via Pool<L>, C1 is validated via type_name::get.
    /// Should NOT be flagged.
    public entry fun withdraw_with_phantom<L, C1>(
        pool: &mut Pool<L>,
        balance: &mut Balance<C1>,
        expected_type: std::string::String,
        amount: u64,
        ctx: &mut TxContext
    ) {
        // Validate C1 type - result used in assertion
        let type_str = type_name::into_string(type_name::get<C1>());
        assert!(type_str == expected_type, 0);

        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// VULNERABLE: L is phantom-bound, but C1 is NOT validated.
    /// Should be flagged for C1.
    // @expect: generic-type-mismatch
    public entry fun withdraw_no_c1_validation<L, C1>(
        pool: &mut Pool<L>,
        balance: &mut Balance<C1>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }
}
