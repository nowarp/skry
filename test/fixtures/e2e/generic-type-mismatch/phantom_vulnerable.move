module test::phantom_vulnerable {
    use sui::coin::{Self, Coin};
    use sui::balance::Balance;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::UID;

    // NON-phantom type parameter - type is NOT ownership-bound
    public struct Pool<T> has key {
        id: UID,
        balance: Balance<T>
    }

    // @false-negative: generic-type-mismatch
    // T is NOT phantom-bound - caller can pass any T without owning Pool<T>
    public fun withdraw<T>(pool: &mut Pool<T>, amount: u64, ctx: &mut TxContext) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    // Mixed phantom/non-phantom
    public struct Mixed<phantom T, U> has key {
        id: UID,
        balance_t: Balance<T>,
        balance_u: Balance<U>
    }

    // @expect: generic-type-mismatch
    // T is phantom-bound (safe), but U is NOT (vulnerable)
    public fun extract_u<T, U>(mixed: &mut Mixed<T, U>, amount: u64, ctx: &mut TxContext) {
        // T extraction would be safe (phantom-bound)
        // let safe = coin::take(&mut mixed.balance_t, amount, ctx);

        // U extraction is vulnerable (not phantom-bound)
        let coins = coin::take(&mut mixed.balance_u, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }
}
