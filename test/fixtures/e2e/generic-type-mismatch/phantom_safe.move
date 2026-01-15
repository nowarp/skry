module test::phantom_safe {
    use sui::coin::{Self, Coin};
    use sui::balance::Balance;
    use sui::tx_context::TxContext;

    // Struct with phantom type parameter - type is ownership-bound
    public struct Pool<phantom T> has key {
        id: UID,
        balance: Balance<T>
    }

    // P is constrained by Pool<P> ownership - caller must have Pool<P> object
    public entry fun withdraw<P>(pool: &mut Pool<P>, amount: u64, ctx: &mut TxContext) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    // Multiple phantom params
    public struct Pair<phantom A, phantom B> has key {
        id: UID,
        balance_a: Balance<A>,
        balance_b: Balance<B>
    }

    // Both A and B are phantom-bound
    public entry fun swap<A, B>(pair: &mut Pair<A, B>, amount: u64, ctx: &mut TxContext) {
        let coins_a = coin::take(&mut pair.balance_a, amount, ctx);
        let coins_b = coin::take(&mut pair.balance_b, amount, ctx);
        transfer::public_transfer(coins_a, tx_context::sender(ctx));
        transfer::public_transfer(coins_b, tx_context::sender(ctx));
    }
}
