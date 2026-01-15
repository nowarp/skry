module test::owned_input_safe {
    use sui::coin::{Self, Coin};
    use sui::balance::Balance;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    // Generic type bound by owned input - caller must provide Coin<T> they own.
    // Sui VM enforces type safety: can't pass Coin<USDC> claiming it's Coin<ETH>.
    // No shared state accessed, no type confusion possible.

    // Safe: T bound by owned Coin<T> input, extracted value returned to caller
    public fun split_coin<T>(coin: Coin<T>, amount: u64, ctx: &mut TxContext): Coin<T> {
        let split = coin::split(&mut coin, amount, ctx);
        transfer::public_transfer(coin, tx_context::sender(ctx));
        split
    }

    // Safe: T bound by owned Coin<T> input, extracted value returned to caller
    public fun split_to_balance<T>(coin: Coin<T>, amount: u64, ctx: &mut TxContext): Balance<T> {
        let split = coin::split(&mut coin, amount, ctx);
        transfer::public_transfer(coin, tx_context::sender(ctx));
        coin::into_balance(split)
    }

    // Safe: T bound by owned Balance<T> input, extracted value returned to caller
    public fun extract_from_balance<T>(balance: &mut Balance<T>, amount: u64, ctx: &mut TxContext): Coin<T> {
        coin::take(balance, amount, ctx)
    }

    // Safe: Multiple generics bound by owned inputs, extracted values returned to caller
    public fun swap_coins<A, B>(
        coin_a: Coin<A>,
        coin_b: Coin<B>,
        amount: u64,
        ctx: &mut TxContext
    ): (Coin<A>, Coin<B>) {
        let split_a = coin::split(&mut coin_a, amount, ctx);
        let split_b = coin::split(&mut coin_b, amount, ctx);
        transfer::public_transfer(coin_a, tx_context::sender(ctx));
        transfer::public_transfer(coin_b, tx_context::sender(ctx));
        (split_a, split_b)
    }
}
