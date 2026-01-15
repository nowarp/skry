/// Safe test cases - proper value transfer
module test::missing_transfer_safe {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};

    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    /// Extracts and transfers to sender
    public entry fun withdraw_to_sender(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// Extracts and transfers to recipient
    public entry fun withdraw_to_recipient(
        pool: &mut Pool,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }

    /// Returns coin (caller responsibility)
    public fun withdraw_returns(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ): Coin<SUI> {
        coin::take(&mut pool.balance, amount, ctx)
    }

    /// Joins coins and transfers
    public entry fun withdraw_and_join(
        pool: &mut Pool,
        amount1: u64,
        amount2: u64,
        ctx: &mut TxContext
    ) {
        let mut coins1 = coin::take(&mut pool.balance, amount1, ctx);
        let coins2 = coin::take(&mut pool.balance, amount2, ctx);
        coin::join(&mut coins1, coins2);
        transfer::public_transfer(coins1, tx_context::sender(ctx));
    }
}
