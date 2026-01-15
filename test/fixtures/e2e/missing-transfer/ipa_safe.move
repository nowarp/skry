/// IPA test - safe entry -> helper chain with transfer
module test::missing_transfer_ipa_safe {
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

    /// SAFE: Entry calls helper that properly transfers
    public entry fun withdraw(
        pool: &mut Pool,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        extract_and_transfer(pool, amount, recipient, ctx);
    }

    /// Helper extracts and transfers
    fun extract_and_transfer(
        pool: &mut Pool,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }

    /// SAFE: Helper returns coin, entry transfers
    public entry fun withdraw_split_responsibility(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = extract_coins(pool, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    fun extract_coins(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ): Coin<SUI> {
        coin::take(&mut pool.balance, amount, ctx)
    }
}
