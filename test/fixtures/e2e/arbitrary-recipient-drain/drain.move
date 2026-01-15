module test::vulnerable_pool {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};

    /// Shared pool holding protocol funds
    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    /// VULNERABLE: Drains pool to attacker-controlled address
    // @expect: arbitrary-recipient-drain
    public entry fun drain(
        pool: &mut Pool,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }

    /// SAFE: User deposits own coins
    public entry fun deposit(
        pool: &mut Pool,
        coin: Coin<SUI>,
    ) {
        balance::join(&mut pool.balance, coin::into_balance(coin));
    }

    /// Init creates shared pool
    fun init(ctx: &mut TxContext) {
        let pool = Pool {
            id: object::new(ctx),
            balance: balance::zero(),
        };
        transfer::share_object(pool);
    }
}
