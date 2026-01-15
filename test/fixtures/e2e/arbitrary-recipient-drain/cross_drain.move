module test::cross_drain {
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

    /// Entry function - calls helper to drain
    // @expect: arbitrary-recipient-drain
    public entry fun entry_drain(
        pool: &mut Pool,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        do_drain(pool, amount, recipient, ctx);
    }

    /// Helper that does the actual drain
    fun do_drain(
        pool: &mut Pool,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
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
