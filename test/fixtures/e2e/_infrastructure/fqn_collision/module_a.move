/// FQN collision test - Module A with Pool struct
/// Tests that rules correctly distinguish between same-named structs in different modules.
module test::module_a {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};

    /// Shared pool in module A
    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    /// AdminCap for module A
    public struct AdminCap has key, store {
        id: UID,
    }

    /// VULNERABLE: Withdraw from module A pool without auth
    public entry fun withdraw(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// SAFE: Withdraw from module A pool with AdminCap
    public entry fun withdraw_admin(
        pool: &mut Pool,
        amount: u64,
        _cap: &AdminCap,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// Init
    fun init(ctx: &mut TxContext) {
        let pool = Pool {
            id: object::new(ctx),
            balance: balance::zero(),
        };
        transfer::share_object(pool);

        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }
}
