/// FQN collision test - Module B with Pool struct (same name as module_a::Pool)
/// Tests that rules correctly distinguish between same-named structs in different modules.
module test::module_b {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};

    /// Shared pool in module B (DIFFERENT from module_a::Pool)
    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
        fee_rate: u64,  // Different field to distinguish from module_a::Pool
    }

    /// AdminCap for module B (DIFFERENT from module_a::AdminCap)
    public struct AdminCap has key, store {
        id: UID,
    }

    /// VULNERABLE: Withdraw from module B pool without auth
    public entry fun withdraw(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// SAFE: Withdraw from module B pool with module B AdminCap
    /// Critical: AdminCap must resolve to module_b::AdminCap, NOT module_a::AdminCap
    public entry fun withdraw_admin(
        pool: &mut Pool,
        amount: u64,
        _cap: &AdminCap,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// VULNERABLE: Withdraw from module B pool with WRONG AdminCap (module A's)
    /// This should be flagged because module_a::AdminCap doesn't protect module_b::Pool
    public entry fun withdraw_wrong_cap(
        pool: &mut Pool,
        amount: u64,
        _cap: &test::module_a::AdminCap,
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
            fee_rate: 100,
        };
        transfer::share_object(pool);

        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }
}
