/// Safe test cases - all functions check version
module test::version_check_safe {
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    const CURRENT_VERSION: u64 = 3;
    const E_WRONG_VERSION: u64 = 0;

    public struct Pool has key {
        id: UID,
        version: u64,
        balance: u64,
    }

    /// All entry functions check version
    public entry fun withdraw(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        verify_version(pool);
        pool.balance = pool.balance - amount;
    }

    public entry fun deposit(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        verify_version(pool);
        pool.balance = pool.balance + amount;
    }

    public entry fun transfer(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        verify_version(pool);
        pool.balance = pool.balance - amount;
    }

    fun verify_version(pool: &Pool) {
        assert!(pool.version == CURRENT_VERSION, E_WRONG_VERSION);
    }
}
