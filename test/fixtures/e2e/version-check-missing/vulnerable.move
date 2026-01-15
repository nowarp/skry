/// Test cases for version-check-missing rule.
/// Public entry function missing version check while others check version
module test::version_check {
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    const CURRENT_VERSION: u64 = 2;
    const E_WRONG_VERSION: u64 = 0;

    public struct Pool has key {
        id: UID,
        version: u64,
        balance: u64,
    }

    /// Has version check
    public entry fun withdraw_v2(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        verify_version(pool);
        pool.balance = pool.balance - amount;
    }

    /// Has version check
    public entry fun deposit_v2(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        verify_version(pool);
        pool.balance = pool.balance + amount;
    }

    /// VULNERABLE: Same module, no version check
    // @expect: version-check-missing
    public entry fun deposit(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        // Missing: verify_version(pool);
        pool.balance = pool.balance + amount;
    }

    /// VULNERABLE: Another function without check
    // @expect: version-check-missing
    public entry fun transfer_funds(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        // Missing version check
        pool.balance = pool.balance - amount;
    }

    fun verify_version(pool: &Pool) {
        assert!(pool.version == CURRENT_VERSION, E_WRONG_VERSION);
    }
}
