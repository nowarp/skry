/// Test: version check via transitive helper (non-standard name)
module test::version_check_transitive_safe {
    use sui::tx_context::TxContext;
    use sui::object::UID;

    const CURRENT_VERSION: u64 = 2;

    public struct Pool has key {
        id: UID,
        version: u64,
        balance: u64,
    }

    /// Entry calls helper which calls version check (non-standard naming)
    /// SAFE: transitive version check via my_internal_checker
    public entry fun deposit(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        do_deposit_with_checks(pool, amount);
    }

    /// Helper that calls version check (non-standard name)
    fun do_deposit_with_checks(pool: &mut Pool, amount: u64) {
        my_internal_checker(pool);
        pool.balance = pool.balance + amount;
    }

    /// Version check with non-standard name
    fun my_internal_checker(pool: &Pool) {
        assert!(pool.version == CURRENT_VERSION, 0);
    }

    /// Another entry with direct check (establishes module has version checking)
    public entry fun withdraw(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        assert!(pool.version == CURRENT_VERSION, 0);
        pool.balance = pool.balance - amount;
    }
}
