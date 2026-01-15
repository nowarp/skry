/// IPA test - vulnerable entry -> helper without version check
module test::version_check_ipa_vuln {
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    const CURRENT_VERSION: u64 = 2;

    public struct Pool has key {
        id: UID,
        version: u64,
        balance: u64,
    }

    /// Has version check
    public entry fun withdraw_checked(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        verify_version(pool);
        do_withdraw(pool, amount);
    }

    /// VULNERABLE: Calls helper without version check
    // @expect: version-check-missing
    public entry fun withdraw_unchecked(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        do_withdraw(pool, amount);  // Missing version check
    }

    fun do_withdraw(pool: &mut Pool, amount: u64) {
        pool.balance = pool.balance - amount;
    }

    fun verify_version(pool: &Pool) {
        assert!(pool.version == CURRENT_VERSION, 0);
    }
}
