/// IPA test - safe entry -> all check version
module test::version_check_ipa_safe {
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    const CURRENT_VERSION: u64 = 2;

    public struct Pool has key {
        id: UID,
        version: u64,
        balance: u64,
    }

    /// All entry functions check version
    public entry fun withdraw(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        verify_version(pool);
        do_withdraw(pool, amount);
    }

    public entry fun deposit(pool: &mut Pool, amount: u64, ctx: &mut TxContext) {
        verify_version(pool);
        do_deposit(pool, amount);
    }

    fun do_withdraw(pool: &mut Pool, amount: u64) {
        pool.balance = pool.balance - amount;
    }

    fun do_deposit(pool: &mut Pool, amount: u64) {
        pool.balance = pool.balance + amount;
    }

    fun verify_version(pool: &Pool) {
        assert!(pool.version == CURRENT_VERSION, 0);
    }
}
