/// Cross-module test - helper module
module test::version_check_helper {
    use sui::object::{Self, UID};

    public struct Pool has key {
        id: UID,
        version: u64,
        balance: u64,
    }

    public fun verify_version(pool: &Pool, expected: u64) {
        assert!(pool.version == expected, 0);
    }

    public fun process(pool: &mut Pool) {
        pool.balance = pool.balance + 1;
    }
}
