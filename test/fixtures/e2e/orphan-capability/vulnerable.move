/// Test cases for orphan-role rule.
/// Role struct defined but never used as parameter
module test::orphan_role {
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    /// ORPHAN: Never used as parameter
    // @expect: orphan-capability
    public struct UnusedAdminCap has key {
        id: UID,
    }

    /// ORPHAN: Another unused role
    // @expect: orphan-capability
    public struct UnusedModeratorCap has key {
        id: UID,
    }

    /// USED: This role is used in functions
    public struct ActiveAdminCap has key {
        id: UID,
    }

    public struct Pool has key {
        id: UID,
        balance: u64,
    }

    /// Uses ActiveAdminCap
    public entry fun withdraw(_admin: &ActiveAdminCap, pool: &mut Pool, ctx: &mut TxContext) {
        pool.balance = pool.balance - 100;
    }

    /// Uses ActiveAdminCap again
    public entry fun deposit(_admin: &ActiveAdminCap, pool: &mut Pool, amount: u64) {
        pool.balance = pool.balance + amount;
    }

    /// Unprotected - should use UnusedAdminCap or UnusedModeratorCap
    public entry fun dangerous_action(pool: &mut Pool) {
        pool.balance = 0;
    }
}
