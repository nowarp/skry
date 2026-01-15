/// Test cases for orphan-privileged-capability rule.
/// Privileged capability defined but never used - protection may be missing
module test::orphan_privileged_capability {
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::object::{Self, UID};
    use sui::coin::{Self, Coin};
    use sui::balance::Balance;
    use sui::sui::SUI;

    /// ORPHAN PRIVILEGED: Created in init, never used
    // @expect: orphan-privileged-capability
    public struct SuperAdminCap has key {
        id: UID,
    }

    /// USED: This capability is actually checked
    public struct RegularAdminCap has key {
        id: UID,
    }

    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    fun init(ctx: &mut TxContext) {
        transfer::transfer(
            SuperAdminCap { id: object::new(ctx) },
            tx_context::sender(ctx)
        );
        transfer::transfer(
            RegularAdminCap { id: object::new(ctx) },
            tx_context::sender(ctx)
        );
    }

    /// Should require SuperAdminCap but doesn't!
    public entry fun emergency_withdraw(pool: &mut Pool, ctx: &mut TxContext) {
        // Missing SuperAdminCap check - anyone can call!
        let amount = sui::balance::value(&pool.balance);
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// Uses RegularAdminCap properly
    public entry fun admin_action(_cap: &RegularAdminCap, pool: &mut Pool) {
        // Protected action
    }
}
