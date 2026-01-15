/// Test cases for shared-capability-exposure rule.
/// Role/capability struct shared instead of transferred.
module test::shared_capability_exposure {
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;

    /// VULNERABLE: AdminCap shared instead of transferred
    // @expect: shared-capability-exposure
    public struct SharedAdminCap has key {
        id: UID,
    }

    /// VULNERABLE: OwnerCap shared instead of transferred
    // @expect: shared-capability-exposure
    public struct SharedOwnerCap has key, store {
        id: UID,
    }

    /// SAFE: AdminCap properly transferred to sender
    public struct ProperAdminCap has key, store {
        id: UID,
    }

    /// Regular shared object (not a capability)
    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    /// init() shows both patterns
    fun init(ctx: &mut TxContext) {
        // VULNERABLE: Sharing capabilities
        let admin_cap = SharedAdminCap { id: object::new(ctx) };
        transfer::share_object(admin_cap);  // WRONG: should use transfer::transfer

        let owner_cap = SharedOwnerCap { id: object::new(ctx) };
        transfer::share_object(owner_cap);  // WRONG: should use transfer::transfer

        // SAFE: Properly transferring to sender
        let proper_cap = ProperAdminCap { id: object::new(ctx) };
        transfer::transfer(proper_cap, tx_context::sender(ctx));  // Correct

        // OK: Pool is meant to be shared
        let pool = Pool {
            id: object::new(ctx),
            balance: balance::zero(),
        };
        transfer::share_object(pool);
    }

    /// Function using shared capability
    public entry fun admin_withdraw(
        pool: &mut Pool,
        _cap: &SharedAdminCap,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// Function with proper capability
    public entry fun proper_withdraw(
        pool: &mut Pool,
        _cap: &ProperAdminCap,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }
}
