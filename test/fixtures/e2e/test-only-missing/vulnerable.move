/// Test cases for test-only-missing rule.
/// Public function creates privileged object without #[test_only] attribute.
module test::test_only_missing {
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;

    /// Admin capability
    public struct AdminCap has key, store {
        id: UID,
    }

    /// Protocol vault
    public struct Vault has key {
        id: UID,
        balance: Balance<SUI>,
    }

    /// VULNERABLE: Public test helper without #[test_only]
    /// Anyone can call this to get admin privileges!
    // @expect: test-only-missing
    public fun create_admin_cap_for_testing(ctx: &mut TxContext): AdminCap {
        AdminCap { id: object::new(ctx) }
    }

    /// Transfers admin cap directly (not detected by test-only-missing: rule checks RETURN type)
    public entry fun get_admin_cap_unsafe(ctx: &mut TxContext) {
        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    /// SAFE: Properly marked as test_only
    #[test_only]
    public fun create_admin_cap_test(ctx: &mut TxContext): AdminCap {
        AdminCap { id: object::new(ctx) }
    }

    /// SAFE: init() is allowed to create admin cap
    fun init(ctx: &mut TxContext) {
        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));

        let vault = Vault {
            id: object::new(ctx),
            balance: balance::zero(),
        };
        transfer::share_object(vault);
    }

    /// SAFE: Requires admin cap parameter (has auth check)
    public fun create_operator_cap(
        _admin: &AdminCap,
        ctx: &mut TxContext
    ): AdminCap {
        AdminCap { id: object::new(ctx) }
    }

    /// Regular privileged function (not creating cap)
    public entry fun withdraw(
        vault: &mut Vault,
        _cap: &AdminCap,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// Private helper - returns cap
    fun create_cap_internal(ctx: &mut TxContext): AdminCap {
        AdminCap { id: object::new(ctx) }
    }

    /// VULNERABLE: Public, calls helper, returns cap (IPA test)
    // @expect: test-only-missing
    public fun create_cap_via_helper(ctx: &mut TxContext): AdminCap {
        create_cap_internal(ctx)
    }
}
