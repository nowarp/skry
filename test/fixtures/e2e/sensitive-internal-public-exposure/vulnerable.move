module test::vulnerable_internal {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};

    public struct AdminCap has key, store {
        id: UID,
    }

    public struct Vault has key {
        id: UID,
        balance: Balance<SUI>,
        reserve_index: u256,
    }

    /// VULNERABLE: Public internal helper with internal caller, no auth
    /// This is called by admin_withdraw but exposed as public
    // @expect: sensitive-internal-public-exposure
    public fun do_withdraw(vault: &mut Vault, amount: u64): Balance<SUI> {
        balance::split(&mut vault.balance, amount)
    }

    /// Internal caller - proves do_withdraw is designed as helper
    /// This one is SAFE because it has capability
    public entry fun admin_withdraw(
        _cap: &AdminCap,
        vault: &mut Vault,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let bal = do_withdraw(vault, amount);
        transfer::public_transfer(coin::from_balance(bal, ctx), tx_context::sender(ctx));
    }

    /// VULNERABLE: Public state mutation helper with internal caller
    /// Updates index AND extracts fee to trigger sink detection
    // @expect: sensitive-internal-public-exposure
    public fun update_reserve_index(vault: &mut Vault, new_index: u256): Balance<SUI> {
        vault.reserve_index = new_index;
        // Extract fee as part of state update (triggers AmountExtractionSink)
        balance::split(&mut vault.balance, 100)
    }

    /// Internal caller for update_reserve_index
    public entry fun admin_update_index(
        _cap: &AdminCap,
        vault: &mut Vault,
        new_index: u256,
        ctx: &mut TxContext
    ) {
        let fee = update_reserve_index(vault, new_index);
        transfer::public_transfer(coin::from_balance(fee, ctx), tx_context::sender(ctx));
    }

    /// VULNERABLE: Public balance join helper with internal caller
    // @expect: sensitive-internal-public-exposure
    public fun join_vault_balance(vault: &mut Vault, deposit: Balance<SUI>) {
        balance::join(&mut vault.balance, deposit);
    }

    /// Internal caller for join_vault_balance
    public entry fun deposit_to_vault(
        vault: &mut Vault,
        coin: Coin<SUI>,
    ) {
        join_vault_balance(vault, coin::into_balance(coin));
    }

    /// MULTI-HOP TEST: bottom_helper is called via middle_helper -> admin_action
    /// Tests that has_internal_callers works transitively

    /// VULNERABLE: Bottom of call chain - internal helper with sensitive sink
    /// Called by: admin_action -> middle_helper -> bottom_helper
    // @expect: sensitive-internal-public-exposure
    public fun bottom_helper(vault: &mut Vault, amount: u64): Balance<SUI> {
        balance::split(&mut vault.balance, amount)
    }

    /// Middle helper - calls bottom_helper
    /// This is also internal but has no sink of its own (just passes through)
    public fun middle_helper(vault: &mut Vault, amount: u64): Balance<SUI> {
        bottom_helper(vault, amount)
    }

    /// Entry point with capability - calls middle_helper
    public entry fun admin_action(
        _cap: &AdminCap,
        vault: &mut Vault,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let bal = middle_helper(vault, amount);
        transfer::public_transfer(coin::from_balance(bal, ctx), tx_context::sender(ctx));
    }

    fun init(ctx: &mut TxContext) {
        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));

        let vault = Vault {
            id: object::new(ctx),
            balance: balance::zero(),
            reserve_index: 0,
        };
        transfer::share_object(vault);
    }
}
