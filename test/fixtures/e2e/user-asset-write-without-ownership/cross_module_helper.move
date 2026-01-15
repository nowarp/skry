/// Cross-module helper for user asset write tests.
module test::cross_module_helper {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};

    /// User vault - holds per-user assets
    public struct UserVault has key {
        id: UID,
        owner: address,
        balance: Balance<SUI>,
        data: u64,
    }

    /// Helper without ownership check
    public fun update(vault: &mut UserVault, new_data: u64) {
        vault.data = new_data;
    }

    /// Helper with ownership check
    public fun update_safe(
        vault: &mut UserVault,
        new_data: u64,
        ctx: &TxContext
    ) {
        assert!(vault.owner == tx_context::sender(ctx), 1);
        vault.data = new_data;
    }

    /// User can deposit (establishes deposit pattern)
    public entry fun deposit(
        vault: &mut UserVault,
        coin: Coin<SUI>,
        ctx: &mut TxContext
    ) {
        balance::join(&mut vault.balance, coin::into_balance(coin));
    }

    /// User can withdraw their own funds (establishes withdraw pattern)
    public entry fun withdraw(
        vault: &mut UserVault,
        amount: u64,
        ctx: &mut TxContext
    ) {
        assert!(vault.owner == tx_context::sender(ctx), 1);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// Create user vault
    public entry fun create_vault(ctx: &mut TxContext) {
        let vault = UserVault {
            id: object::new(ctx),
            owner: tx_context::sender(ctx),
            balance: balance::zero(),
            data: 0,
        };
        transfer::share_object(vault);
    }
}
