/// Cross-User Asset Theft - Cross-Module Test (Theft Module)
/// Module that accesses vaults from another module

module test::theft_module {
    use test::vault_module::{Self, Vault};
    use sui::coin::Coin;
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    /// VULNERABLE: Withdraws from vault (from vault_module) without ownership check
    /// Cross-module asset theft
    // @expect: cross-user-asset-theft
    public entry fun steal_cross_module(
        vault: &mut Vault,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = vault_module::extract_funds(vault, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// SAFE: Verifies ownership using helper from vault_module
    public entry fun withdraw_safe_cross_module(
        vault: &mut Vault,
        amount: u64,
        ctx: &mut TxContext
    ) {
        vault_module::verify_owner(vault, tx_context::sender(ctx));
        let coins = vault_module::extract_funds(vault, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// SAFE: Read vault balance (no extraction)
    public fun get_vault_balance(vault: &Vault): u64 {
        // Just reading is safe
        0  // Placeholder - would need access to balance field
    }
}
