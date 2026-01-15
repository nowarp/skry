/// Cross-User Asset Theft - Cross-Module Test (Vault Module)
/// Defines user asset container and helpers

module test::vault_module {
    use sui::object::{Self, UID};
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    /// User-owned vault (user asset container)
    public struct Vault has key {
        id: UID,
        owner: address,
        balance: Balance<SUI>,
    }

    /// Helper to extract coins from vault (NO ownership check)
    public fun extract_funds(vault: &mut Vault, amount: u64, ctx: &mut TxContext): Coin<SUI> {
        coin::take(&mut vault.balance, amount, ctx)
    }

    /// Helper that checks ownership
    public fun verify_owner(vault: &Vault, caller: address) {
        assert!(vault.owner == caller, 0);
    }

    /// Create vault for user
    public entry fun create_vault(ctx: &mut TxContext) {
        let vault = Vault {
            id: object::new(ctx),
            owner: tx_context::sender(ctx),
            balance: balance::zero(),
        };
        transfer::share_object(vault);
    }

    /// SAFE: Deposit is safe (transfers FROM sender)
    /// Creates deposit pattern needed for IsUserAssetContainer detection
    public entry fun deposit(
        vault: &mut Vault,
        coin: Coin<SUI>,
    ) {
        balance::join(&mut vault.balance, coin::into_balance(coin));
    }
}

