/// Cross-User Asset Theft - FQN Collision Test (Module A)
/// Tests FQN resolution for user asset detection

module test::module_a {
    use sui::object::{Self, UID};
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    /// User asset Vault in module A
    public struct Vault has key {
        id: UID,
        owner: address,
        balance: Balance<SUI>,
    }

    /// Init creates shared vault
    fun init(ctx: &mut TxContext) {
        let vault = Vault {
            id: object::new(ctx),
            owner: tx_context::sender(ctx),
            balance: balance::zero(),
        };
        transfer::share_object(vault);
    }

    /// VULNERABLE: Withdraws from module_a::Vault without ownership check
    /// Should be flagged (module_a::Vault is a user asset)
    // @expect: cross-user-asset-theft
    public entry fun steal_from_vault(
        vault: &mut Vault,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// SAFE: Verifies ownership before withdrawal
    public entry fun withdraw_safe(
        vault: &mut Vault,
        amount: u64,
        ctx: &mut TxContext
    ) {
        assert!(vault.owner == tx_context::sender(ctx), 0);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
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

