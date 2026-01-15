/// Cross-User Asset Theft - FQN Collision Test (Module B)
/// Same-named struct but NOT a user asset (protocol state)

module test::module_b {
    use sui::object::{Self, UID};
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    /// NOT a user asset (protocol-owned pool, not user vault)
    /// No owner field = protocol state, not user asset
    public struct Vault has key {
        id: UID,
        balance: Balance<SUI>,
        fee_rate: u64,
    }

    /// AdminCap for module B
    public struct AdminCap has key {
        id: UID,
    }

    /// Init creates shared Vault and AdminCap
    fun init(ctx: &mut TxContext) {
        let vault = Vault {
            id: object::new(ctx),
            balance: balance::zero(),
            fee_rate: 100,
        };
        transfer::share_object(vault);

        let admin = AdminCap { id: object::new(ctx) };
        transfer::transfer(admin, tx_context::sender(ctx));
    }

    /// VULNERABLE (different reason): Withdraws from protocol vault without auth
    /// This is missing-authorization, NOT cross-user-asset-theft
    /// NOT flagged by cross-user-asset-theft (module_b::Vault is protocol state, not user asset)
    public entry fun withdraw_from_vault(
        vault: &mut Vault,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// SAFE: Admin withdrawal from protocol vault
    public entry fun withdraw_admin(
        vault: &mut Vault,
        amount: u64,
        _admin: &AdminCap,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// Cross-module: steal from module_a::Vault (the user asset one)
    /// VULNERABLE: Should be flagged for accessing module_a::Vault
    // @expect: cross-user-asset-theft
    public entry fun steal_from_module_a(
        vault: &mut test::module_a::Vault,
        amount: u64,
        ctx: &mut TxContext
    ) {
        // Note: we can't directly access vault.balance from another module
        // In real code, module_a would provide a helper. For the test, we just
        // demonstrate the intent to access module_a::Vault
        // The WritesUserAsset fact should be generated based on the parameter type
        transfer::public_transfer(coin::zero<SUI>(ctx), tx_context::sender(ctx));
    }

    /// Deposit into protocol vault (module_b::Vault)
    /// Creates deposit pattern for this module's Vault
    public entry fun deposit_protocol(
        vault: &mut Vault,
        coin: Coin<SUI>,
    ) {
        balance::join(&mut vault.balance, coin::into_balance(coin));
    }
}

