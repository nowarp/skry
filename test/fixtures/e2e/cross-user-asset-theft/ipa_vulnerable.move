/// Cross-User Asset Theft - IPA Test
/// Tests detection of asset theft through helper call chains

module test::cross_user_asset_theft_ipa {
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

    /// AdminCap for safe operations
    public struct AdminCap has key {
        id: UID,
    }

    /// Init creates AdminCap and shared Vault
    fun init(ctx: &mut TxContext) {
        let admin = AdminCap { id: object::new(ctx) };
        transfer::transfer(admin, tx_context::sender(ctx));

        // Create shared vault for user assets
        let vault = Vault {
            id: object::new(ctx),
            owner: tx_context::sender(ctx),
            balance: balance::zero(),
        };
        transfer::share_object(vault);
    }

    /// VULNERABLE: Withdraws from vault via helper chain without ownership check
    /// Asset theft through IPA
    // @expect: cross-user-asset-theft
    public entry fun steal_via_helper(
        vault: &mut Vault,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = extract_coins(vault, amount, ctx);
        send_to_caller(coins, ctx);
    }

    /// Helper that extracts coins (no ownership check)
    fun extract_coins(vault: &mut Vault, amount: u64, ctx: &mut TxContext): Coin<SUI> {
        coin::take(&mut vault.balance, amount, ctx)
    }

    /// Helper that sends to caller
    fun send_to_caller(coins: Coin<SUI>, ctx: &TxContext) {
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// VULNERABLE: Direct withdrawal without ownership verification
    // @expect: cross-user-asset-theft
    public entry fun steal_direct(
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

    /// SAFE: Admin can withdraw (has AdminCap)
    public entry fun withdraw_admin(
        vault: &mut Vault,
        amount: u64,
        _admin: &AdminCap,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// SAFE: Deposit is safe (transfers FROM sender, not TO sender)
    /// This creates the deposit pattern needed for IsUserAssetContainer detection
    public entry fun deposit(
        vault: &mut Vault,
        coin: Coin<SUI>,
    ) {
        balance::join(&mut vault.balance, coin::into_balance(coin));
    }
}

