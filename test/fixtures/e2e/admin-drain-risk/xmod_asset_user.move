/// Cross-module user asset test: Module that uses asset from another module
/// Tests if WritesUserAsset is detected for cross-module types
module test::xmod_asset_user {
    use sui::coin::{Self, Coin};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use test::xmod_asset_types::{Self, UserVault, AdminCap};

    /// Local admin cap (different from xmod_asset_types::AdminCap)
    public struct LocalAdminCap has key, store {
        id: UID,
    }

    /// VULNERABLE: Uses cross-module UserVault type
    /// Tests if WritesUserAsset propagates correctly for cross-module types
    // @expect: admin-drain-risk
    public entry fun admin_drain_xmod(
        _admin: &AdminCap,
        vault: &mut UserVault,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let balance = xmod_asset_types::balance_mut(vault);
        let amount = sui::balance::value(balance);
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }

    /// VULNERABLE: Uses local cap but cross-module vault
    /// Tests FQN handling for mixed module types
    // @expect: admin-drain-risk
    public entry fun local_admin_drain_xmod(
        _admin: &LocalAdminCap,
        vault: &mut UserVault,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let balance = xmod_asset_types::balance_mut(vault);
        let amount = sui::balance::value(balance);
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }

    /// SAFE: Returns to vault owner (cross-module)
    public entry fun admin_rescue_xmod(
        _admin: &AdminCap,
        vault: &mut UserVault,
        ctx: &mut TxContext
    ) {
        let owner = xmod_asset_types::owner(vault);
        let balance = xmod_asset_types::balance_mut(vault);
        let amount = sui::balance::value(balance);
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, owner);
    }
}
