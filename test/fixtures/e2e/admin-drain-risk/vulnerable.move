/// Test cases for admin-drain-risk rule.
/// Admin-guarded function can drain user assets to arbitrary recipient
module test::admin_drain_risk {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};

    public struct AdminCap has key, store {
        id: UID,
    }

    public struct UserVault has key {
        id: UID,
        owner: address,
        balance: Balance<SUI>,
    }

    /// VULNERABLE: Admin can drain ANY user's vault to arbitrary recipient
    // @expect: admin-drain-risk
    public entry fun admin_emergency_withdraw(
        _admin: &AdminCap,
        vault: &mut UserVault,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let amount = balance::value(&vault.balance);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, recipient);  // To arbitrary recipient!
    }

    /// VULNERABLE: Admin can withdraw to tainted recipient
    // @expect: admin-drain-risk
    public entry fun admin_rescue_funds(
        _cap: &AdminCap,
        vault: &mut UserVault,
        to: address,
        ctx: &mut TxContext
    ) {
        let amount = balance::value(&vault.balance);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, to);  // Centralization risk
    }

    /// SAFE: Admin can only withdraw to vault owner
    public entry fun admin_safe_withdraw(
        _admin: &AdminCap,
        vault: &mut UserVault,
        ctx: &mut TxContext
    ) {
        let amount = balance::value(&vault.balance);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, vault.owner);  // Only to owner
    }

    /// SAFE: No admin capability - user controls their own vault
    public entry fun user_withdraw(
        vault: &mut UserVault,
        amount: u64,
        ctx: &mut TxContext
    ) {
        assert!(tx_context::sender(ctx) == vault.owner, 0);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, vault.owner);
    }
}
