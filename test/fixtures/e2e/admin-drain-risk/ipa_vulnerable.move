/// IPA test - vulnerable entry -> helper chain
module test::admin_drain_ipa_vuln {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    public struct AdminCap has key, store {
        id: UID,
    }

    public struct UserVault has key {
        id: UID,
        owner: address,
        balance: Balance<SUI>,
    }

    /// VULNERABLE: Entry with admin cap calls helper with tainted recipient
    // @expect: admin-drain-risk
    public entry fun admin_withdraw(
        _admin: &AdminCap,
        vault: &mut UserVault,
        recipient: address,
        ctx: &mut TxContext
    ) {
        drain_to_recipient(vault, recipient, ctx);
    }

    /// Helper drains to arbitrary recipient
    fun drain_to_recipient(
        vault: &mut UserVault,
        to: address,
        ctx: &mut TxContext
    ) {
        let amount = balance::value(&vault.balance);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, to);  // Admin can steal user funds
    }
}
