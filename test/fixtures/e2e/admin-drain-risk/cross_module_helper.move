/// Cross-module test - helper module
module test::admin_drain_helper {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    public struct UserVault has key {
        id: UID,
        owner: address,
        balance: Balance<SUI>,
    }

    /// VULNERABLE if called by admin with arbitrary recipient
    /// Not reported here but the entrypoint will
    public fun drain_vault(
        vault: &mut UserVault,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let amount = balance::value(&vault.balance);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, recipient);  // Centralization risk
    }

    /// SAFE: Returns to vault owner
    public fun return_to_owner(
        vault: &mut UserVault,
        ctx: &mut TxContext
    ) {
        let amount = balance::value(&vault.balance);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, vault.owner);
    }
}
