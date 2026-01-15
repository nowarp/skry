/// IPA test - safe entry -> helper with owner check
module test::admin_drain_ipa_safe {
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

    /// SAFE: Entry calls helper that returns to owner
    public entry fun admin_rescue(
        _admin: &AdminCap,
        vault: &mut UserVault,
        ctx: &mut TxContext
    ) {
        return_to_owner(vault, ctx);
    }

    /// Helper returns funds to vault owner only
    fun return_to_owner(
        vault: &mut UserVault,
        ctx: &mut TxContext
    ) {
        let amount = balance::value(&vault.balance);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, vault.owner);  // Only to rightful owner
    }
}
